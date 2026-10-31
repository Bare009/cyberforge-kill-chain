# Copied from AI-SOC: backend/services/collectors/poller.py
# killchain changes: the Mongo due-query / lease / progress / outcome calls use
# the JSON store; leases are an in-process set (one API process runs the
# poller) and `pull_state.lease_owner` is only written so the UI can show
# "running"; items go to the file sink (sink.py) with dedupe on
# (connector_id, connector_id:native_id); licensing, tenancy and Prometheus
# metrics are removed. `connectors_lifespan` (new) starts the poller and the
# optional syslog listener from the FastAPI lifespan.
"""Scheduler for API-pull connectors.

Every `POLLER_TICK_SECONDS` the poller looks for enabled `transport: api_pull`
connectors whose `pull_state.next_run_at` has passed (or was never set, or was
reset by "Poll now" in Settings), and runs its vendor client for up to
`POLLER_MAX_PAGES_PER_RUN` pages.

Connector record fields used (written by registry.py):

    pull: {
      client:          sentinelone | sumologic | usm_anywhere | generic_rest
      config:          client-specific settings (base_url, resource, ...)
      interval_seconds poll period
      credentials_enc  Fernet token of a JSON object (see credentials.py)
    }
    pull_state: {                              -- written here only
      cursor           client state dict (watermark + continuation)
      next_run_at      when the next run is due
      lease_owner / lease_until                 -- set while a run is in progress
      last_run_at, last_success_at, consecutive_failures,
      last_error {message, kind, at} | None,
      last_run {fetched, queued, duplicates, pages, complete, duration_ms}
    }

Failure policy
  transient / rate_limit  exponential backoff from the interval, capped;
                          a vendor Retry-After is honoured when larger
  auth / config           retried at a slow fixed pace (>= 15 min) -- these
                          need an operator, and hammering a vendor with bad
                          credentials can get the API client locked.
The watermark never advances on a failed page, and each completed page's state
is saved before the next is fetched, so no failure mode skips data.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

import httpx

from .config import CollectorSettings, connectors_enabled, syslog_enabled
from .credentials import CredentialError, decrypt_credentials
from .pull_clients import PullError, PullItem, build_client
from .sink import Sink, get_sink
from .store import ConnectorStore, get_store

logger = logging.getLogger(__name__)

_SLOW_RETRY_SECONDS = 900  # auth/config failures
_CONTINUE_SOON_SECONDS = 5  # page cap reached with more data waiting


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(v: Any) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


class Poller:
    def __init__(
        self,
        store: Optional[ConnectorStore] = None,
        settings: Optional[CollectorSettings] = None,
        *,
        sink: Optional[Sink] = None,
        http: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.store = store or get_store()
        self.settings = settings or CollectorSettings()
        self.sink = sink or get_sink()
        self._running: Set[str] = set()
        self._sem = asyncio.Semaphore(self.settings.poll_concurrency)
        self._http: Optional[httpx.AsyncClient] = http
        self._own_http = http is None

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.poll_http_timeout_seconds),
                follow_redirects=False,
                headers={'User-Agent': 'killchain-collector/1.0'},
            )
        return self._http

    # ── Scheduling ──────────────────────────────────────────────────────────

    async def run(self, stop: asyncio.Event) -> None:
        self._client()
        self._clear_stale_leases()
        tasks: Set[asyncio.Task] = set()
        logger.info('API poller started (instance=%s)', self.settings.instance_id)
        try:
            while not stop.is_set():
                try:
                    for t in self.tick():
                        tasks.add(t)
                        t.add_done_callback(tasks.discard)
                except Exception as exc:
                    logger.error('Poller tick failed: %s', exc, exc_info=True)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.settings.poll_tick_seconds)
                except asyncio.TimeoutError:
                    pass
        finally:
            for t in list(tasks):
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if self._own_http and self._http is not None:
                await self._http.aclose()
            logger.info('API poller stopped')

    def tick(self) -> List[asyncio.Task]:
        """Start a run for every due connector not already running. Returns the tasks."""
        started: List[asyncio.Task] = []
        for doc in self._due_connectors():
            cid = doc['connector_id']
            if cid in self._running:
                continue
            leased = self._acquire_lease(cid)
            if not leased:
                continue
            self._running.add(cid)
            started.append(asyncio.create_task(self._guarded_run(leased)))
        return started

    def _clear_stale_leases(self) -> None:
        # A previous process that died mid-run leaves lease_owner set; with
        # in-process leases nothing else can own it, so clear it.
        for doc in self.store.find({'transport': 'api_pull'}):
            if (doc.get('pull_state') or {}).get('lease_owner'):
                self._release_lease(doc['connector_id'])

    def _due_connectors(self) -> List[Dict[str, Any]]:
        now = _now()
        out = []
        for doc in self.store.find({'transport': 'api_pull', 'enabled': True}):
            nxt = _utc((doc.get('pull_state') or {}).get('next_run_at'))
            if nxt is None or nxt <= now:
                out.append(doc)
        return out[:200]

    def _acquire_lease(self, connector_id: str) -> Optional[Dict[str, Any]]:
        now = _now()
        lease_until = now + timedelta(seconds=self.settings.poll_run_timeout_seconds + 60)
        ok = self.store.update_one(
            {'connector_id': connector_id, 'transport': 'api_pull', 'enabled': True},
            {'$set': {
                'pull_state.lease_owner': self.settings.instance_id,
                'pull_state.lease_until': lease_until,
            }},
        )
        return self.store.find_one({'connector_id': connector_id}) if ok else None

    async def _guarded_run(self, doc: Dict[str, Any]) -> None:
        try:
            async with self._sem:
                await self.run_connector(doc)
        except asyncio.CancelledError:
            self._release_lease(doc['connector_id'])
            raise
        except Exception as exc:  # run_connector records its own errors
            logger.error('Unexpected poller failure for %s: %s', doc.get('connector_id'), exc, exc_info=True)
            self._release_lease(doc['connector_id'])
        finally:
            self._running.discard(doc['connector_id'])

    def _release_lease(self, connector_id: str) -> None:
        try:
            self.store.update_one(
                {'connector_id': connector_id},
                {'$set': {'pull_state.lease_owner': None, 'pull_state.lease_until': None}},
            )
        except Exception:
            pass

    # ── One run ─────────────────────────────────────────────────────────────

    def _interval(self, doc: Dict[str, Any]) -> int:
        pull = doc.get('pull') or {}
        try:
            interval = int(pull.get('interval_seconds') or 300)
        except (TypeError, ValueError):
            interval = 300
        return max(self.settings.poll_min_interval_seconds, interval)

    async def run_connector(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Run one poll for a connector and record the outcome.

        Returns the `last_run` summary (also useful to tests / tooling).
        """
        cid = doc['connector_id']
        vendor = str(doc.get('vendor') or 'unknown').lower()
        pull = doc.get('pull') or {}
        client_id = str(pull.get('client') or '')
        state: Optional[Dict[str, Any]] = (doc.get('pull_state') or {}).get('cursor') or None

        started = time.monotonic()
        fetched = queued = duplicates = pages = 0
        complete = False
        error: Optional[Tuple[str, str]] = None  # (kind, message)
        retry_after: Optional[float] = None
        info: Dict[str, Any] = {}

        try:
            creds = decrypt_credentials(pull.get('credentials_enc'))
            client = build_client(client_id, self._client(), pull.get('config') or {}, creds)
            state = state or client.initial_state()

            async def _pages() -> None:
                nonlocal state, fetched, queued, duplicates, pages, complete, info
                for _ in range(self.settings.poll_max_pages_per_run):
                    page = await client.fetch_page(state)
                    pages += 1
                    fetched += len(page.items)
                    q, d = self._ingest(doc, vendor, client_id, page.items)
                    queued += q
                    duplicates += d
                    state = page.state
                    info.update(page.info)
                    self._save_progress(cid, state)
                    if page.done:
                        complete = True
                        return

            await asyncio.wait_for(_pages(), timeout=self.settings.poll_run_timeout_seconds)
        except PullError as exc:
            error, retry_after = (exc.kind, str(exc)), exc.retry_after
        except CredentialError as exc:
            error = ('config', str(exc))
        except OSError as exc:
            error = ('transient', f'Could not write ingested records: {exc}')
        except asyncio.TimeoutError:
            error = ('transient', f'Run exceeded {self.settings.poll_run_timeout_seconds}s; will resume.')
        except Exception as exc:
            logger.error('Poll of %s failed unexpectedly: %s', cid, exc, exc_info=True)
            error = ('transient', f'Internal error: {exc.__class__.__name__}')

        duration = time.monotonic() - started
        summary = {
            'fetched': fetched,
            'queued': queued,
            'duplicates': duplicates,
            'pages': pages,
            'complete': complete,
            'duration_ms': int(duration * 1000),
        }
        if info.get('warning'):
            summary['warning'] = info['warning']
        self._record_outcome(doc, summary, error, retry_after)

        if error:
            logger.warning('Poll %s (%s/%s) failed [%s]: %s', cid, vendor, client_id, error[0], error[1])
        else:
            logger.info('Poll %s (%s/%s): fetched=%d queued=%d dup=%d pages=%d complete=%s',
                        cid, vendor, client_id, fetched, queued, duplicates, pages, complete)
        return summary

    def _ingest(
        self, doc: Dict[str, Any], vendor: str, client_id: str, items: List[PullItem]
    ) -> Tuple[int, int]:
        cid = doc['connector_id']
        if not items:
            return 0, 0
        # Oldest first, so the earliest alerts are the ones delivered first.
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        ordered = sorted(items, key=lambda i: i.occurred_at or epoch)
        res = self.sink.ingest_many(
            [dict(i.payload) for i in ordered],
            source=vendor,
            source_hint=vendor,
            connector=doc,
            transport='api_pull',
            # Namespaced by connector: two connectors pulling different
            # tenants of the same vendor cannot collide on a vendor id.
            alert_ids=[f'{cid}:{i.native_id}' for i in ordered],
            meta_extra={'pull_client': client_id},
        )
        return res.accepted, res.duplicates

    def _save_progress(self, connector_id: str, state: Dict[str, Any]) -> None:
        self.store.update_one(
            {'connector_id': connector_id},
            {'$set': {
                'pull_state.cursor': state,
                'pull_state.lease_until': _now() + timedelta(
                    seconds=self.settings.poll_run_timeout_seconds + 60),
            }},
        )

    def next_delay(
        self,
        doc: Dict[str, Any],
        *,
        error_kind: Optional[str],
        failures: int,
        complete: bool,
        retry_after: Optional[float],
    ) -> float:
        interval = self._interval(doc)
        if error_kind is None:
            return _CONTINUE_SOON_SECONDS if not complete else interval
        if error_kind in ('auth', 'config'):
            return max(interval, _SLOW_RETRY_SECONDS)
        backoff = min(interval * (2 ** max(0, failures - 1)), self.settings.poll_max_backoff_seconds)
        if retry_after:
            backoff = max(backoff, min(float(retry_after), self.settings.poll_max_backoff_seconds))
        return backoff

    def _record_outcome(
        self,
        doc: Dict[str, Any],
        summary: Dict[str, Any],
        error: Optional[Tuple[str, str]],
        retry_after: Optional[float],
    ) -> None:
        cid = doc['connector_id']
        now = _now()
        prev_failures = int((doc.get('pull_state') or {}).get('consecutive_failures') or 0)
        failures = prev_failures + 1 if error else 0
        delay = self.next_delay(
            doc,
            error_kind=error[0] if error else None,
            failures=failures,
            complete=bool(summary.get('complete')),
            retry_after=retry_after,
        )
        update: Dict[str, Any] = {
            '$set': {
                'pull_state.last_run_at': now,
                'pull_state.last_run': summary,
                'pull_state.consecutive_failures': failures,
                'pull_state.next_run_at': now + timedelta(seconds=delay),
                'pull_state.lease_owner': None,
                'pull_state.lease_until': None,
                'pull_state.last_error': (
                    {'kind': error[0], 'message': error[1][:500], 'at': now} if error else None
                ),
            },
        }
        if not error:
            update['$set']['pull_state.last_success_at'] = now
        if summary.get('queued'):
            update['$set']['last_seen_at'] = now
            update['$inc'] = {'alerts_received': int(summary['queued'])}
        try:
            self.store.update_one({'connector_id': cid}, update)
        except Exception as exc:
            logger.error('Could not record poll outcome for %s: %s', cid, exc)


# ── killchain: run inside the API process ────────────────────────────────────

@contextlib.asynccontextmanager
async def connectors_lifespan(app: Any = None) -> AsyncIterator[None]:
    """FastAPI lifespan: create data/ingest/live.log, start the poller (KILLCHAIN_CONNECTORS,
    default on) and the syslog listener (KILLCHAIN_SYSLOG=1), stop both on shutdown."""
    try:
        get_sink().ensure_live_log()
    except OSError as exc:
        logger.warning('Cannot create %s: %s', get_sink().live_log, exc)
    stop = asyncio.Event()
    tasks: List[asyncio.Task] = []
    if connectors_enabled():
        tasks.append(asyncio.create_task(Poller().run(stop), name='killchain-poller'))
    if syslog_enabled():
        from .syslog_server import run_syslog

        tasks.append(asyncio.create_task(run_syslog(stop), name='killchain-syslog'))
    try:
        yield
    finally:
        stop.set()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=10)
            for t in pending:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
