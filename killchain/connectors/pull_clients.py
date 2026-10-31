# Copied from AI-SOC: backend/services/collectors/pull_clients.py (unchanged
# apart from this header; dedupe of re-read items is done by killchain's sink).
"""Vendor API clients for scheduled pull ("API pull" transport).

Each client turns one vendor API into pages of `PullItem`s and a resumable
state dict. The scheduler (`poller.py`) owns timing, leases, persistence and
ingest; clients only know how to talk to their vendor.

State model (shared by every client)
------------------------------------
  watermark   ISO-8601 UTC. Everything at or before it has been fully fetched.
  run_max     Newest item timestamp seen in the *current* traversal.
  cursor/offset/page   Continuation within the current traversal.

A traversal walks every page matching "newer than watermark". The watermark
only advances (to run_max) when the traversal completes, so a run that is cut
short -- page cap, crash, vendor outage -- resumes from its continuation next
time instead of skipping the unseen pages. Windows are inclusive or overlap on
purpose; the resulting re-reads are dropped by `alerts_raw` dedupe on the
vendor-native id, which is cheaper than being clever about boundaries.

Supported clients
-----------------
  sentinelone    Management API v2.1 -- threats or cloud-detection alerts.
                 Auth: `Authorization: ApiToken <token>`.
  sumologic      Cloud SIEM API -- signals or insights.
                 Auth: HTTP Basic with an access ID / access key.
  usm_anywhere   AlienVault (LevelBlue) USM Anywhere API 2.0 -- alarms.
                 Auth: OAuth2 client credentials.
  generic_rest   Configurable JSON-over-HTTP client (URL, auth scheme, item
                 path, id/timestamp fields, pagination). Used for Cybolt, which
                 publishes no public API spec, and for any custom source.

Outbound-request safety
-----------------------
Base URLs are operator-supplied, so every request is checked by
`validate_target_url` first: https only (unless COLLECTOR_ALLOW_HTTP), no
credentials in the URL, and the resolved address must not be link-local
(cloud metadata), multicast or reserved. Loopback and RFC 1918 addresses are
refused unless COLLECTOR_ALLOW_PRIVATE_TARGETS is set -- needed for on-prem
sources, but off by default so a connector cannot be pointed at Vault, Mongo
or another internal service. Redirects are never followed, and response bodies
are capped.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = int(os.getenv('COLLECTOR_MAX_RESPONSE_BYTES', str(25 * 1024 * 1024)))
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500  # never above raw_ingest.MAX_BATCH_SIZE semantics


# ── Errors / data types ──────────────────────────────────────────────────────

class PullError(RuntimeError):
    """A pull run failed.

    kind:
      auth        credentials rejected (401/403) -- operator must fix them
      rate_limit  vendor asked us to slow down (429); see retry_after
      transient   network error / timeout / 5xx -- retry with backoff
      config      bad URL, blocked target, unexpected response shape
    """

    def __init__(self, message: str, *, kind: str = 'transient', retry_after: Optional[float] = None):
        super().__init__(message)
        self.kind = kind
        self.retry_after = retry_after


@dataclass
class PullItem:
    native_id: str
    occurred_at: Optional[datetime]
    payload: Dict[str, Any]


@dataclass
class PullPage:
    items: List[PullItem]
    state: Dict[str, Any]
    done: bool
    info: Dict[str, Any] = field(default_factory=dict)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _env_flag(name: str) -> bool:
    return (os.getenv(name) or '').strip().lower() in ('1', 'true', 'yes', 'on')


def to_datetime(value: Any) -> Optional[datetime]:
    """Parse ISO-8601 strings and epoch seconds/milliseconds to aware UTC."""
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        if isinstance(value, (int, float)) or str(value).strip().lstrip('-').isdigit():
            n = float(value)
            if n >= 1e12:
                n /= 1000.0
            return datetime.fromtimestamp(n, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    s = str(value).strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def get_path(obj: Any, path: str) -> Any:
    """Dotted lookup: 'data.items', 'alertInfo.alertId', 'hits.0.id'."""
    if not path:
        return obj
    cur = obj
    for part in path.split('.'):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def _max_dt(*values: Optional[datetime]) -> Optional[datetime]:
    present = [v for v in values if v is not None]
    return max(present) if present else None


def initial_watermark(lookback_minutes: int) -> str:
    minutes = max(1, min(int(lookback_minutes or 60), 60 * 24 * 30))
    return iso_z(datetime.now(timezone.utc) - timedelta(minutes=minutes))


async def validate_target_url(
    url: str,
    *,
    allow_http: Optional[bool] = None,
    allow_private: Optional[bool] = None,
) -> None:
    """Refuse URLs that would let a connector reach internal services.

    The two policy flags default to the collector's env settings; other callers
    (automated response) pass their own.
    """
    parts = urlsplit(url)
    if allow_http is None:
        allow_http = _env_flag('COLLECTOR_ALLOW_HTTP')
    if parts.scheme not in (('https', 'http') if allow_http else ('https',)):
        raise PullError(
            f'URL scheme {parts.scheme or "(none)"!r} not allowed; use https.', kind='config'
        )
    if parts.username or parts.password:
        raise PullError('Credentials must not be embedded in the URL.', kind='config')
    host = parts.hostname
    if not host:
        raise PullError('URL has no host.', kind='config')

    if allow_private is None:
        allow_private = _env_flag('COLLECTOR_ALLOW_PRIVATE_TARGETS')
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=0)
    except OSError as exc:
        raise PullError(f'Cannot resolve {host!r}: {exc}', kind='transient') from exc

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split('%', 1)[0])
        except ValueError:
            continue
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise PullError(f'{host!r} resolves to a blocked address ({ip}).', kind='config')
        if (ip.is_private or ip.is_loopback) and not allow_private:
            raise PullError(
                f'{host!r} resolves to a private address ({ip}). Set '
                'COLLECTOR_ALLOW_PRIVATE_TARGETS=true to allow on-prem targets.',
                kind='config',
            )


# ── Base client ──────────────────────────────────────────────────────────────

class PullClient(ABC):
    client_id: str = ''
    vendor: str = ''

    def __init__(self, http: httpx.AsyncClient, config: Dict[str, Any], credentials: Dict[str, Any]):
        self.http = http
        self.config = config or {}
        self.creds = credentials or {}
        self.page_size = max(1, min(int(self.config.get('page_size') or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))
        self.validate()

    # Subclasses declare required config/credential fields.
    required_config: Tuple[str, ...] = ()
    required_credentials: Tuple[str, ...] = ()

    def validate(self) -> None:
        missing = [k for k in self.required_config if not str(self.config.get(k) or '').strip()]
        missing += [k for k in self.required_credentials if not str(self.creds.get(k) or '').strip()]
        if missing:
            raise PullError(f'Missing required settings: {", ".join(missing)}', kind='config')

    def base_url(self) -> str:
        return str(self.config.get('base_url') or '').strip().rstrip('/')

    def initial_state(self) -> Dict[str, Any]:
        return {'watermark': initial_watermark(int(self.config.get('initial_lookback_minutes') or 60))}

    @abstractmethod
    async def fetch_page(self, state: Dict[str, Any]) -> PullPage:
        ...

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Any:
        await validate_target_url(url)
        req_headers = {'Accept': 'application/json', **(headers or {})}
        try:
            async with self.http.stream(
                method,
                url,
                params=params,
                headers=req_headers,
                json=json_body,
                auth=auth,
                follow_redirects=False,
            ) as resp:
                status = resp.status_code
                if status in (401, 403):
                    raise PullError(f'{self.vendor} rejected the credentials (HTTP {status}).', kind='auth')
                if status == 429:
                    ra = resp.headers.get('Retry-After')
                    try:
                        retry_after = float(ra) if ra else None
                    except ValueError:
                        retry_after = None
                    raise PullError(f'{self.vendor} rate limited the request (HTTP 429).',
                                    kind='rate_limit', retry_after=retry_after)
                if 300 <= status < 400:
                    raise PullError(
                        f'{self.vendor} answered with a redirect (HTTP {status}); redirects are '
                        'not followed. Check the base URL.', kind='config')
                if status >= 500:
                    raise PullError(f'{self.vendor} server error (HTTP {status}).', kind='transient')
                chunks: List[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise PullError(
                            f'{self.vendor} response exceeded {MAX_RESPONSE_BYTES} bytes; '
                            'reduce page_size.', kind='config')
                    chunks.append(chunk)
                body = b''.join(chunks)
                if status >= 400:
                    snippet = body[:300].decode('utf-8', errors='replace')
                    raise PullError(f'{self.vendor} request failed (HTTP {status}): {snippet}', kind='config')
        except PullError:
            raise
        except httpx.TimeoutException as exc:
            raise PullError(f'{self.vendor} request timed out.', kind='transient') from exc
        except httpx.HTTPError as exc:
            raise PullError(f'{self.vendor} request failed: {exc.__class__.__name__}', kind='transient') from exc

        if not body:
            return {}
        try:
            return json.loads(body)
        except ValueError as exc:
            raise PullError(f'{self.vendor} returned a non-JSON response.', kind='config') from exc


# ── SentinelOne ──────────────────────────────────────────────────────────────

class SentinelOneClient(PullClient):
    """SentinelOne Management API v2.1.

    config: base_url (console, e.g. https://usea1-acme.sentinelone.net),
            resource: threats | alerts, site_ids / account_ids (optional,
            comma separated), page_size, initial_lookback_minutes
    credentials: api_token (service user API token)
    """

    client_id = 'sentinelone'
    vendor = 'sentinelone'
    required_config = ('base_url',)
    required_credentials = ('api_token',)

    _PATHS = {
        'threats': '/web/api/v2.1/threats',
        'alerts': '/web/api/v2.1/cloud-detection/alerts',
    }

    def _resource(self) -> str:
        r = str(self.config.get('resource') or 'threats').lower()
        if r not in self._PATHS:
            raise PullError(f'Unknown SentinelOne resource {r!r}.', kind='config')
        return r

    def _native(self, resource: str, item: Dict[str, Any]) -> Tuple[Optional[str], Optional[datetime]]:
        if resource == 'alerts':
            info = item.get('alertInfo') if isinstance(item.get('alertInfo'), dict) else {}
            nid = info.get('alertId') or item.get('id')
            ts = info.get('createdAt') or item.get('createdAt')
        else:
            info = item.get('threatInfo') if isinstance(item.get('threatInfo'), dict) else {}
            nid = item.get('id') or info.get('threatId')
            ts = info.get('createdAt') or item.get('createdAt')
        return (str(nid) if nid else None), to_datetime(ts)

    async def fetch_page(self, state: Dict[str, Any]) -> PullPage:
        resource = self._resource()
        watermark = state.get('watermark') or self.initial_state()['watermark']
        params: Dict[str, Any] = {
            'limit': self.page_size,
            'sortBy': 'createdAt',
            'sortOrder': 'asc',
            'createdAt__gt': watermark,
        }
        for cfg_key, param in (('site_ids', 'siteIds'), ('account_ids', 'accountIds')):
            val = str(self.config.get(cfg_key) or '').strip()
            if val:
                params[param] = ','.join(p.strip() for p in val.split(',') if p.strip())
        if state.get('cursor'):
            params['cursor'] = state['cursor']

        body = await self._request_json(
            'GET',
            self.base_url() + self._PATHS[resource],
            params=params,
            headers={'Authorization': f'ApiToken {self.creds["api_token"]}'},
        )
        data = body.get('data') if isinstance(body, dict) else None
        if not isinstance(data, list):
            raise PullError('SentinelOne response has no "data" list.', kind='config')

        items: List[PullItem] = []
        run_max = to_datetime(state.get('run_max'))
        for raw in data:
            if not isinstance(raw, dict):
                continue
            nid, ts = self._native(resource, raw)
            if not nid:
                continue
            items.append(PullItem(nid, ts, raw))
            run_max = _max_dt(run_max, ts)

        next_cursor = (body.get('pagination') or {}).get('nextCursor') if isinstance(body.get('pagination'), dict) else None
        if next_cursor and data:
            return PullPage(items, {
                'watermark': watermark,
                'cursor': next_cursor,
                'run_max': iso_z(run_max) if run_max else state.get('run_max'),
            }, done=False)
        final = _max_dt(run_max, to_datetime(watermark))
        return PullPage(items, {'watermark': iso_z(final) if final else watermark}, done=True)


# ── Sumo Logic Cloud SIEM ────────────────────────────────────────────────────

class SumoLogicClient(PullClient):
    """Sumo Logic Cloud SIEM API.

    config: base_url (deployment API endpoint incl. /api, e.g.
            https://api.us2.sumologic.com/api), resource: signals | insights,
            query (optional extra Cloud SIEM DSL filter, e.g. severity:>=5),
            exclude_records (bool, drop the bulky allRecords array),
            page_size, initial_lookback_minutes
    credentials: access_id, access_key
    """

    client_id = 'sumologic'
    vendor = 'sumologic'
    required_config = ('base_url',)
    required_credentials = ('access_id', 'access_key')

    def _resource(self) -> str:
        r = str(self.config.get('resource') or 'signals').lower()
        if r not in ('signals', 'insights'):
            raise PullError(f'Unknown Sumo Logic resource {r!r}.', kind='config')
        return r

    async def fetch_page(self, state: Dict[str, Any]) -> PullPage:
        resource = self._resource()
        watermark = state.get('watermark') or self.initial_state()['watermark']
        wm_dt = to_datetime(watermark) or datetime.now(timezone.utc)
        ts_field = 'timestamp' if resource == 'signals' else 'created'
        q = f'{ts_field}:>{wm_dt.astimezone(timezone.utc).isoformat(timespec="seconds")}'
        extra = str(self.config.get('query') or '').strip()
        if extra:
            q = f'{q} {extra}'
        offset = int(state.get('offset') or 0)
        params: Dict[str, Any] = {'q': q, 'limit': self.page_size, 'offset': offset}
        if resource == 'insights':
            params['exclude'] = 'signals.allRecords'
        elif self.config.get('exclude_records'):
            params['exclude'] = 'allRecords'

        body = await self._request_json(
            'GET',
            f'{self.base_url()}/sec/v1/{resource}',
            params=params,
            auth=(str(self.creds['access_id']), str(self.creds['access_key'])),
        )
        container = body.get('data') if isinstance(body, dict) and isinstance(body.get('data'), dict) else body
        objects = container.get('objects') if isinstance(container, dict) else None
        if not isinstance(objects, list):
            raise PullError('Sumo Logic response has no "objects" list.', kind='config')

        items: List[PullItem] = []
        run_max = to_datetime(state.get('run_max'))
        for raw in objects:
            if not isinstance(raw, dict) or not raw.get('id'):
                continue
            ts = to_datetime(raw.get('timestamp') or raw.get('created'))
            items.append(PullItem(str(raw['id']), ts, raw))
            run_max = _max_dt(run_max, ts)

        if container.get('hasNextPage') and objects:
            return PullPage(items, {
                'watermark': watermark,
                'offset': offset + len(objects),
                'run_max': iso_z(run_max) if run_max else state.get('run_max'),
            }, done=False)
        final = _max_dt(run_max, wm_dt)
        return PullPage(items, {'watermark': iso_z(final)}, done=True)


# ── AlienVault / LevelBlue USM Anywhere ──────────────────────────────────────

class UsmAnywhereClient(PullClient):
    """USM Anywhere API 2.0 alarms.

    config: base_url (https://<subdomain>.alienvault.cloud), exclude_suppressed
            (bool), page_size, initial_lookback_minutes
    credentials: client_id, client_secret (API client from Settings > API Clients)

    OSSIM / USM Appliance have no equivalent alarm API; use the syslog or
    agent transport for those.
    """

    client_id = 'usm_anywhere'
    vendor = 'alienvault'
    required_config = ('base_url',)
    required_credentials = ('client_id', 'client_secret')

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self._token: Optional[str] = None
        self._token_expiry = datetime.min.replace(tzinfo=timezone.utc)

    async def _access_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self._token and now < self._token_expiry:
            return self._token
        body = await self._request_json(
            'POST',
            f'{self.base_url()}/api/2.0/oauth/token',
            params={'grant_type': 'client_credentials'},
            auth=(str(self.creds['client_id']), str(self.creds['client_secret'])),
        )
        token = body.get('access_token') if isinstance(body, dict) else None
        if not token:
            raise PullError('USM Anywhere did not return an access token.', kind='auth')
        ttl = int(body.get('expires_in') or 600)
        self._token = str(token)
        self._token_expiry = now + timedelta(seconds=max(30, ttl - 30))
        return self._token

    async def fetch_page(self, state: Dict[str, Any]) -> PullPage:
        watermark = state.get('watermark') or self.initial_state()['watermark']
        wm_dt = to_datetime(watermark) or datetime.now(timezone.utc)
        page = int(state.get('page') or 0)
        params: Dict[str, Any] = {
            'page': page,
            'size': self.page_size,
            'sort': 'timestamp_occured,asc',
            'timestamp_occured_gte': int(wm_dt.timestamp() * 1000),
        }
        if self.config.get('exclude_suppressed'):
            params['suppressed'] = 'false'

        token = await self._access_token()
        body = await self._request_json(
            'GET',
            f'{self.base_url()}/api/2.0/alarms',
            params=params,
            headers={'Authorization': f'Bearer {token}'},
        )
        if not isinstance(body, dict):
            raise PullError('USM Anywhere returned an unexpected response.', kind='config')
        alarms = (body.get('_embedded') or {}).get('alarms') or []
        page_info = body.get('page') or {}

        items: List[PullItem] = []
        run_max = to_datetime(state.get('run_max'))
        for raw in alarms:
            if not isinstance(raw, dict) or not raw.get('uuid'):
                continue
            ts = to_datetime(raw.get('timestamp_occured_iso8601') or raw.get('timestamp_occured'))
            items.append(PullItem(str(raw['uuid']), ts, raw))
            run_max = _max_dt(run_max, ts)

        total_pages = int(page_info.get('totalPages') or 0)
        if alarms and page + 1 < total_pages:
            return PullPage(items, {
                'watermark': watermark,
                'page': page + 1,
                'run_max': iso_z(run_max) if run_max else state.get('run_max'),
            }, done=False)
        final = _max_dt(run_max, wm_dt)
        return PullPage(items, {'watermark': iso_z(final)}, done=True)


# ── Generic REST (Cybolt / custom) ───────────────────────────────────────────

class _SafeTemplate(string.Formatter):
    """`{since}` style substitution that leaves unknown braces untouched."""

    def get_value(self, key, args, kwargs):  # type: ignore[override]
        if isinstance(key, str) and key in kwargs:
            return kwargs[key]
        return '{' + str(key) + '}'


_FMT = _SafeTemplate()


def _render(value: Any, ctx: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return _FMT.format(value, **ctx)
        except (ValueError, IndexError):
            return value
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    return value


class GenericRestClient(PullClient):
    """Configurable JSON API poller.

    config:
      url              full endpoint URL
      method           GET (default) | POST
      auth_type        bearer | header | basic | none
      auth_header      header name for auth_type=header (e.g. X-API-Key)
      query_params     dict; string values may use {since} {since_epoch}
                       {since_epoch_ms} {limit} {cursor} {page} {offset}
      body             dict, POST only; same placeholders
      items_path       dotted path to the list of items ('' = body is the list)
      id_field         dotted path to each item's unique id
      timestamp_field  dotted path to each item's timestamp (ISO or epoch)
      pagination       none | cursor | page | offset
      cursor_path      dotted path to the next cursor in the response (cursor)
      cursor_param     query parameter carrying the cursor (cursor)
      page_param       query parameter for page number (page), default 'page'
      page_start       first page number, default 1
      offset_param     query parameter for offset (offset), default 'offset'
      page_size, initial_lookback_minutes
    credentials:
      token            for bearer/header
      username, password  for basic
    """

    client_id = 'generic_rest'
    vendor = 'custom'
    required_config = ('url', 'id_field')

    def validate(self) -> None:
        super().validate()
        # items_path may legitimately be '' (the body itself is the list), so
        # only its presence is required, not a non-empty value.
        if 'items_path' not in self.config or self.config.get('items_path') is None:
            raise PullError('Missing required settings: items_path', kind='config')
        auth_type = self._auth_type()
        if auth_type in ('bearer', 'header') and not str(self.creds.get('token') or '').strip():
            raise PullError('Missing required settings: token', kind='config')
        if auth_type == 'header' and not str(self.config.get('auth_header') or '').strip():
            raise PullError('Missing required settings: auth_header', kind='config')
        if auth_type == 'basic' and not (self.creds.get('username') and self.creds.get('password')):
            raise PullError('Missing required settings: username, password', kind='config')
        if self._pagination() == 'cursor' and not (self.config.get('cursor_path') and self.config.get('cursor_param')):
            raise PullError('Cursor pagination needs cursor_path and cursor_param.', kind='config')

    def _auth_type(self) -> str:
        t = str(self.config.get('auth_type') or 'bearer').lower()
        if t not in ('bearer', 'header', 'basic', 'none'):
            raise PullError(f'Unknown auth_type {t!r}.', kind='config')
        return t

    def _pagination(self) -> str:
        p = str(self.config.get('pagination') or 'none').lower()
        if p not in ('none', 'cursor', 'page', 'offset'):
            raise PullError(f'Unknown pagination {p!r}.', kind='config')
        return p

    async def fetch_page(self, state: Dict[str, Any]) -> PullPage:
        watermark = state.get('watermark') or self.initial_state()['watermark']
        wm_dt = to_datetime(watermark) or datetime.now(timezone.utc)
        pagination = self._pagination()
        page_start = int(self.config.get('page_start') if self.config.get('page_start') is not None else 1)
        page = int(state.get('page') if state.get('page') is not None else page_start)
        offset = int(state.get('offset') or 0)
        cursor = state.get('cursor')

        ctx = {
            'since': iso_z(wm_dt),
            'since_epoch': int(wm_dt.timestamp()),
            'since_epoch_ms': int(wm_dt.timestamp() * 1000),
            'limit': self.page_size,
            'cursor': cursor or '',
            'page': page,
            'offset': offset,
        }
        params = _render(dict(self.config.get('query_params') or {}), ctx)
        if pagination == 'cursor' and cursor:
            params[str(self.config['cursor_param'])] = cursor
        elif pagination == 'page':
            params[str(self.config.get('page_param') or 'page')] = page
        elif pagination == 'offset':
            params[str(self.config.get('offset_param') or 'offset')] = offset

        headers: Dict[str, str] = {}
        auth: Optional[Tuple[str, str]] = None
        auth_type = self._auth_type()
        if auth_type == 'bearer':
            headers['Authorization'] = f'Bearer {self.creds["token"]}'
        elif auth_type == 'header':
            headers[str(self.config['auth_header'])] = str(self.creds['token'])
        elif auth_type == 'basic':
            auth = (str(self.creds['username']), str(self.creds['password']))

        method = str(self.config.get('method') or 'GET').upper()
        if method not in ('GET', 'POST'):
            raise PullError(f'Unsupported method {method!r}.', kind='config')
        json_body = _render(self.config.get('body'), ctx) if method == 'POST' and self.config.get('body') else None

        body = await self._request_json(
            method, str(self.config['url']).strip(), params=params,
            headers=headers, json_body=json_body, auth=auth,
        )
        raw_items = get_path(body, str(self.config.get('items_path') or ''))
        if not isinstance(raw_items, list):
            raise PullError(
                f'items_path {self.config.get("items_path")!r} did not resolve to a list.', kind='config')

        id_field = str(self.config['id_field'])
        ts_field = str(self.config.get('timestamp_field') or '')
        items: List[PullItem] = []
        run_max = to_datetime(state.get('run_max'))
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            nid = get_path(raw, id_field)
            if nid in (None, ''):
                continue
            ts = to_datetime(get_path(raw, ts_field)) if ts_field else None
            items.append(PullItem(str(nid), ts, raw))
            run_max = _max_dt(run_max, ts)

        more = False
        next_state: Dict[str, Any] = {'watermark': watermark,
                                      'run_max': iso_z(run_max) if run_max else state.get('run_max')}
        if pagination == 'cursor':
            nxt = get_path(body, str(self.config['cursor_path']))
            if nxt and raw_items and nxt != cursor:
                more = True
                next_state['cursor'] = nxt
        elif pagination == 'page':
            if len(raw_items) >= self.page_size:
                more = True
                next_state['page'] = page + 1
        elif pagination == 'offset':
            if len(raw_items) >= self.page_size:
                more = True
                next_state['offset'] = offset + len(raw_items)

        if more:
            return PullPage(items, next_state, done=False)
        final = _max_dt(run_max, wm_dt)
        # Without a timestamp field the watermark cannot move; every run re-reads
        # the same window and relies on id dedupe. Flag it for the status view.
        info = {} if ts_field else {'warning': 'No timestamp_field configured; watermark does not advance.'}
        return PullPage(items, {'watermark': iso_z(final)}, done=True, info=info)


# ── Registry ─────────────────────────────────────────────────────────────────

CLIENTS: Dict[str, type[PullClient]] = {
    c.client_id: c for c in (SentinelOneClient, SumoLogicClient, UsmAnywhereClient, GenericRestClient)
}


def build_client(
    client_id: str,
    http: httpx.AsyncClient,
    config: Dict[str, Any],
    credentials: Dict[str, Any],
) -> PullClient:
    cls = CLIENTS.get((client_id or '').strip().lower())
    if cls is None:
        raise PullError(f'Unknown pull client {client_id!r}.', kind='config')
    return cls(http, dict(config or {}), dict(credentials or {}))
