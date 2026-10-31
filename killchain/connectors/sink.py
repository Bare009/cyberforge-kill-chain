# Copied from AI-SOC: backend/services/ingestion/raw_ingest.py
# Kept: BATCH_ENVELOPE_KEYS, MAX_BATCH_SIZE, BatchShapeError, split_batch,
# derive_alert_id, build_ingestion_meta (tenant is always 'default').
# killchain changes: split_batch also keeps plain-string records (raw log
# lines); persist_and_queue (Mongo alerts_raw + Redis queue) is replaced by a
# file sink: dedupe on (connector_id, alert_id), every record appended to
# <data>/ingest/<connector_id>/records.ndjson, and the raw log line it carries
# (if any) appended to the shared <data>/ingest/live.log that live mode tails.
# Licensing / tenancy / metrics removed.
"""Transport-neutral raw-record intake: stamp, dedupe, store, forward raw lines.

Every inbound path ends here, whatever carried the record:

  * HTTP push      -- `webhook.py`
  * API pull       -- `poller.py`
  * syslog         -- `syslog_server.py` (optional, KILLCHAIN_SYSLOG=1)

Raw line extraction: the first non-empty string among the fields in
RAW_LINE_FIELDS (`event.original` may be nested or a literal key), or the
record itself when it is a plain string. Embedded newlines split it into
several lines. A record with no such string is stored but counted as
`not_analysable`: the killchain parser only reads FortiGate key=value lines.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from .config import ingest_dir, live_log_path
from .store import ConnectorStore, get_store

logger = logging.getLogger(__name__)

TENANT_FIELD = 'tenant_id'
DEFAULT_TENANT = 'default'

# Envelope keys unwrapped when a sender batches alerts into one payload. Kept in
# sync with BATCH_ENVELOPE_KEYS in vendors.py.
BATCH_ENVELOPE_KEYS: tuple[str, ...] = (
    'alerts',
    'events',
    'records',
    'messages',
    'data',
    'items',
    'results',
)

# Guard against a runaway or hostile sender turning one request into unbounded
# work. Anything larger is rejected outright rather than partially accepted.
MAX_BATCH_SIZE = 500

RAW_LINE_FIELDS: tuple[str, ...] = ('full_log', '_raw', 'raw', 'message', 'log', 'event.original')

Record = Union[Dict[str, Any], str]

_SAFE_ID = re.compile(r'[^A-Za-z0-9_-]')


class BatchShapeError(ValueError):
    """The payload is not an alert, a list of alerts, or a known envelope.

    `too_large` distinguishes "over MAX_BATCH_SIZE" (HTTP 413) from a malformed
    body (HTTP 400) for callers that map this onto a status code.
    """

    def __init__(self, message: str, *, too_large: bool = False) -> None:
        super().__init__(message)
        self.too_large = too_large


def _is_record(v: Any) -> bool:
    return isinstance(v, dict) or (isinstance(v, str) and v.strip() != '')


def split_batch(body: Any) -> List[Record]:
    """Normalise any accepted body shape into a flat list of records.

    Accepts a single JSON object, a JSON string (one raw line), a JSON array of
    objects and/or strings, or an object wrapping such an array under a known
    envelope key. Envelope detection is generic rather than per-vendor, so a
    new log source needs no code here.
    """
    if isinstance(body, list):
        items = body
    elif isinstance(body, dict):
        items = None
        for key in BATCH_ENVELOPE_KEYS:
            val = body.get(key)
            # Only treat this as an envelope when the value is a list of
            # records. A scalar `data` field means the dict is itself the alert
            # -- unwrapping it would destroy the payload.
            if isinstance(val, list) and val and all(_is_record(v) for v in val):
                items = val
                break
        if items is None:
            return [body]
    elif isinstance(body, str) and body.strip():
        return [body]
    else:
        raise BatchShapeError('Alert payload must be a JSON object, a string, or an array of them.')

    alerts = [i for i in items if _is_record(i)]
    if not alerts:
        raise BatchShapeError('Batch contained no JSON objects or log lines.')
    if len(alerts) > MAX_BATCH_SIZE:
        raise BatchShapeError(
            f'Batch too large: {len(alerts)} alerts (max {MAX_BATCH_SIZE}).',
            too_large=True,
        )
    return alerts


def derive_alert_id(raw_alert: Record) -> str:
    """Best-effort stable id from the payload, else a unique synthetic one."""
    alert_id = None
    if isinstance(raw_alert, dict):
        alert_id = (
            raw_alert.get('id')
            or raw_alert.get('alert_id')
            or raw_alert.get('_id')
            or raw_alert.get('event_id')
            or raw_alert.get('EventRecordID')
        )
    if alert_id not in (None, ''):
        return str(alert_id)
    # A uuid rather than a timestamp: several id-less alerts arriving in the same
    # second would otherwise derive identical ids and collapse into one.
    return f'unknown-{uuid.uuid4().hex[:16]}'


def build_ingestion_meta(
    *,
    source: str,
    source_hint: Optional[str],
    cert_info: Optional[Dict[str, Any]] = None,
    connector: Optional[Dict[str, Any]] = None,
    transport: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cert_info = cert_info or {}
    meta: Dict[str, Any] = {
        'received_from': source,
        'source_hint': source_hint,
        'ingested_at': datetime.now(timezone.utc).isoformat(),
        'cert_cn': cert_info.get('common_name', 'anonymous'),
        # killchain is single-tenant.
        TENANT_FIELD: DEFAULT_TENANT,
    }
    if connector:
        meta['connector_id'] = connector.get('connector_id')
        meta['connector_name'] = connector.get('name')
        meta['auth_mode'] = connector.get('auth_mode')
        if connector.get('time_zone'):
            meta['source_timezone'] = connector.get('time_zone')
    if transport:
        meta['transport'] = transport
    if extra:
        # Transport-specific provenance (sender IP, poll cursor...). Never
        # allowed to overwrite the core keys above.
        for k, v in extra.items():
            meta.setdefault(k, v)
    return meta


def _lookup(rec: Dict[str, Any], dotted: str) -> Any:
    if dotted in rec:
        return rec[dotted]
    cur: Any = rec
    for part in dotted.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def extract_raw_lines(record: Record) -> List[str]:
    """The raw log line(s) a record carries; [] when it has none."""
    text: Optional[str] = None
    if isinstance(record, str):
        text = record
    elif isinstance(record, dict):
        for key in RAW_LINE_FIELDS:
            v = _lookup(record, key)
            if isinstance(v, str) and v.strip():
                text = v
                break
    if not text:
        return []
    return [ln.strip('\r') for ln in text.splitlines() if ln.strip()]


@dataclass
class IngestResult:
    alert_ids: List[str] = field(default_factory=list)   # accepted (not duplicate)
    duplicates: int = 0
    lines_forwarded: int = 0
    not_analysable: int = 0

    @property
    def accepted(self) -> int:
        return len(self.alert_ids)


class Sink:
    """Writes accepted records under one ingest folder. Thread-safe."""

    def __init__(self, root: Path, live_log: Path, store: Optional[ConnectorStore] = None) -> None:
        self.root = Path(root)
        self.live_log = Path(live_log)
        self.store = store
        self._lock = threading.RLock()
        self._seen: Dict[str, Set[str]] = {}

    def ensure_live_log(self) -> Path:
        """Create live.log (empty) so live mode can be started before anything arrives."""
        with self._lock:
            self.live_log.parent.mkdir(parents=True, exist_ok=True)
            if not self.live_log.exists():
                self.live_log.touch()
        return self.live_log

    def _dir(self, connector_id: str) -> Path:
        safe = _SAFE_ID.sub('_', connector_id or 'unknown')[:64] or 'unknown'
        return self.root / safe

    def _seen_ids(self, connector_id: str) -> Set[str]:
        s = self._seen.get(connector_id)
        if s is None:
            p = self._dir(connector_id) / 'seen_ids.txt'
            s = set(p.read_text(encoding='utf-8').splitlines()) if p.exists() else set()
            self._seen[connector_id] = s
        return s

    def ingest_many(
        self,
        records: List[Record],
        *,
        source: str,
        source_hint: Optional[str],
        connector: Optional[Dict[str, Any]] = None,
        transport: Optional[str] = None,
        alert_ids: Optional[List[Optional[str]]] = None,
        meta_extra: Optional[Dict[str, Any]] = None,
    ) -> IngestResult:
        """Stamp, dedupe, store and forward a batch. `alert_ids` overrides the derived ids."""
        cid = str((connector or {}).get('connector_id') or 'unknown')
        res = IngestResult()
        out_dir = self._dir(cid)
        rec_lines: List[str] = []
        new_ids: List[str] = []
        raw_lines: List[str] = []
        with self._lock:
            seen = self._seen_ids(cid)
            for i, record in enumerate(records):
                given = alert_ids[i] if alert_ids and i < len(alert_ids) else None
                alert_id = given or derive_alert_id(record)
                if alert_id in seen:
                    res.duplicates += 1
                    continue
                meta = build_ingestion_meta(
                    source=source, source_hint=source_hint, connector=connector,
                    transport=transport, extra=meta_extra,
                )
                meta['raw_id'] = alert_id
                lines = extract_raw_lines(record)
                meta['raw_lines'] = len(lines)
                if isinstance(record, dict):
                    stored = dict(record)
                    stored['_ingestion_meta'] = meta
                else:
                    stored = {'_raw': record, '_ingestion_meta': meta}
                rec_lines.append(json.dumps(stored, ensure_ascii=False, default=str))
                if lines:
                    raw_lines.extend(lines)
                    res.lines_forwarded += len(lines)
                else:
                    res.not_analysable += 1
                seen.add(alert_id)
                if not alert_id.startswith('unknown-'):
                    new_ids.append(alert_id)
                res.alert_ids.append(alert_id)

            if rec_lines:
                out_dir.mkdir(parents=True, exist_ok=True)
                with open(out_dir / 'records.ndjson', 'a', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(rec_lines) + '\n')
            if new_ids:
                with open(out_dir / 'seen_ids.txt', 'a', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(new_ids) + '\n')
            if raw_lines:
                self.live_log.parent.mkdir(parents=True, exist_ok=True)
                # One write of whole lines, so the tailer never sees half a record.
                with open(self.live_log, 'a', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(raw_lines) + '\n')

        if connector and (res.lines_forwarded or res.not_analysable or res.duplicates):
            try:
                (self.store or get_store()).update_one(
                    {'connector_id': cid},
                    {'$inc': {
                        'lines_forwarded': res.lines_forwarded,
                        'not_analysable': res.not_analysable,
                        'duplicates': res.duplicates,
                    }},
                )
            except Exception as exc:  # counters are best-effort
                logger.debug('sink counter update failed for %s: %s', cid, exc)
        return res


_sinks: Dict[str, Sink] = {}
_sinks_lock = threading.Lock()


def get_sink() -> Sink:
    """The sink for <KILLCHAIN_DATA_DIR>/ingest (one per path, per process)."""
    root, live = ingest_dir(), live_log_path()
    key = str(root.resolve())
    with _sinks_lock:
        s = _sinks.get(key)
        if s is None:
            s = _sinks[key] = Sink(root, live)
        return s
