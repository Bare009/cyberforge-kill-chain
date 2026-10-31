"""JSON-file stand-in for AI-SOC's `siem_integrations` Mongo collection.

New in killchain (AI-SOC used Motor/MongoDB). One file,
<KILLCHAIN_DATA_DIR>/connectors/connectors.json, holding a list of connector
documents in exactly the shape AI-SOC's registry writes (see registry.py).

Only the operations the copied code uses are implemented, with Mongo-like
semantics so that code needed few changes:

  find(filter)           -> list of matching docs (copies)
  find_one(filter)       -> doc or None
  insert_one(doc)
  update_one(filter, update)   update = {'$set': {...}, '$inc': {...}};
                               dotted keys ('pull_state.next_run_at') create
                               nested dicts. Returns True when a doc matched.
  delete_one(filter)     -> number deleted (0 or 1)

Filter values: a plain value means equality (a missing field equals None), or
a dict with one of $ne, $in, $lte, $lt. Datetimes round-trip through JSON as
{"$date": "<iso>"}.

Writes are atomic (temp file + os.replace) and serialised by a lock. The file
is re-read when its mtime changes, so an edit by hand is picked up.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import connectors_dir

FILE_NAME = 'connectors.json'
_MISSING = object()


def _encode(v: Any) -> Any:
    if isinstance(v, datetime):
        return {'$date': (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()}
    if isinstance(v, dict):
        return {k: _encode(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_encode(x) for x in v]
    return v


def _decode(v: Any) -> Any:
    if isinstance(v, dict):
        if set(v) == {'$date'} and isinstance(v['$date'], str):
            try:
                return datetime.fromisoformat(v['$date'])
            except ValueError:
                return v['$date']
        return {k: _decode(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_decode(x) for x in v]
    return v


def _get(doc: Dict[str, Any], dotted: str) -> Any:
    cur: Any = doc
    for part in dotted.split('.'):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _set(doc: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split('.')
    cur = doc
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _cmp_value(v: Any) -> Any:
    # Compare aware datetimes; naive ones are taken as UTC.
    if isinstance(v, datetime) and v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v


def _matches(doc: Dict[str, Any], flt: Optional[Dict[str, Any]]) -> bool:
    for key, want in (flt or {}).items():
        got = _get(doc, key)
        val = None if got is _MISSING else got
        if isinstance(want, dict) and want and all(k.startswith('$') for k in want):
            for op, arg in want.items():
                if op == '$ne':
                    if val == arg:
                        return False
                elif op == '$in':
                    vals = val if isinstance(val, list) else [val]
                    if not any(x in arg for x in vals):
                        return False
                elif op in ('$lte', '$lt'):
                    if val is None:
                        return False
                    a, b = _cmp_value(val), _cmp_value(arg)
                    try:
                        if not (a <= b if op == '$lte' else a < b):
                            return False
                    except TypeError:
                        return False
                else:
                    raise ValueError(f'unsupported filter operator {op}')
        elif val != want:
            return False
    return True


class ConnectorStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._docs: List[Dict[str, Any]] = []
        self._mtime: Optional[float] = None
        self._load()

    # ── file ────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._docs, self._mtime = [], None
            return
        if self._mtime == st.st_mtime_ns:
            return
        raw = json.loads(self.path.read_text(encoding='utf-8') or '[]')
        if isinstance(raw, dict):           # tolerate {"connectors": [...]}
            raw = raw.get('connectors') or []
        self._docs = [_decode(d) for d in raw if isinstance(d, dict)]
        self._mtime = st.st_mtime_ns

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f'.{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp')
        tmp.write_text(json.dumps(_encode(self._docs), indent=2, ensure_ascii=False), encoding='utf-8')
        os.replace(tmp, self.path)
        self._mtime = self.path.stat().st_mtime_ns

    # ── Mongo-like API ──────────────────────────────────────────────────────

    def find(self, flt: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        with self._lock:
            self._load()
            return [copy.deepcopy(d) for d in self._docs if _matches(d, flt)]

    def find_one(self, flt: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._load()
            for d in self._docs:
                if _matches(d, flt):
                    return copy.deepcopy(d)
            return None

    def insert_one(self, doc: Dict[str, Any]) -> None:
        with self._lock:
            self._load()
            cid = doc.get('connector_id')
            if cid and any(d.get('connector_id') == cid for d in self._docs):
                raise ValueError(f'duplicate connector_id {cid}')
            self._docs.append(copy.deepcopy(doc))
            self._save()

    def update_one(self, flt: Dict[str, Any], update: Dict[str, Any]) -> bool:
        with self._lock:
            self._load()
            for d in self._docs:
                if not _matches(d, flt):
                    continue
                for key, value in (update.get('$set') or {}).items():
                    _set(d, key, copy.deepcopy(value))
                for key, inc in (update.get('$inc') or {}).items():
                    cur = _get(d, key)
                    base = cur if isinstance(cur, (int, float)) and cur is not _MISSING else 0
                    _set(d, key, base + inc)
                self._save()
                return True
            return False

    def delete_one(self, flt: Dict[str, Any]) -> int:
        with self._lock:
            self._load()
            for i, d in enumerate(self._docs):
                if _matches(d, flt):
                    del self._docs[i]
                    self._save()
                    return 1
            return 0


_stores: Dict[str, ConnectorStore] = {}
_stores_lock = threading.Lock()


def get_store(path: Optional[Path] = None) -> ConnectorStore:
    """The store for <KILLCHAIN_DATA_DIR>/connectors/connectors.json (one per path, per process)."""
    p = Path(path) if path else connectors_dir() / FILE_NAME
    key = str(p.resolve())
    with _stores_lock:
        st = _stores.get(key)
        if st is None:
            st = _stores[key] = ConnectorStore(p)
        return st
