"""Column helpers shared by the line parsers.

Raw values -> typed Arrow arrays, event time, and the time-quality flags written
to every row's `ts_quality` column.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence, Tuple

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc

try:
    import orjson

    loads = orjson.loads

    def dumps(obj: Any) -> str:
        return orjson.dumps(obj, default=str).decode()

except ImportError:  # orjson is optional; the stdlib is slower but equivalent
    import json

    loads = json.loads

    def dumps(obj: Any) -> str:
        return json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)


NS = 1_000_000_000
INT64_MIN = int(np.iinfo(np.int64).min)

QUALITY = ("ok", "eventtime_mismatch", "date_missing", "missing", "stuck", "backwards", "tz_assumed")
Q_OK, Q_MISMATCH, Q_DATE_MISSING, Q_MISSING, Q_STUCK, Q_BACKWARDS, Q_TZ_ASSUMED = range(len(QUALITY))

_QUALITY_ARR = pa.array(QUALITY, pa.string())
_NULL_STR = pa.scalar(None, pa.string())
# Up to 18 digits, or 19 digits below 9e18 (int64 max is 9.22e18); nanosecond
# epochs such as FortiGate's eventtime have 19 digits.
_INT_RE = r"^-?(?:\d{1,18}|[1-8]\d{18})$"
_TZ_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_NUM_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_EPOCH_NAIVE = datetime(1970, 1, 1)
_US = timedelta(microseconds=1)
_NAIVE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S")


# ── value conversion ─────────────────────────────────────────────────────────

def str_array(values: Sequence[Optional[bytes]]) -> pa.Array:
    """bytes/None -> utf8 array. Invalid UTF-8 is replaced, never raised."""
    arr = pa.array(values, type=pa.binary())
    try:
        return arr.cast(pa.string())
    except (pa.ArrowInvalid, pa.ArrowTypeError):
        return pa.array([v.decode("utf-8", "replace") if v is not None else None for v in values], type=pa.string())


def unquote(arr: pa.Array) -> pa.Array:
    """Drop the double quotes around key="value" values and undo \\" escapes."""
    if arr.null_count == len(arr):
        return arr
    quoted = pc.and_(pc.starts_with(arr, '"'), pc.ends_with(arr, '"'))
    if not pc.any(quoted).as_py():
        return arr
    out = pc.if_else(quoted, pc.utf8_slice_codeunits(arr, 1, -1), arr)
    if pc.any(pc.match_substring(out, "\\")).as_py():
        out = pc.replace_substring(out, '\\"', '"')
    return out


def to_int(s: pa.Array) -> pa.Array:
    """String array -> int64; anything that is not a plain integer becomes null."""
    if s.null_count == len(s):
        return pa.nulls(len(s), pa.int64())
    s = pc.if_else(pc.match_substring_regex(s, _INT_RE), s, _NULL_STR)
    return pc.cast(s, pa.int64())


def int_array(values: Sequence[Optional[bytes]]) -> pa.Array:
    return to_int(unquote(str_array(values)))


def _np_int(arr: pa.Array) -> Tuple[np.ndarray, np.ndarray]:
    """(values with nulls as 0, validity mask)."""
    valid = pc.is_valid(arr).to_numpy(zero_copy_only=False)
    values = pc.fill_null(arr, 0).to_numpy(zero_copy_only=False).astype(np.int64, copy=False)
    return values, valid


# ── time zones and event time ────────────────────────────────────────────────

def parse_tz(value: Optional[str], default: int = 0) -> int:
    """'+0530', '+05:30', 'Z', 'UTC' -> seconds east of UTC; anything else -> default."""
    if not value:
        return default
    v = value.strip()
    if v.upper() in ("Z", "UTC", "GMT"):
        return 0
    m = _TZ_RE.match(v)
    if not m:
        return default
    secs = int(m.group(2)) * 3600 + int(m.group(3)) * 60
    return -secs if m.group(1) == "-" else secs


def tz_offsets(tz: pa.Array, default: int) -> np.ndarray:
    enc = pc.dictionary_encode(tz)
    table = np.array([parse_tz(v, default) for v in enc.dictionary.to_pylist()] + [default], dtype=np.int64)
    idx = pc.fill_null(enc.indices, len(table) - 1).to_numpy(zero_copy_only=False).astype(np.int64)
    return table[idx]


def fortigate_time(date: pa.Array, time_: pa.Array, tz: pa.Array, eventtime: pa.Array,
                   default_tz: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Event time in UTC microseconds from FortiGate date/time/tz/eventtime.

    `eventtime` adds sub-second precision, but devices disagree on what it means:
    FortiOS writes a true UTC epoch, while the organisers' data writes the local
    wall clock as if it were UTC (it is exactly `tz` ahead). Both readings are
    checked against date+time and the one that agrees within 2 s wins. When
    neither agrees, date+time is kept and the row is flagged eventtime_mismatch.
    """
    n = len(date)
    local = pc.strptime(pc.binary_join_element_wise(date, time_, " "),
                        format="%Y-%m-%d %H:%M:%S", unit="s", error_is_null=True)
    local_s, has_local = _np_int(pc.cast(local, pa.int64()))
    tzo = tz_offsets(tz, default_tz)
    utc_s = local_s - tzo

    et, has_et = _np_int(eventtime)
    et_ns = np.zeros(n, dtype=np.int64)
    m_ns = has_et & (et >= 10**17)
    m_us = has_et & (et >= 10**14) & (et < 10**17)
    m_ms = has_et & (et >= 10**11) & (et < 10**14)
    m_s = has_et & (et >= 10**8) & (et < 9 * 10**9)
    et_ns[m_ns] = et[m_ns]
    et_ns[m_us] = et[m_us] * 1_000
    et_ns[m_ms] = et[m_ms] * 1_000_000
    et_ns[m_s] = et[m_s] * NS
    has_et = m_ns | m_us | m_ms | m_s

    both = has_et & has_local
    as_local = both & (np.abs(et_ns - local_s * NS) < 2 * NS)
    as_utc = both & ~as_local & (np.abs(et_ns - utc_s * NS) < 2 * NS)
    ts_ns = np.where(has_local, utc_s * NS, et_ns)
    ts_ns = np.where(as_local, et_ns - tzo * NS, ts_ns)
    ts_ns = np.where(as_utc, et_ns, ts_ns)

    quality = np.full(n, Q_OK, dtype=np.int8)
    quality[both & ~as_local & ~as_utc] = Q_MISMATCH
    quality[~has_local & has_et] = Q_DATE_MISSING
    valid = has_local | has_et
    quality[~valid] = Q_MISSING
    return ts_ns // 1_000, valid, quality


def parse_time_value(v: Any, default_tz: int) -> Optional[Tuple[int, int]]:
    """One JSON time value (ISO string or epoch number) -> (UTC microseconds, quality code)."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and _NUM_RE.match(v.strip())):
        x = float(v)
        if x >= 1e17:
            return int(x // 1_000), Q_OK
        if x >= 1e14:
            return int(x), Q_OK
        if x >= 1e11:
            return int(x * 1_000), Q_OK
        if x >= 1e8:
            return int(x * 1_000_000), Q_OK
        return None
    if not isinstance(v, str):
        return None
    t = v.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    dt = None
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        for fmt in _NAIVE_FORMATS:
            try:
                dt = datetime.strptime(t, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        return (dt - _EPOCH_NAIVE) // _US - default_tz * 1_000_000, Q_TZ_ASSUMED
    return (dt - _EPOCH) // _US, Q_OK


def json_time(values: Sequence[Any], default_tz: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    n = len(values)
    as_text = pa.array([None if v is None else str(v) for v in values], pa.string())
    try:
        # Fast path: ISO 8601 strings that carry a zone.
        ts, valid = _np_int(pc.cast(pc.cast(as_text, pa.timestamp("us", tz="UTC")), pa.int64()))
        quality = np.full(n, Q_OK, dtype=np.int8)
        quality[~valid] = Q_MISSING
        return ts, valid, quality
    except (pa.ArrowInvalid, pa.ArrowNotImplementedError):
        pass
    ts = np.zeros(n, dtype=np.int64)
    valid = np.zeros(n, dtype=bool)
    quality = np.full(n, Q_MISSING, dtype=np.int8)
    for i, v in enumerate(values):
        r = parse_time_value(v, default_tz)
        if r is not None:
            ts[i], quality[i] = r
            valid[i] = True
    return ts, valid, quality


# ── time quality ─────────────────────────────────────────────────────────────

class TimeQuality:
    """Flags stuck clocks and lines that jump back in time.

    State is kept across the batches of one byte range, so runs and the running
    maximum continue over batch boundaries.

    stuck:     at least `stuck_run` consecutive rows carry the identical timestamp.
               Real traffic at microsecond precision never does that; a generator
               or device clamping its clock does. The first rows of a run that
               started in an already-written batch stay unflagged (< stuck_run rows).
    backwards: more than `backwards_secs` older than the newest good row so far.
    """

    def __init__(self, stuck_run: int = 1000, backwards_secs: int = 300) -> None:
        self.stuck_run = stuck_run
        self.backwards_us = backwards_secs * 1_000_000
        self.prev: Optional[int] = None
        self.run = 0
        self.maxv = INT64_MIN

    def apply(self, ts: np.ndarray, valid: np.ndarray, quality: np.ndarray) -> None:
        n = len(ts)
        if n == 0:
            return
        same = np.zeros(n, dtype=bool)
        same[1:] = valid[1:] & valid[:-1] & (ts[1:] == ts[:-1])
        cont = bool(valid[0] and self.prev is not None and ts[0] == self.prev)
        same[0] = cont
        run_id = np.cumsum(~same)  # 0 marks the run carried over from the previous batch
        counts = np.bincount(run_id)
        lens = counts[run_id]
        if cont:
            lens = lens + np.where(run_id == 0, self.run, 0)
        stuck = valid & (lens >= self.stuck_run)
        last = int(run_id[-1])
        if valid[-1]:
            self.run = int(counts[last]) + (self.run if cont and last == 0 else 0)
            self.prev = int(ts[-1])
        else:
            self.run, self.prev = 0, None
        quality[stuck] = Q_STUCK

        live = valid & ~stuck
        runmax = np.maximum.accumulate(np.where(live, ts, INT64_MIN))
        np.maximum(runmax, self.maxv, out=runmax)
        prevmax = np.empty(n, dtype=np.int64)
        prevmax[0] = self.maxv
        prevmax[1:] = runmax[:-1]
        has_prev = prevmax != INT64_MIN
        back = live & has_prev & (ts < np.where(has_prev, prevmax, 0) - self.backwards_us)
        quality[back] = Q_BACKWARDS
        self.maxv = int(runmax[-1])


# ── output helpers ───────────────────────────────────────────────────────────

def ts_array(ts_us: np.ndarray, valid: np.ndarray) -> pa.Array:
    return pa.array(ts_us, type=pa.timestamp("us", tz="UTC"), mask=~valid)


def quality_array(codes: np.ndarray) -> pa.Array:
    return pc.take(_QUALITY_ARR, pa.array(codes.astype(np.int32)))


def batch_info(ts_us: np.ndarray, valid: np.ndarray, quality: np.ndarray) -> dict:
    counts = np.bincount(quality.astype(np.int64), minlength=len(QUALITY))
    info: dict = {"quality": {QUALITY[i]: int(c) for i, c in enumerate(counts) if c}}
    good = valid & ((quality == Q_OK) | (quality == Q_TZ_ASSUMED))
    if good.any():
        info["min_ok"] = int(ts_us[good].min())
        info["max_ok"] = int(ts_us[good].max())
    return info
