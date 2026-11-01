"""A fixed mapping applied to a batch of records: source fields -> the canonical Arrow table.

The same Mapper converts the sample in `schema` (for coverage and validation) and every batch in the
generic parser, so the report shows exactly what the parse writes. All work is columnar (pyarrow
compute on whole batches); only a value that needs a Python fallback (an odd time format) is handled
one distinct value at a time.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc

from ..parser import arrowutil as au
from . import canonical as C
from .mapping import Synonyms, load_synonyms, map_value, parse_one, severity_1_5

Getter = Callable[[str], pa.Array]
_NULL = pa.scalar(None, pa.string())
CATEGORIES = ("network", "endpoint", "auth", "vendor_alert", "other")
PER_RECORD = "per_record"


def clean(arr: pa.Array) -> pa.Array:
    """Trimmed text; empty and '-' (the usual 'no value' of Windows, web and Zeek logs) -> null."""
    if not pa.types.is_string(arr.type) and not pa.types.is_large_string(arr.type):
        arr = pc.cast(arr, pa.string())
    if arr.null_count == len(arr):
        return arr
    t = pc.utf8_trim_whitespace(arr)
    empty = pc.or_(pc.equal(pc.utf8_length(t), 0), pc.equal(t, "-"))
    return pc.if_else(empty, _NULL, t)


def _nulls(n: int) -> pa.Array:
    return pa.nulls(n, pa.string())


def map_array(col: str, arr: pa.Array, maps: Dict[str, Dict[str, Any]]) -> pa.Array:
    """Value-map a text array through its dictionary (one Python call per distinct value)."""
    if arr.null_count == len(arr):
        return arr
    enc = pc.dictionary_encode(arr)
    if isinstance(enc, pa.ChunkedArray):
        enc = enc.combine_chunks()
    mapped = pa.array([map_value(col, v, maps) for v in enc.dictionary.to_pylist()], pa.string())
    return pc.take(mapped, enc.indices)


def _lower(arr: pa.Array) -> pa.Array:
    return pc.utf8_lower(arr) if arr.null_count < len(arr) else arr


def true_only(mask: pa.Array) -> pa.Array:
    """Boolean with nulls -> null as False. (pc.fill_null(mask, False) loses some True values on
    boolean arrays in pyarrow 21; Kleene AND with the validity is exact.)"""
    return pc.and_kleene(mask, pc.is_valid(mask))


def _is_in(arr: pa.Array, values: Sequence[Any]) -> pa.Array:
    vs = pa.array([str(v).lower() for v in values], pa.string())
    return true_only(pc.is_in(_lower(arr), value_set=vs))


def row_categories(cols: Dict[str, pa.Array], n: int) -> pa.Array:
    """Category of each record from the columns it has (vendor_alert > endpoint > auth > network > other)."""
    def has(c: str) -> pa.Array:
        a = cols.get(c)
        return pa.array(np.zeros(n, dtype=bool)) if a is None else pc.is_valid(a)

    def eq(c: str, values: Sequence[str]) -> pa.Array:
        a = cols.get(c)
        return pa.array(np.zeros(n, dtype=bool)) if a is None else _is_in(a, values)

    alert = pc.or_(has("alert_name"), pc.or_(has("mitre_technique"), has("mitre_tactic")))
    endpoint = pc.or_(pc.or_(has("process_name"), has("command_line")), pc.or_(has("parent_process"), has("file_hash")))
    auth = pc.or_(pc.or_(has("logon_type"), eq("action", ["login", "logout"])),
                  eq("log_desc", ["Admin login failed", "Admin login successful"]))
    network = pc.or_(has("src_ip"), has("dst_ip"))
    out = np.full(n, "other", dtype=object)
    for mask, name in ((network, "network"), (auth, "auth"), (endpoint, "endpoint"), (alert, "vendor_alert")):
        out[np.asarray(mask.to_numpy(zero_copy_only=False), dtype=bool)] = name
    return pa.array(out, pa.string())


class Mapper:
    """mapping: the schema.yaml document (see docs/schema.md)."""

    def __init__(self, mapping: Dict[str, Any], synonyms: Optional[Synonyms] = None) -> None:
        syn = synonyms or load_synonyms()
        self.mapping = mapping
        self.columns: Dict[str, List[str]] = {c: list(s.get("fields") or []) for c, s in
                                             (mapping.get("columns") or {}).items() if s and s.get("fields")}
        maps = {c: dict(m) for c, m in syn.value_maps.items()}
        for c, m in (mapping.get("value_maps") or {}).items():
            maps.setdefault(c, {}).update({str(k).strip().lower(): v for k, v in (m or {}).items()})
        self.value_maps = maps
        self.value_maps_by = mapping["value_maps_by"] if "value_maps_by" in mapping else syn.value_maps_by
        self.derive = mapping["derive"] if "derive" in mapping else syn.derive
        self.time = mapping.get("time") or {}
        self.assume_tz = au.parse_tz(mapping.get("assume_tz") or "+00:00", 0)
        self.severity_scale = mapping.get("severity_scale")
        self.vendor_severity_scale = mapping.get("vendor_severity_scale")
        self.category = mapping.get("category") or {}
        self.product = mapping.get("product_name")

    # -- fields
    def needed_fields(self) -> List[str]:
        out: List[str] = []
        for fs in self.columns.values():
            out += fs
        for k in ("field", "tz_field", "date_field", "time_field"):
            if self.time.get(k):
                out.append(self.time[k])
        if self.category.get("field"):
            out.append(self.category["field"])
        return list(dict.fromkeys(out))

    def used_fields(self) -> set:
        """Fields whose values land in a column; every other field is kept in `extra`."""
        used = set()
        for c, fs in self.columns.items():
            if c != "alert_entities":
                used.update(fs)
        for k in ("field", "tz_field", "date_field", "time_field"):
            if self.time.get(k):
                used.add(self.time[k])
        return used

    # -- columns
    def _coalesce(self, get: Getter, fields: List[str], n: int) -> pa.Array:
        arrs = [clean(get(f)) for f in fields]
        if not arrs:
            return _nulls(n)
        return arrs[0] if len(arrs) == 1 else pc.coalesce(*arrs)

    def text_columns(self, get: Getter, n: int) -> Dict[str, pa.Array]:
        """Canonical text per column after value maps, contextual maps and derived values."""
        cols: Dict[str, pa.Array] = {}
        for c, fs in self.columns.items():
            if c in ("ts", "tz", "date", "time_of_day"):
                continue
            cols[c] = self._coalesce(get, fs, n)
        for c in list(cols):
            if c in C.LITERAL_COLS or c == "proto" or c in self.value_maps:
                cols[c] = map_array(c, cols[c], self.value_maps)
        dq = cols.pop("dns_query", None)
        if dq is not None and dq.null_count < n:
            cols["hostname"] = pc.coalesce(cols["hostname"], dq) if "hostname" in cols else dq
            sub = cols.get("log_subtype", _nulls(n))
            cols["log_subtype"] = pc.if_else(pc.and_(pc.is_valid(dq), pc.is_null(sub)), pa.scalar("dns"), sub)
        self._contextual(cols, n)
        self._derive(cols, n)
        return cols

    def _contextual(self, cols: Dict[str, pa.Array], n: int) -> None:
        for col, spec in (self.value_maps_by or {}).items():
            by = spec.get("by")
            if col not in cols or by not in cols:
                continue
            arr, key = cols[col], cols[by]
            for kv, m in (spec.get("maps") or {}).items():
                sel = _is_in(key, [kv])
                if not pc.any(sel).as_py():
                    continue
                for raw, new in (m or {}).items():
                    hit = pc.and_(sel, true_only(pc.equal(arr, str(raw))))
                    arr = pc.if_else(hit, pa.scalar(str(new)), arr)
            cols[col] = arr

    def _derive(self, cols: Dict[str, pa.Array], n: int) -> None:
        for d in self.derive or []:
            mask = pa.array(np.ones(n, dtype=bool))
            for c, values in (d.get("when") or {}).items():
                a = cols.get(c)
                if a is None:
                    mask = None
                    break
                mask = pc.and_(mask, _is_in(a, values if isinstance(values, list) else [values]))
            if mask is None or not pc.any(mask).as_py():
                continue
            for c, v in (d.get("set") or {}).items():
                a = cols.get(c, _nulls(n))
                cols[c] = pc.if_else(pc.and_(mask, pc.is_null(a)), pa.scalar(str(v)), a)
            for dst, src in (d.get("copy") or {}).items():
                if src in cols:
                    a = cols.get(dst, _nulls(n))
                    cols[dst] = pc.if_else(pc.and_(mask, pc.is_null(a)), cols[src], a)

    # -- time
    def time_values(self, get: Getter, n: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray, pa.Array, Optional[pa.Array]]:
        """(UTC µs, valid, quality codes, source text, epoch raw) for the batch."""
        t = self.time
        fmt = t.get("format")
        if t.get("date_field") and t.get("time_field"):
            text = pc.binary_join_element_wise(clean(get(t["date_field"])), clean(get(t["time_field"])), " ")
        elif t.get("field"):
            text = clean(get(t["field"]))
        else:
            return (np.zeros(n, np.int64), np.zeros(n, bool), np.full(n, au.Q_MISSING, np.int8), _nulls(n), None)
        tz = au.tz_offsets(clean(get(t["tz_field"])), self.assume_tz) if t.get("tz_field") else None
        ts = np.zeros(n, np.int64)
        valid = np.zeros(n, bool)
        quality = np.full(n, au.Q_MISSING, np.int8)
        raw_epoch = None
        if fmt == "epoch":
            ints = au.to_int(text)
            v, ok = au._np_int(ints)
            fl = pc.cast(pc.if_else(pc.and_(pc.is_null(ints), pc.is_valid(text)), text, _NULL), pa.float64(), safe=False) \
                if pc.any(pc.and_(pc.is_null(ints), pc.is_valid(text))).as_py() else None
            us = np.zeros(n, np.int64)
            for lo, hi, mul, div in ((1e17, 1e20, 1, 1000), (1e14, 1e17, 1, 1), (1e11, 1e14, 1000, 1), (1e8, 1e11, 1_000_000, 1)):
                m = ok & (v >= lo) & (v < hi)
                us[m] = v[m] * mul // div
                valid |= m
            if fl is not None:
                f = pc.fill_null(fl, 0).to_numpy(zero_copy_only=False)
                fm = pc.is_valid(fl).to_numpy(zero_copy_only=False) & ~valid
                for lo, hi, mul in ((1e17, 1e20, 1e-3), (1e14, 1e17, 1), (1e11, 1e14, 1e3), (1e8, 1e11, 1e6)):
                    m = fm & (f >= lo) & (f < hi)
                    us[m] = (f[m] * mul).astype(np.int64)
                    valid |= m
            ts = us
            quality[valid] = au.Q_OK
            raw_epoch = pa.array(v, pa.int64(), mask=~ok)
        elif fmt == "iso":
            ts, valid, quality = au.json_time(text.to_pylist(), self.assume_tz)
            if tz is not None:   # a separate zone field: naive values are in that zone
                naive = valid & (quality == au.Q_TZ_ASSUMED)
                ts = np.where(naive, ts + self.assume_tz * 1_000_000 - tz * 1_000_000, ts)
                quality[naive] = au.Q_OK
        elif fmt:
            zoned_fmt = "%z" in fmt
            parsed = None
            if "%f" not in fmt and "%p" not in fmt:
                try:
                    parsed = pc.strptime(text, format=fmt, unit="us", error_is_null=True)
                except (pa.ArrowInvalid, pa.ArrowNotImplementedError):
                    parsed = None
            if parsed is not None:
                v, ok = au._np_int(pc.cast(parsed, pa.int64()))
            else:
                enc = pc.dictionary_encode(text)
                lut_v, lut_ok = [], []
                for s in enc.dictionary.to_pylist():
                    r = parse_one(s, fmt)
                    lut_v.append(r[0] if r else 0)
                    lut_ok.append(r is not None)
                idx = pc.fill_null(enc.indices, 0).to_numpy(zero_copy_only=False).astype(np.int64)
                lv = np.array(lut_v or [0], np.int64)
                lo = np.array(lut_ok or [False], bool)
                v = lv[idx]
                ok = lo[idx] & pc.is_valid(enc.indices).to_numpy(zero_copy_only=False)
            valid = ok
            if zoned_fmt:
                ts = v
                quality[valid] = au.Q_OK
            else:
                off = tz if tz is not None else np.full(n, self.assume_tz, np.int64)
                ts = v - off * 1_000_000
                quality[valid] = au.Q_OK if tz is not None else au.Q_TZ_ASSUMED
        return ts, valid, quality, text, raw_epoch

    # -- category
    def categories(self, cols: Dict[str, pa.Array], get: Getter, n: int) -> pa.Array:
        per_row = row_categories(cols, n)
        f, m = self.category.get("field"), self.category.get("map") or {}
        if not f or not m:
            return per_row
        key = clean(get(f))
        enc = pc.dictionary_encode(key)
        lut = pa.array([m.get(v) if m.get(v) in CATEGORIES else None for v in enc.dictionary.to_pylist()], pa.string())
        by_group = pc.take(lut, enc.indices)
        return pc.coalesce(by_group, per_row)

    # -- the table
    def table(self, get: Getter, n: int, source: str, lines: Sequence[int], offsets: Sequence[int],
              hashes: Sequence[int], extras: Union[List[Optional[dict]], pa.Array, None],
              issues: Optional[List[Optional[List[str]]]], tq: Optional[au.TimeQuality]) -> Tuple[pa.Table, dict]:
        issues = list(issues) if issues is not None else [None] * n
        bad: Dict[int, Dict[str, Any]] = {}
        cols = self.text_columns(get, n)
        ts, valid, quality, ttext, raw_epoch = self.time_values(get, n)
        lost = true_only(pc.and_(pc.is_valid(ttext), pa.array(~valid)))
        if pc.any(lost).as_py():
            for i in np.flatnonzero(lost.to_numpy(zero_copy_only=False)):
                bad.setdefault(int(i), {})["_bad_ts"] = ttext[int(i)].as_py()
                issues[int(i)] = (issues[int(i)] or []) + ["bad_time"]
        if tq is not None:
            tq.apply(ts, valid, quality)
        arrays: Dict[str, pa.Array] = {
            "ts": au.ts_array(ts, valid), "ts_quality": au.quality_array(quality),
            "event_time_raw": raw_epoch if raw_epoch is not None else pa.nulls(n, pa.int64()),
            "source": pa.array([source] * n, pa.string()),
            "line": pa.array(lines, pa.int64()), "byte_offset": pa.array(offsets, pa.int64()),
            "line_hash": pa.array(hashes, pa.int64()),
        }
        sev_text = cols.get("severity")
        if "vendor_severity" in cols:
            vs = cols.pop("vendor_severity")
            scale = self.vendor_severity_scale
        elif sev_text is not None:
            vs, scale = sev_text, self.severity_scale
        else:
            vs, scale = None, None
        if vs is not None and scale:
            enc = pc.dictionary_encode(vs)
            lut = pa.array([severity_1_5(v, scale) for v in enc.dictionary.to_pylist()], pa.int64())
            arrays["vendor_severity"] = pc.take(lut, enc.indices)
        if sev_text is not None:
            cols["severity"] = _lower(sev_text)
        for name in C.OUTPUT_COLUMNS:
            if name in arrays or name == "category":
                continue
            a = cols.get(name)
            if a is None:
                arrays[name] = pa.nulls(n, pa.int64() if name in C.INT_COLS else pa.float64() if name in C.FLOAT_COLS
                                        else pa.string())
            elif name in C.INT_COLS:
                arrays[name] = au.to_int(a)
                for i, v in _lost(a, arrays[name]):
                    bad.setdefault(i, {})["_bad_" + name] = v
                    if "bad_number" not in (issues[i] or []):
                        issues[i] = (issues[i] or []) + ["bad_number"]
            elif name in C.FLOAT_COLS:
                f = pc.cast(pc.if_else(pc.match_substring_regex(a, r"^-?\d+(\.\d+)?$"), a, _NULL), pa.float64())
                arrays[name] = pc.if_else(pc.greater(f, 1.0), pc.divide(f, 100.0), f)
            else:
                arrays[name] = a
        if self.product and cols.get("product") is None:
            arrays["product"] = pa.array([self.product] * n, pa.string())
        arrays["category"] = self.categories(cols, get, n)
        arrays["parse_issue"] = pa.array([",".join(dict.fromkeys(i)) if i else None for i in issues], pa.string())
        arrays["extra"] = _merge_extra(extras, bad, n)
        table = pa.table({f.name: arrays[f.name] for f in C.SCHEMA}, schema=C.SCHEMA)
        info = au.batch_info(ts, valid, quality)
        info["issues"] = dict(Counter(x for i in issues if i for x in dict.fromkeys(i)))
        return table, info


def _lost(text: pa.Array, ints: pa.Array) -> List[Tuple[int, str]]:
    """(row, text) where a number column got a value that is not an integer (as arrowutil.lost_values)."""
    lost = true_only(pc.and_(pc.is_valid(text), pc.is_null(ints)))
    if not pc.any(lost).as_py():
        return []
    idx = np.flatnonzero(lost.to_numpy(zero_copy_only=False))
    return [(int(i), text[int(i)].as_py()) for i in idx]


def _merge_extra(extras: Union[List[Optional[dict]], pa.Array, None], bad: Dict[int, Dict[str, Any]], n: int) -> pa.Array:
    if extras is None:
        extras = [None] * n
    if isinstance(extras, (pa.Array, pa.ChunkedArray)):
        if not bad:
            return extras
        vals = extras.to_pylist()
        for i, b in bad.items():
            cur = au.loads(vals[i]) if vals[i] else {}
            vals[i] = au.dumps({**cur, **b})
        return pa.array(vals, pa.string())
    out = []
    for i, e in enumerate(extras):
        if i in bad:
            e = {**(e or {}), **bad[i]}
        out.append(au.dumps(e) if e else None)
    return pa.array(out, pa.string())


def records_getter(records: Sequence[Dict[str, Any]], fields: Sequence[str]) -> Getter:
    """Getter over a list of flat records (values turned into text once per field)."""
    from .mapping import to_text

    cache: Dict[str, pa.Array] = {}

    def get(f: str) -> pa.Array:
        a = cache.get(f)
        if a is None:
            vals = [r.get(f) for r in records]
            a = pa.array([v if (type(v) is str and v) else (None if v is None else to_text(v)) for v in vals],
                         pa.string())
            cache[f] = a
        return a
    return get
