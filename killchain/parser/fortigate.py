"""FortiGate key=value lines -> the `firewall` table.

A line looks like
    date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" ... srcip=10.10.40.225 ...
Values are bare tokens or double-quoted strings (which may contain spaces, '='
and \\" escapes). Known keys become typed columns with snake_case names; any
other key is kept in `extra` as a JSON object, so nothing in the line is lost.
"""

from __future__ import annotations

import re
from collections import Counter
from itertools import chain
from typing import List, Optional, Tuple

import pyarrow as pa

from . import arrowutil as au

PREFIX = b"date="
# A quoted value is "[^"\\]*(?:\\.[^"\\]*)*": the same strings as "(?:[^"\\]|\\.)*", but runs of
# ordinary bytes match in one step instead of one alternation per byte.
KV_RE = re.compile(rb'([A-Za-z0-9_\-]+)=("[^"\\]*(?:\\.[^"\\]*)*"|[^ ]*)')

# (FortiGate key, column, type)
FIELDS: List[Tuple[str, str, str]] = [
    ("logid", "log_id", "str"),
    ("type", "log_type", "str"),
    ("subtype", "log_subtype", "str"),
    ("level", "level", "str"),
    ("action", "action", "str"),
    ("status", "status", "str"),
    ("reason", "reason", "str"),
    ("srcip", "src_ip", "str"),
    ("srcport", "src_port", "int"),
    ("srcintf", "src_intf", "str"),
    ("srcintfrole", "src_intf_role", "str"),
    ("srccountry", "src_country", "str"),
    ("dstip", "dst_ip", "str"),
    ("dstport", "dst_port", "int"),
    ("dstintf", "dst_intf", "str"),
    ("dstintfrole", "dst_intf_role", "str"),
    ("dstcountry", "dst_country", "str"),
    ("proto", "proto", "int"),
    ("service", "service", "str"),
    ("policyid", "policy_id", "int"),
    ("sessionid", "session_id", "int"),
    ("app", "app", "str"),
    ("appcat", "app_cat", "str"),
    ("apprisk", "app_risk", "str"),
    ("duration", "duration", "int"),
    ("sentbyte", "sent_bytes", "int"),
    ("rcvdbyte", "rcvd_bytes", "int"),
    ("sentpkt", "sent_pkts", "int"),
    ("rcvdpkt", "rcvd_pkts", "int"),
    ("hostname", "hostname", "str"),
    ("url", "url", "str"),
    ("catdesc", "cat_desc", "str"),
    ("attack", "attack", "str"),
    ("attackid", "attack_id", "int"),
    ("severity", "severity", "str"),
    ("crscore", "cr_score", "int"),
    ("virus", "virus", "str"),
    ("user", "user", "str"),
    ("ui", "ui", "str"),
    ("method", "method", "str"),
    ("logdesc", "log_desc", "str"),
    ("msg", "msg", "str"),
    ("devname", "dev_name", "str"),
    ("devid", "dev_id", "str"),
    ("vd", "vd", "str"),
]
TIME_KEYS = (b"date", b"time", b"tz", b"eventtime")
_KEYS = TIME_KEYS + tuple(k.encode() for k, _, _ in FIELDS)
_KNOWN = frozenset(_KEYS)
_INT_COLS = {name for _, name, kind in FIELDS if kind == "int"}

SCHEMA = pa.schema(
    [
        ("ts", pa.timestamp("us", tz="UTC")),
        ("ts_quality", pa.string()),
        ("event_time_raw", pa.int64()),
        ("source", pa.string()),
        ("line", pa.int64()),
        ("byte_offset", pa.int64()),
        ("line_hash", pa.int64()),
    ]
    + [(name, pa.int64() if kind == "int" else pa.string()) for _, name, kind in FIELDS]
    + [("parse_issue", pa.string()), ("extra", pa.string())]
)


def _unq(v: bytes) -> str:
    if len(v) >= 2 and v[:1] == b'"' and v[-1:] == b'"':
        v = v[1:-1].replace(b'\\"', b'"')
    return v.decode("utf-8", "replace")


def _binary_start(raw: bytes) -> Optional[int]:
    """Offset of the first control byte or invalid UTF-8 sequence, or None."""
    m = au.CTRL_RE.search(raw)
    cut = m.start() if m else None
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as e:
        cut = e.start if cut is None else min(cut, e.start)
    return cut


def _covered(pairs: List[Tuple[bytes, bytes]]) -> int:
    """Bytes a line has when it is exactly these key=value pairs joined by single spaces."""
    # map/chain run in C: this is called once per line, and a generator here cost a third of parse time
    return sum(map(len, chain.from_iterable(pairs))) + 2 * len(pairs) - 1 if pairs else 0


class FortiGateBatch:
    stream = "firewall"
    schema = SCHEMA

    def __init__(self) -> None:
        self.rows: List[tuple] = []
        self.meta: List[Tuple[int, int, int]] = []
        self.extras: List[Optional[dict]] = []
        self.issues: List[Optional[List[str]]] = []
        self.unknown_keys: Counter = Counter()

    def __len__(self) -> int:
        return len(self.rows)

    def add(self, raw: bytes, line_no: int, offset: int, line_hash: int) -> None:
        pairs = KV_RE.findall(raw)
        issues: List[str] = []
        extra: dict = {}
        # Fast path: a clean ASCII line made only of key=value pairs and single spaces.
        if not raw.isascii() or au.CTRL_RE.search(raw) or _covered(pairs) != len(raw):
            cut = _binary_start(raw)
            if cut is not None:
                # Text that runs into binary data (e.g. a line cut off by a file
                # appended after it): keep the pairs before the first bad byte.
                # Cut back to the last space: bytes between it and the first bad
                # byte belong to the binary data, not to a field.
                space = raw.rfind(b" ", 0, cut)
                cut = space if space > 0 else cut
                pairs = KV_RE.findall(raw[:cut])
                issues.append("truncated_binary_tail")
                extra["_dropped_bytes"] = len(raw) - cut
            rest = KV_RE.sub(b"", raw if cut is None else raw[:cut]).strip(b" ")
            if rest and rest.replace(b" ", b""):
                issues.append("stray_text")
                extra["_stray"] = rest.decode("utf-8", "replace")[:500]
        d = dict(pairs)
        if len(d) != len(pairs):
            issues.append("duplicate_key")
            seen: dict = {}
            for k, v in pairs:
                seen.setdefault(k, []).append(v)
            for k, vs in seen.items():
                if len(vs) > 1:  # the last value wins the column; keep the others
                    extra["_dup_" + k.decode("ascii", "replace")] = [_unq(v) for v in vs[:-1]]
        self.rows.append(tuple(map(d.get, _KEYS)))
        self.meta.append((line_no, offset, line_hash))
        other = d.keys() - _KNOWN
        if other:
            self.unknown_keys.update(k.decode("ascii", "replace") for k in other)
            for k in sorted(other):
                extra[k.decode("ascii", "replace")] = _unq(d[k])
        self.extras.append(extra or None)
        self.issues.append(issues or None)

    def to_table(self, source: str, tq: au.TimeQuality, default_tz: int) -> Tuple[pa.Table, dict]:
        cols = list(zip(*self.rows))
        date, time_, tz, etime = (au.unquote(au.str_array(c)) for c in cols[:4])
        et = au.to_int(etime)
        ts, valid, quality = au.fortigate_time(date, time_, tz, et, default_tz)
        tq.apply(ts, valid, quality)
        lines, offsets, hashes = zip(*self.meta)
        n = len(self.rows)
        arrays = {
            "ts": au.ts_array(ts, valid),
            "ts_quality": au.quality_array(quality),
            "event_time_raw": et,
            "source": pa.array([source] * n, pa.string()),
            "line": pa.array(lines, pa.int64()),
            "byte_offset": pa.array(offsets, pa.int64()),
            "line_hash": pa.array(hashes, pa.int64()),
        }
        for (_, name, kind), values in zip(FIELDS, cols[4:]):
            if kind == "int":
                text = au.unquote(au.str_array(values))
                arrays[name] = au.to_int(text)
                # A number column holding something that is not a number: keep the text.
                for i, v in au.lost_values(text, arrays[name]):
                    self.extras[i] = {**(self.extras[i] or {}), "_bad_" + name: v}
                    self.issues[i] = (self.issues[i] or []) + ["bad_number"]
            else:
                arrays[name] = au.unquote(au.str_array(values))
        for i, iss in enumerate(self.issues):  # 'bad_number' may repeat per column
            if iss and len(iss) != len(set(iss)):
                self.issues[i] = list(dict.fromkeys(iss))
        arrays["parse_issue"] = pa.array([",".join(i) if i else None for i in self.issues], pa.string())
        arrays["extra"] = pa.array([au.dumps(e) if e else None for e in self.extras], pa.string())
        table = pa.table(arrays, schema=SCHEMA)
        info = au.batch_info(ts, valid, quality)
        info["issues"] = dict(Counter(x for i in self.issues if i for x in i))
        return table, info
