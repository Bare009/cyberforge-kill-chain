"""Checks a proposed field -> column mapping on the sample. A field that fails is dropped and reported.

Rules (MIN_SHARE of the non-empty sample values must pass):
  IP columns        parse as an IPv4/IPv6 address
  ports             integers 0-65535 (after the value map)
  bytes, packets,
  duration          non-negative integers
  other int columns integers (proto after tcp/udp -> 6/17)
  vendor_severity   a known word or a number on a 1-5 / 0-10 / 0-15 / 0-100 scale
  alert_confidence  a number 0-1 or 0-100
  ts                one time format (epoch s/ms/µs/ns, ISO 8601, or a strptime format) in 2000-2100
Text columns are not checked.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import canonical as C
from .mapping import detect_time_format, map_value, severity_scale

MIN_SHARE = 0.9
_INT_MAX = 2**63


def _int(v: str) -> Optional[int]:
    t = v.strip()
    if not t or not (t.isdigit() or (t[0] == "-" and t[1:].isdigit())):
        return None
    x = int(t)
    return x if -_INT_MAX <= x < _INT_MAX else None


def _ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.strip())
        return True
    except ValueError:
        return False


def check(col: str, values: Sequence[Optional[str]], value_maps: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """{'ok', 'share', 'n', 'rule', 'bad_examples'[, 'format' | 'scale']} for one field's sample values."""
    vals = [v for v in values if v is not None and str(v).strip() not in ("", "-")]
    res: Dict[str, Any] = {"n": len(vals), "rule": None, "ok": True, "share": 1.0, "bad_examples": []}
    if not vals:
        return res

    def score(rule: str, test) -> Dict[str, Any]:
        good = [test(v) for v in vals]
        share = sum(good) / len(vals)
        bad = list(dict.fromkeys(str(v)[:60] for v, g in zip(vals, good) if not g))[:3]
        res.update(rule=rule, share=round(share, 4), ok=share >= MIN_SHARE, bad_examples=bad)
        return res

    if col in C.IP_COLS:
        return score("ip address", _ip)
    if col in C.PORT_COLS:
        return score("port 0-65535", lambda v: (lambda x: x is not None and 0 <= x <= 65535)(_int(map_value(col, v, value_maps) or "")))
    if col in C.COUNT_COLS:
        return score("non-negative integer", lambda v: (lambda x: x is not None and x >= 0)(_int(v)))
    if col == "vendor_severity":
        scale = severity_scale(vals)
        res.update(rule="severity scale", scale=scale, ok=scale is not None, share=1.0 if scale else 0.0,
                   bad_examples=[] if scale else list(dict.fromkeys(vals))[:3])
        return res
    if col == "alert_confidence":
        def conf(v: str) -> bool:
            try:
                x = float(v)
            except ValueError:
                return False
            return 0 <= x <= 100
        return score("number 0-1 or 0-100", conf)
    if col in C.INT_COLS:
        return score("integer", lambda v: _int(map_value(col, v, value_maps) or "") is not None)
    if col == "ts":
        fmt, share, zoned = detect_time_format(vals, MIN_SHARE)
        res.update(rule="time", format=fmt, zoned=zoned, share=round(share, 4), ok=fmt is not None and share >= MIN_SHARE,
                   bad_examples=[] if share >= MIN_SHARE else list(dict.fromkeys(vals))[:3])
        return res
    return res


def validate_columns(columns: Dict[str, List[str]], sample: Sequence[Dict[str, Any]], value_maps: Dict[str, Dict[str, Any]],
                     to_text) -> Tuple[Dict[str, List[str]], List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """(kept columns, dropped [{column, field, reason, share, bad_examples}], checks {column: {field: result}})."""
    kept: Dict[str, List[str]] = {}
    dropped: List[Dict[str, Any]] = []
    checks: Dict[str, Dict[str, Any]] = {}
    for col, fields in columns.items():
        ok_fields = []
        for f in fields:
            r = check(col, [to_text(rec.get(f)) for rec in sample], value_maps)
            checks.setdefault(col, {})[f] = r
            if r["ok"]:
                ok_fields.append(f)
            else:
                dropped.append({"column": col, "field": f, "reason": f"{r['rule']}: {r['share']:.0%} of {r['n']} values pass",
                                "share": r["share"], "bad_examples": r["bad_examples"]})
        if ok_fields:
            kept[col] = ok_fields
    return kept, dropped, checks
