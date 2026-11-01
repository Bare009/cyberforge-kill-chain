"""Source field names -> canonical columns: the synonym table, value maps, time and severity formats.

The synonym table is config/schema_synonyms.yaml. Names are compared after `norm()` (lower case, only
letters and digits), so "Source address", "source_address" and "sourceAddress" are one name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from . import canonical as C

ROOT = Path(__file__).resolve().parents[2]
SYNONYMS_YAML = ROOT / "config" / "schema_synonyms.yaml"
MAX_FIELDS_PER_COLUMN = 3
SUFFIX_MIN = 5

_NORM_RE = re.compile(r"[^a-z0-9]")
EXACT = "="          # prefix of synonym keys compared on the lower-cased name with its separators


def norm(name: str) -> str:
    return _NORM_RE.sub("", str(name).lower())


Entry = Tuple[str, Optional[Tuple[str, ...]], bool]     # (normed or exact key, formats, full path only)


@dataclass
class Synonyms:
    columns: Dict[str, List[Entry]]          # column -> entries in priority order
    wrappers: Tuple[str, ...] = ()
    event_type_fields: List[str] = field(default_factory=list)
    value_maps: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    value_maps_by: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    derive: List[Dict[str, Any]] = field(default_factory=list)
    message_patterns: List[Dict[str, Any]] = field(default_factory=list)
    shared: set = field(default_factory=set)       # frozensets of columns that may take the same field


def load_synonyms(path: Path = SYNONYMS_YAML) -> Synonyms:
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    cols: Dict[str, List[Entry]] = {}
    for col, names in (doc.get("columns") or {}).items():
        if col not in C.MAPPABLE:
            raise ValueError(f"{path}: '{col}' is not a canonical column")
        out: List[Entry] = []
        for n in names or []:
            spec = n if isinstance(n, dict) else {"name": n}
            name = str(spec["name"])
            key = EXACT + name.lower() if spec.get("exact") else norm(name)
            out.append((key, tuple(spec.get("formats") or ()) or None, "." in name or bool(spec.get("exact"))))
        cols[col] = out
    vm = {c: {str(k).strip().lower(): v for k, v in (m or {}).items()} for c, m in (doc.get("value_maps") or {}).items()}
    return Synonyms(cols, tuple(doc.get("wrappers") or ()), list(doc.get("event_type_fields") or []), vm,
                    doc.get("value_maps_by") or {}, list(doc.get("derive") or []),
                    list(doc.get("message_patterns") or []),
                    {frozenset(g) for g in (doc.get("shared_fields") or [])})


# ── matching ────────────────────────────────────────────────────────────────

def _suffixes(f: str) -> List[str]:
    parts = [p for p in re.split(r"[.\[\]]", f) if p]
    out = []
    if len(parts) >= 2:
        for k in (2, 1):
            s = norm("".join(parts[-k:]))
            if len(s) >= SUFFIX_MIN:
                out.append(s)
    return out


def match_fields(fields: Sequence[str], fmt: str, syn: Synonyms) -> Dict[str, List[str]]:
    """column -> source fields (list order of the synonym table, at most 3).

    A field is first matched on its full name. Only fields no synonym matches in full are tried on
    their last one or two dotted parts, and only against synonyms without a dot (so "x.hostname" can
    match "hostname" but never "host.name"). An `exact` synonym matches only the same lower-cased name
    with its separators. A field feeds the first column that takes it, except for the shared_fields
    pairs. Fields named parsed.<column> (from a syslog message pattern) map to that column.
    """
    full: Dict[str, List[str]] = {}
    for f in fields:
        full.setdefault(norm(f), []).append(f)
        full.setdefault(EXACT + f.lower(), []).append(f)
    all_names = {n for entries in syn.columns.values() for n, _, _ in entries}
    suffix: Dict[str, List[str]] = {}
    for f in fields:
        if norm(f) in all_names or EXACT + f.lower() in all_names:
            continue
        for s in _suffixes(f):
            suffix.setdefault(s, []).append(f)
    out: Dict[str, List[str]] = {}
    owner: Dict[str, str] = {}          # field -> first column that took it
    for col, entries in syn.columns.items():
        picked: List[str] = []
        usable = [(n, path_only) for n, fmts, path_only in entries if not fmts or fmt in fmts]
        cands = [f for n, _ in usable for f in full.get(n, [])] + \
                [f for n, path_only in usable if not path_only for f in suffix.get(n, [])]   # full names first
        for f in cands:
            if f in picked:
                continue
            o = owner.get(f)
            if o is not None and frozenset((o, col)) not in syn.shared:
                continue
            picked.append(f)
        if picked:
            out[col] = picked[:MAX_FIELDS_PER_COLUMN]
            for f in out[col]:
                owner.setdefault(f, col)
    for f in fields:
        if f.startswith("parsed.") and f[7:] in C.MAPPABLE:
            out.setdefault(f[7:], [])
            if f not in out[f[7:]]:
                out[f[7:]].insert(0, f)
    return out


# ── values ──────────────────────────────────────────────────────────────────

def to_text(v: Any) -> Optional[str]:
    """A record value as column text: lists joined by ',', booleans true/false, '' -> None."""
    if v is None:
        return None
    if isinstance(v, str):
        return v if v.strip() != "" else None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() and abs(v) < 1e18 else repr(v)
    if isinstance(v, (int,)):
        return str(v)
    if isinstance(v, list):
        items = [to_text(x) for x in v]
        items = [x for x in items if x is not None]
        return ",".join(items) if items else None
    if isinstance(v, dict):
        import json

        return json.dumps(v, ensure_ascii=False, default=str) if v else None
    return str(v)


def map_value(col: str, raw: Optional[str], maps: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """One raw value -> canonical text (lower case for the literal columns)."""
    if raw is None:
        return None
    v = raw.strip()
    if col not in maps and col not in C.LITERAL_COLS:
        return v
    key = v.lower()
    m = maps.get(col) or {}
    if key in m:
        return str(m[key])
    if col in ("log_type", "log_subtype") and re.search(r"[./:]", key):
        last = re.split(r"[./:]", key)[-1]     # "firewall.ha" -> "ha"
        return str(m.get(last, last))
    return key if col in C.LITERAL_COLS else v


def canonical_vocab(syn: Synonyms) -> Dict[str, set]:
    """Allowed canonical values per literal column (the targets of the value maps)."""
    out: Dict[str, set] = {}
    for col in C.LITERAL_COLS:
        out[col] = {str(v) for v in (syn.value_maps.get(col) or {}).values()}
    for col, spec in syn.value_maps_by.items():
        for m in (spec.get("maps") or {}).values():
            out.setdefault(col, set()).update(str(v) for v in m.values())
    for d in syn.derive:
        for col, v in (d.get("set") or {}).items():
            if col in out:
                out[col].add(str(v))
    out.setdefault("log_desc", set()).update(["Admin login failed", "Admin login successful"])
    return out


# ── severity ────────────────────────────────────────────────────────────────

SEVERITY_WORDS = {
    "informational": 1, "information": 1, "info": 1, "notice": 1, "debug": 1, "unknown": 1, "none": 1,
    "low": 2, "minor": 2, "warning": 2, "warn": 2,
    "medium": 3, "moderate": 3, "major": 3, "error": 3,
    "high": 4, "severe": 4, "alert": 4,
    "critical": 5, "crit": 5, "emergency": 5, "fatal": 5, "very-high": 5, "veryhigh": 5,
}


def severity_scale(values: Iterable[Optional[str]]) -> Optional[str]:
    """'text' | '1-5' | '0-10' | '0-15' | '0-100', or None when most values fit no scale."""
    vals = [v.strip().lower() for v in values if v is not None and v.strip()]
    if not vals:
        return None
    words = sum(v in SEVERITY_WORDS for v in vals)
    if words / len(vals) >= 0.9:
        return "text"
    nums = []
    for v in vals:
        try:
            nums.append(float(v))
        except ValueError:
            pass
    if len(nums) / len(vals) < 0.9 or min(nums) < 0:
        return None
    hi = max(nums)
    return "1-5" if hi <= 5 else "0-10" if hi <= 10 else "0-15" if hi <= 15 else "0-100" if hi <= 100 else None


def severity_1_5(v: Optional[str], scale: Optional[str]) -> Optional[int]:
    if v is None or scale is None:
        return None
    t = v.strip().lower()
    if t in SEVERITY_WORDS:
        return SEVERITY_WORDS[t]
    try:
        x = float(t)
    except ValueError:
        return None
    if x < 0:
        return None
    if scale == "1-5":
        return int(min(5, max(1, round(x))))
    if scale == "0-10":       # CEF: 0-3 low, 4-6 medium, 7-8 high, 9-10 very high
        return 1 if x < 1 else 2 if x < 4 else 3 if x < 7 else 4 if x < 9 else 5
    if scale == "0-15":       # Wazuh rule.level
        return 1 if x < 4 else 2 if x < 7 else 3 if x < 10 else 4 if x < 13 else 5
    if scale == "0-100":
        return 1 if x < 20 else 2 if x < 40 else 3 if x < 60 else 4 if x < 80 else 5
    return None


# ── time ────────────────────────────────────────────────────────────────────

_EPOCH_RE = re.compile(r"^\d{9,19}(?:\.\d+)?$")
TIME_FORMATS = [
    "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S", "%b %d %Y %H:%M:%S", "%d %b %Y %H:%M:%S", "%Y-%m-%d %H:%M:%S %z",
    "%Y/%m/%d %H:%M:%S %z", "%d/%b/%Y:%H:%M:%S %z", "%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S",
]
MIN_YEAR, MAX_YEAR = 2000, 2100


def epoch_us(t: str) -> Optional[int]:
    """Epoch seconds, ms, µs or ns (by magnitude) -> µs."""
    try:
        x = float(t)
    except ValueError:
        return None
    if x >= 1e17:
        return int(x // 1_000)
    if x >= 1e14:
        return int(x)
    if x >= 1e11:
        return int(x * 1_000)
    if x >= 1e8:
        return int(x * 1_000_000)
    return None


def _year_ok(us: Optional[int]) -> bool:
    if us is None:
        return False
    return MIN_YEAR <= datetime.fromtimestamp(us / 1e6, tz=timezone.utc).year <= MAX_YEAR


def parse_one(t: str, fmt: str) -> Optional[Tuple[int, bool]]:
    """(UTC µs if zoned else naive µs, has zone) for one value in one format, or None."""
    t = t.strip()
    if fmt == "epoch":
        us = epoch_us(t) if _EPOCH_RE.match(t) else None
        return (us, True) if _year_ok(us) else None
    if fmt == "iso":
        s = t[:-1] + "+00:00" if t[-1:] in "Zz" else t
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return int((dt - datetime(1970, 1, 1)).total_seconds() * 1e6), False
        return int(dt.timestamp() * 1e6), True
    if "%Y" not in fmt and "%y" not in fmt:
        return None          # no year: cannot place the event in time without guessing
    try:
        dt = datetime.strptime(t, fmt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return int((dt - datetime(1970, 1, 1)).total_seconds() * 1e6), False
    return int(dt.timestamp() * 1e6), True


def detect_time_format(values: Sequence[Optional[str]], min_share: float = 0.9) -> Tuple[Optional[str], float, bool]:
    """(format, share parsed, zoned) for sample values: 'epoch', 'iso' or a strptime format."""
    vals = [v.strip() for v in values if v is not None and str(v).strip()]
    if not vals:
        return None, 0.0, False
    best: Tuple[Optional[str], float, bool] = (None, 0.0, False)
    for fmt in ["epoch", "iso"] + TIME_FORMATS:
        ok, zoned = 0, 0
        for v in vals:
            r = parse_one(v, fmt)
            if r is not None and (fmt == "epoch" or _year_ok(r[0] if r[1] else r[0])):
                ok += 1
                zoned += r[1]
        share = ok / len(vals)
        if share > best[1]:
            best = (fmt, share, zoned == ok and ok > 0)
        if share >= min_share:
            return fmt, share, zoned == ok and ok > 0
    return best
