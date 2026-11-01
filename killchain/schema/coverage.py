"""Which rules can run on a mapped file: each rule's columns, read from its YAML text.

Required columns come from where / group_by / field / sql / steps (string literals removed first, so a
compared value is never taken for a column); entity columns are optional (an alert still fires
without them). Derived columns of db.py count as the parser column they come from (src_internal ->
src_ip, ist_hour -> ts ...). A rule can run when every required column has some coverage.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import yaml

from . import canonical as C

ROOT = Path(__file__).resolve().parents[2]
RULE_DIRS = [ROOT / "rules" / d for d in ("firewall", "anomaly", "windows", "endpoint", "auth")]
_STR_RE = re.compile(r"'(?:[^']|'')*'")
_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
KNOWN = set(C.OUTPUT_COLUMNS) | {"ts"}


def columns_in(text: str) -> List[str]:
    out: List[str] = []
    for name in _ID_RE.findall(_STR_RE.sub("''", text or "")):
        col = C.DERIVED.get(name, name)
        if col in KNOWN and col not in out:
            out.append(col)
    return out


def _texts(v: Any) -> Iterable[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [t for x in v for t in _texts(x)]
    if isinstance(v, dict):
        return [t for x in v.values() for t in _texts(x)]
    return [str(v)]


def rule_requirements(dirs: Sequence[Path] = RULE_DIRS) -> List[Dict[str, Any]]:
    out = []
    for d in dirs:
        for p in sorted(Path(d).glob("*.y*ml")):
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if not isinstance(doc, dict) or "id" not in doc:
                continue
            req_text = list(_texts(doc.get("where"))) + list(_texts(doc.get("group_by"))) + \
                list(_texts(doc.get("field"))) + list(_texts(doc.get("sql"))) + \
                [t for s in doc.get("steps") or [] for t in _texts((s or {}).get("where"))]
            required = columns_in("\n".join(req_text))
            if doc.get("kind") in ("count", "distinct", "match", "sequence") and "ts" not in required:
                required.append("ts")          # windows, gaps and sequences need event time
            optional = [c for c in columns_in("\n".join(_texts(doc.get("entities")))) if c not in required]
            any_of = [[C.DERIVED.get(c, c) for c in g] for g in doc.get("requires_any") or [] if isinstance(g, list)]
            if any_of:      # alternatives (event_id OR status ...): ts still needed by windowed kinds
                any_of = [g + (["ts"] if "ts" in required and "ts" not in g else []) for g in any_of]
                required = list(dict.fromkeys(c for g in any_of for c in g))
            out.append({"id": doc["id"], "layer": doc.get("layer", "rule"), "path": str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p),
                        "table": doc.get("table", "events"), "required": required, "optional": optional,
                        **({"requires_any": any_of} if any_of else {})})
    return out


def available_columns(mapped: Iterable[str], derive: Sequence[Dict[str, Any]], coverage: Dict[str, float]) -> set:
    """Columns a parse can fill: mapped ones, ones with sample coverage, and ones a derive rule sets
    from available columns (log_desc 'Admin login failed' from a mapped login status ...)."""
    have = set(mapped) | {c for c, v in coverage.items() if (v or 0) > 0}
    if "dns_query" in have:
        have |= {"hostname", "log_subtype"}
    changed = True
    while changed:
        changed = False
        for d in derive or []:
            if all(c in have for c in (d.get("when") or {})):
                new = set(d.get("set") or {}) | {k for k, v in (d.get("copy") or {}).items() if v in have}
                if new - have:
                    have |= new
                    changed = True
    return have


def rule_report(reqs: List[Dict[str, Any]], available: set) -> Dict[str, Any]:
    run, skip = [], []
    for r in reqs:
        missing = [c for c in r["required"] if c not in available]
        if r.get("requires_any"):
            # the rule's `requires_any`: it can run when every column of one group is available
            gaps = [[c for c in g if c not in available] for g in r["requires_any"]]
            missing = [] if any(not g for g in gaps) else min(gaps, key=len)
        opt_missing = [c for c in r["optional"] if c not in available]
        item = {"id": r["id"], "layer": r["layer"], "required": r["required"]}
        if missing:
            skip.append({**item, "missing": missing})
        else:
            run.append({**item, "optional_missing": opt_missing})
    return {"can_run": run, "skipped": skip, "counts": {"can_run": len(run), "skipped": len(skip)}}
