"""Live-mode settings (config/live.yaml) and which rules fit the live window."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

ROOT = Path(__file__).resolve().parents[2]
LIVE_YAML = ROOT / "config" / "live.yaml"
DEFAULTS: Dict[str, Any] = {"interval_s": 2.0, "window_hours": 72, "max_rows": 2_000_000, "max_backfill_mb": 256,
                            "max_line_bytes": 1 << 20, "duckdb": {"memory_limit": "2GB", "threads": 2},
                            "skip_rules": {}}


def load_settings(path: Union[str, Path, None] = None) -> Dict[str, Any]:
    p = Path(path) if path else LIVE_YAML
    d: Dict[str, Any] = {}
    if p.exists():
        with open(p, encoding="utf-8") as f:
            d = yaml.safe_load(f) or {}
    out = {**DEFAULTS, **d}
    out["duckdb"] = {**DEFAULTS["duckdb"], **(d.get("duckdb") or {})}
    out["skip_rules"] = {str(k): str(v) for k, v in (d.get("skip_rules") or {}).items()}
    return out


def rule_span(r: Any) -> Optional[int]:
    """Seconds of history a rule needs at once, or None when it declares no window (match, sql)."""
    if r.kind in ("count", "distinct"):
        return r.window_s
    if r.kind == "sequence":
        return r.within_s
    return None


def select_rules(rules: List[Any], window_s: int, skip: Dict[str, str]
                 ) -> Tuple[List[Any], List[Dict[str, str]], List[str]]:
    """(active rules, skipped [{id, reason}], errors). An unknown id in skip is an error."""
    ids = {r.id for r in rules}
    errors = [f"config/live.yaml skip_rules: no rule {k!r}" for k in sorted(skip) if k not in ids]
    active, skipped = [], []
    for r in rules:
        span = rule_span(r)
        if r.id in skip:
            skipped.append({"id": r.id, "reason": skip[r.id]})
        elif span is not None and span > window_s:
            skipped.append({"id": r.id, "reason": f"window longer than {window_s / 3600:g} h"})
        else:
            active.append(r)
    return active, skipped, errors
