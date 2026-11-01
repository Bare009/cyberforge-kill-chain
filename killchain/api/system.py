"""Evaluation and System endpoints (docs/build-plan.md P11, day 6).

GET /metrics   metrics.json from `python -m killchain eval score`, with the PRD's Good and
               Great targets for each of the seven metrics; `available: false` until eval ran
GET /system    pipeline stages with time and memory, data quality, threat-intel and LLM
               status, raw-log availability, the run's files and the API itself
"""

from __future__ import annotations

import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Request

router = APIRouter()
STARTED = time.time()

METRIC_INFO = {
    "detection_recall": ("Detection recall", "share", "planted attack lines covered by an alert"),
    "label_accuracy": ("Label accuracy", "share", "covered lines with the right ATT&CK technique (exact, parent or accepted alternate)"),
    "attack_path_rebuilt": ("Attack paths rebuilt", "share", "planted incidents found as one incident with every step, in order"),
    "false_alarm_share": ("False alarms", "share", "our incidents with no planted lines (minus those reviewed as real)"),
    "processing_secs": ("Processing time", "seconds", "sum of every stage's wall time"),
    "peak_rss_mb": ("Peak memory", "MB", "largest peak memory of any stage"),
    "open_time_p95_ms": ("Investigation speed", "ms", "p95 of GET /incidents/{n}/path"),
}


def _mtime(p: Path) -> str | None:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return None


def metrics_view(b: Any) -> Dict[str, Any]:
    m = b.metrics
    if not m:
        return {"available": False, "run": b.run,
                "hint": f"Run `python -m killchain eval score --run {b.run_dir}` (add --api http://localhost:8000 "
                        "to measure open times) to write metrics.json."}
    from killchain.eval.score import TARGETS

    targets = {}
    for k, (good, great, higher) in TARGETS.items():
        label, unit, meaning = METRIC_INFO.get(k, (k, "", ""))
        targets[k] = {"label": label, "unit": unit, "meaning": meaning, "good": good, "great": great,
                      "higher_is_better": higher}
    return {"available": True, "run": b.run, "generated_at": _mtime(b.run_dir / "metrics.json"),
            "truth": m.get("truth"), "targets": targets, **{k: m.get(k) for k in
            ("metrics", "grades", "detail", "per_incident", "per_class", "paths", "per_rule")}}


@router.get("/metrics", tags=["system"])
def get_metrics(request: Request) -> Dict[str, Any]:
    """The evaluation result (metrics.json) with the PRD targets."""
    return metrics_view(request.app.state.bundle)


def _versions() -> Dict[str, str]:
    """Package versions from their metadata (no imports, so the first /system call stays fast)."""
    from importlib.metadata import PackageNotFoundError, version

    out = {"python": platform.python_version()}
    for name in ("fastapi", "duckdb", "polars", "pyarrow", "openai", "httpx"):
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            continue
    return out


def run_files(run_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not run_dir.is_dir():              # no run loaded (--run none)
        return rows
    for p in sorted(run_dir.iterdir()):
        if p.name.endswith(".tmp"):
            continue
        if p.is_dir():
            files = [f for f in p.rglob("*") if f.is_file()]
            rows.append({"name": p.name + "/", "files": len(files), "bytes": sum(f.stat().st_size for f in files),
                         "modified": max((_mtime(f) or "" for f in files), default=None) or None})
        else:
            rows.append({"name": p.name, "files": 1, "bytes": p.stat().st_size, "modified": _mtime(p)})
    return rows


@router.get("/system", tags=["system"])
def get_system(request: Request) -> Dict[str, Any]:
    """Everything the System page shows: stages, data quality, TI and LLM status, raw logs, files, API."""
    from .app import llm_status

    st = request.app.state
    b = st.bundle
    rs = b.run_summary or {}
    sources = sorted({ln.get("source") for inc in b.incidents.values() for s in inc.get("chain") or []
                      for ln in s.get("line_sample") or [] if ln.get("source")})
    raw = st.evidence.raw
    live = st.live
    return {
        "run": b.run,
        "run_dir": None if b.empty else str(b.run_dir),
        "sample": b.sample,
        "empty": b.empty,
        "bundled_at": rs.get("bundled_at"),
        "stages": rs.get("stages") or {},
        "totals": rs.get("totals") or {},
        "counts": rs.get("counts") or {"incidents": len(b.incidents), "alerts": len(b.alerts)},
        "warnings": rs.get("warnings") or [],
        "contract_errors": b.errors[:50],
        "contract_error_count": len(b.errors),
        "data_quality": rs.get("data_quality"),
        "threat_intel": st.ti.status(),
        "llm": llm_status(b, st.llm_cache),
        "evidence": {"origin": st.evidence.origin, "raw_dir": str(raw.raw_dir),
                     "logs": [{"source": s, "available": raw.available(s)} for s in sources]},
        "rules_dir": str(st.rules.root),
        "rule_test_sandbox": st.agents.sandbox.available,
        "files": run_files(b.run_dir),
        "api": {"started_at": datetime.fromtimestamp(STARTED, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "uptime_s": round(time.time() - STARTED), "loaded_at": live.loaded_at, "reloads": live.reloads,
                "watching": live.watching, "versions": _versions(), "platform": platform.platform(terse=True)},
    }
