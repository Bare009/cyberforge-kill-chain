"""python -m killchain run --input data/raw/firex-10G.log [--name firex-10G] [--offline] [--no-llm]

Runs parse -> prepare -> detect -> correlate -> chain -> reach -> score -> report -> enrich ->
narrate -> bundle on one log file. Each stage's output is printed with a [stage] prefix and kept in
<run>/logs/<stage>.log. The run's record (per-stage wall time, peak memory, counts, status) is written
to <run>/pipeline.json and under the `pipeline` key of <run>/run_summary.json.

Exit codes: 0 done (maybe with warnings), 1 a required stage failed, 2 usage or input error,
3 the input holds no events.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .pipeline import STAGES, Context, run_pipeline

NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DATA_DIR = Path(__file__).resolve().parents[2] / "data"


def _short(counts: Dict[str, Any], limit: int = 6) -> str:
    parts = []
    for k, v in counts.items():
        if isinstance(v, dict):
            v = "/".join(f"{a}:{b}" for a, b in v.items()) or "-"
        parts.append(f"{k}={v}")
    return ", ".join(parts[:limit])


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain run", description=__doc__.split("\n\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n")[2])
    ap.add_argument("--input", required=True, help="raw log file (FortiGate key=value and/or JSON lines)")
    ap.add_argument("--name", help="run name (default: the input file name without extension)")
    ap.add_argument("--offline", action="store_true", help="no network: enrich uses cache and local context only, "
                                                           "the narrator is skipped")
    ap.add_argument("--no-llm", action="store_true", help="skip the AI narrator; incidents keep template reports")
    ap.add_argument("--reuse-parsed", action="store_true",
                    help="skip parse (and db prepare when events.duckdb is newer) when <data>/parsed/<name> "
                         "was parsed from this same file")
    ap.add_argument("--from", dest="from_stage", choices=STAGES, help="start at this stage; earlier outputs are reused")
    ap.add_argument("--workers", type=int, help="parser worker processes (default: the parser's own)")
    ap.add_argument("--data-dir", default=str(DATA_DIR), help="holds parsed/<name> and runs/<name> (default data)")
    ap.add_argument("--ti-cache", help="threat-intel SQLite cache for enrich (default data/cache/ti.sqlite)")
    a = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    inp = Path(a.input)
    if not inp.is_file():
        print(f"run: not a file: {inp}", file=sys.stderr)
        return 2
    name = a.name or inp.stem
    if not NAME_RE.match(name):
        print(f"run: bad run name {name!r}: use letters, digits, '.', '_' and '-' only", file=sys.stderr)
        return 2

    ctx = Context(input=inp, name=name, data_dir=Path(a.data_dir), offline=a.offline, no_llm=a.no_llm,
                  reuse_parsed=a.reuse_parsed, from_stage=a.from_stage, workers=a.workers,
                  ti_cache=Path(a.ti_cache) if a.ti_cache else None)
    code, rec = run_pipeline(ctx)
    if rec.get("error"):
        print(rec["error"], file=sys.stderr)
    if code == 2:
        return code

    print(f"\n{'stage':10s} {'status':9s} {'secs':>8s} {'peak MB':>8s}  counts")
    for s in rec["stages"]:
        secs = "-" if s["wall_secs"] is None else f"{s['wall_secs']:.1f}"
        mb = "-" if s["peak_rss_mb"] is None else str(s["peak_rss_mb"])
        extra = _short(s["counts"]) if s["counts"] else (s["reason"] or "")
        print(f"{s['name']:10s} {s['status']:9s} {secs:>8s} {mb:>8s}  {extra}")
    print(f"total {rec['wall_secs']} s, peak {rec['peak_rss_mb']} MB, status {rec['status']} (exit {code})")
    for w in rec["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    for n in rec["notes"]:
        print(f"note: {n}")
    run_dir = Path(rec["run_dir"])
    print(f"-> {run_dir / 'run_summary.json'} (pipeline), {run_dir / 'pipeline.json'}")
    return code
