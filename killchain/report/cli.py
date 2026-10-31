"""python -m killchain report --run data/runs/firex-10G [N]

Without N: renders the template report (killchain/report/template.py) of every incident into its
`report` ({source: template, markdown, triage: null}) and `report_source`, and rewrites incidents/<n>.json
with the same index.json and alerts.json, plus report/_stats.json. Threat intel comes from
<run>/enrichment.json when present. Needs score.json (run score first); nothing is written when any
incident fails the contract check. Stage order: ... -> reach -> score -> report.

With N: prints incident N's report markdown.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain report", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="run folder holding score's bundle")
    ap.add_argument("number", nargs="?", type=int, help="print this incident's report instead of building")
    a = ap.parse_args(argv)
    run = Path(a.run)
    if a.number is not None:
        p = run / "incidents" / f"{a.number}.json"
        if not p.exists():
            print(f"report: {p} not found; run `python -m killchain report --run {run}` first", file=sys.stderr)
            return 1
        print(json.loads(p.read_text(encoding="utf-8"))["report"]["markdown"], end="")
        return 0

    if not (run / "score.json").exists():
        print(f"report: score.json not found in {run}; run `python -m killchain score --run {run}` first",
              file=sys.stderr)
        return 1
    from ..detect.cli import _Peak
    from ..graph import incident_files as files
    from ..score.cli import InputError, load_bundle
    from ..score.risk import load_enrichment
    from .template import report_for

    try:
        index, incidents, alerts = load_bundle(run, "report")
    except InputError as e:
        print(e, file=sys.stderr)
        return 1
    peak = _Peak()
    peak.start()
    t0 = time.perf_counter()
    enrichment = load_enrichment(run)
    for inc in incidents:
        inc["report"] = report_for(inc, enrichment)
        inc["report_source"] = "template"
    errors = files.check(incidents, index, alerts)
    wall = time.perf_counter() - t0
    peak.stop.set()
    if errors:
        print(f"report: {len(errors)} contract error(s), nothing written:\n  " + "\n  ".join(errors[:20]),
              file=sys.stderr)
        return 1
    chars = sum(len(i["report"]["markdown"]) for i in incidents)
    stats = {"stage": "report", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20),
             "incidents": len(incidents), "markdown_chars": chars,
             "threat_intel_source": "enrichment.json" if enrichment is not None else None, "contract_errors": 0}
    files.write(run, incidents, index, alerts, {"report/_stats.json": stats})
    for i in incidents:
        print(f"#{i['incident_number']} {len(i['report']['markdown']):,} chars | {i['title']}")
    print(f"\n{len(incidents)} template reports, {chars:,} characters, 0 contract errors; {wall:.2f} s -> {run}")
    return 0
