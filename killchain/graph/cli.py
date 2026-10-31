"""python -m killchain chain --run data/runs/firex-10G [N]

Without N: builds the numbered chain, gaps and path graph of every incident from correlate's output and
writes chains.json, incident_lines.parquet, chain/_stats.json and the provisional bundle
(incidents/<n>.json, index.json, alerts.json with incident_number filled). Nothing is written when any
incident fails the contract check. Re-running chain resets reach next to a placeholder until the P8
`reach` stage runs again. Stage order: detect -> correlate -> chain.

With N: prints the text form of incident N from incidents/N.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

INPUTS = {"incidents.parquet": "correlate", "incident_alerts.parquet": "correlate",
          "alerts.parquet": "detect", "alert_evidence.parquet": "detect", "alerts.json": "detect"}


def text_form(inc: Dict[str, Any]) -> str:
    out = [f"#{inc['incident_number']} {inc['incident_id']} sev {inc['severity']} | {inc['title']}",
           f"{inc['ts_start_ist']} to {inc['ts_end_ist']} IST, {inc['merged']['alerts']} alerts, "
           f"{inc['merged']['events']:,} events",
           inc["chain_text"], ""]
    for s in inc["chain"]:
        end = f" (ongoing until {s['ts_end_ist']})" if s["ongoing"] else ""
        out.append(f"{s['n']:>2}. {s['ts_start_ist']} IST{end} {s['technique']} {s['tactic']} "
                   f"{s['src'] or '-'} -> {s['dst'] or '-'} x{s['event_count']}: {s['action']}")
    out.append("")
    out += [f"gap: {g}" for g in inc["gaps"]] or ["gaps: none"]
    out.append(f"reach next: {inc['next']['sentence']}")
    return "\n".join(out)


def _show(run: Path, n: int) -> int:
    p = run / "incidents" / f"{n}.json"
    if not p.exists():
        print(f"chain: {p} not found; run `python -m killchain chain --run {run}` first", file=sys.stderr)
        return 1
    print(text_form(json.loads(p.read_text(encoding="utf-8"))))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain chain", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="run folder holding correlate's output")
    ap.add_argument("number", nargs="?", type=int, help="print this incident's text form instead of building")
    a = ap.parse_args(argv)
    run = Path(a.run)
    if a.number is not None:
        return _show(run, a.number)

    missing = [(n, s) for n, s in INPUTS.items() if not (run / n).exists()]
    if missing:
        stage = "detect" if any(s == "detect" for _, s in missing) else "correlate"
        print(f"chain: {', '.join(n for n, _ in missing)} not found in {run}; run "
              f"`python -m killchain {stage} --run {run}` first", file=sys.stderr)
        return 1
    import polars as pl

    from .. import db
    from ..detect.cli import _Peak
    from . import incident_files as files
    from .chain import build_chains

    peak = _Peak()
    peak.start()
    t0 = time.perf_counter()
    incidents = pl.read_parquet(run / "incidents.parquet")
    members = pl.read_parquet(run / "incident_alerts.parquet")
    alerts = pl.read_parquet(run / "alerts.parquet")
    evidence = pl.read_parquet(run / "alert_evidence.parquet")
    alerts_json = json.loads((run / "alerts.json").read_text(encoding="utf-8"))
    chains, lines = build_chains(incidents, members, alerts, evidence, db.load_network())
    by_id = {c["incident_id"]: c for c in chains}
    bundle = [files.assemble(r, by_id[r["incident_id"]]) for r in incidents.sort("incident_number").iter_rows(named=True)]
    index = files.index_rows(bundle, run.name)
    alerts_out = files.alerts_with_incidents(alerts_json, members)
    errors = files.check(bundle, index, alerts_out)
    wall = time.perf_counter() - t0
    peak.stop.set()
    if errors:
        print(f"chain: {len(errors)} contract error(s), nothing written:\n  " + "\n  ".join(errors[:20]),
              file=sys.stderr)
        return 1
    steps = [s for c in chains for s in c["chain"]]
    stats = {"stage": "chain", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20),
             "incidents": len(chains), "steps": len(steps), "ongoing_steps": sum(s["ongoing"] for s in steps),
             "gaps": sum(len(c["gaps"]) for c in chains), "incident_lines": lines.height,
             "graph_nodes": sum(len(c["graph"]["nodes"]) for c in chains),
             "graph_edges": sum(len(c["graph"]["edges"]) for c in chains), "contract_errors": 0}
    files.write(run, bundle, index, alerts_out, {
        "chains.json": {"run": run.name, "incidents": chains},
        "incident_lines.parquet": lines,
        "chain/_stats.json": stats,
    })
    for c in chains:
        print(f"#{c['incident_number']} {c['chain_text']} | gaps {len(c['gaps'])}")
    print(f"\n{stats['incidents']} incidents, {stats['steps']} steps ({stats['ongoing_steps']} ongoing), "
          f"{stats['gaps']} gaps, {stats['incident_lines']:,} evidence lines, 0 contract errors; "
          f"{wall:.2f} s -> {run}")
    return 0
