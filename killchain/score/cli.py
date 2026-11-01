"""python -m killchain score --run data/runs/firex-10G [N]

Without N: computes the risk score of every incident (killchain/score/risk.py), numbers the incidents 1..N
by risk (worst first; ties by first time, then incident_id) and rewrites the bundle: incidents/<n>.json,
index.json and alerts.json (incident_number follows the new numbers), plus score.json (old -> new number
and the parts per incident_id) and score/_stats.json. Threat intel comes from <run>/enrichment.json when
present, else that part is 0. Nothing is written when an input is missing, reach has not run, or any
incident fails the contract check. Stage order: detect -> correlate -> chain -> reach -> score -> report.

Only the bundle is renumbered; incidents.parquet, chains.json, reach.json and incident_lines.parquet keep
correlate's numbers (join on incident_id).

With N: prints incident N's risk parts.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .risk import PART_NAMES


class InputError(Exception):
    pass


def load_bundle(run: Path, stage: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(index, incidents in index order, alerts) from the run folder; InputError when something is missing."""
    need = [run / "index.json", run / "alerts.json"]
    missing = [p.name for p in need if not p.exists()]
    if missing:
        raise InputError(f"{stage}: {', '.join(missing)} not found in {run}; run "
                         f"`python -m killchain chain --run {run}` and `reach` first")
    index = json.loads((run / "index.json").read_text(encoding="utf-8"))
    incidents = []
    for row in index.get("incidents") or []:
        p = run / "incidents" / f"{row['incident_number']}.json"
        if not p.exists():
            raise InputError(f"{stage}: {p} not found; run `python -m killchain chain --run {run}` and `reach` first")
        incidents.append(json.loads(p.read_text(encoding="utf-8")))
    alerts = json.loads((run / "alerts.json").read_text(encoding="utf-8"))
    return index, incidents, alerts


def parts_table(inc: Dict[str, Any]) -> str:
    out = [f"#{inc['incident_number']} {inc['incident_id']} | {inc['title']}",
           f"{'part':18s} {'value':>6s} {'weight':>6s} {'points':>6s}  detail"]
    for k, p in inc["risk_parts"].items():
        out.append(f"{PART_NAMES.get(k, k):18s} {p['value']:6.4f} {p['weight']:6.2f} {p['points']:6.2f}  "
                   f"{p.get('detail', '')}")
    out.append(f"{'total':18s} {'':6s} {'':6s} {inc['risk_score']:6.1f}  {inc['risk_band']}")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain score", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="run folder holding reach's bundle")
    ap.add_argument("number", nargs="?", type=int, help="print this incident's risk parts instead of scoring")
    a = ap.parse_args(argv)
    run = Path(a.run)
    if a.number is not None:
        p = run / "incidents" / f"{a.number}.json"
        if not p.exists():
            print(f"score: {p} not found; run `python -m killchain score --run {run}` first", file=sys.stderr)
            return 1
        print(parts_table(json.loads(p.read_text(encoding="utf-8"))))
        return 0

    from .. import db
    from ..detect.cli import _Peak
    from ..graph import incident_files as files
    from .risk import apply_risk, load_enrichment, rank, risk_parts

    try:
        index, incidents, alerts = load_bundle(run, "score")
    except InputError as e:
        print(e, file=sys.stderr)
        return 1
    stale = [i["incident_number"] for i in incidents
             if i["next"].get("sentence") == files.NEXT_PLACEHOLDER["sentence"]]
    if stale:
        print(f"score: reach next is a placeholder in {len(stale)} incident(s) (e.g. #{stale[0]}); run "
              f"`python -m killchain reach --run {run}` first", file=sys.stderr)
        return 1

    peak = _Peak()
    peak.start()
    t0 = time.perf_counter()
    net = db.run_network(run)
    enrichment = load_enrichment(run)
    before = {i["incident_id"]: int(i["incident_number"]) for i in incidents}
    for inc in incidents:
        apply_risk(inc, risk_parts(inc, net, enrichment))
    ranked, mapping = rank(incidents)
    alerts_out = [{**x, "incident_number": mapping.get(x["incident_number"]) if x.get("incident_number") is not None
                   else None} for x in alerts]
    old_rows = {r["incident_id"]: r for r in index.get("incidents") or []}
    new_index = files.index_rows(ranked, index.get("run") or run.name)
    for r in new_index["incidents"]:                 # keep the verdicts a bundle step may have filled
        o = old_rows.get(r["incident_id"]) or {}
        r["triage_verdict"], r["ti_verdict"] = o.get("triage_verdict"), o.get("ti_verdict")
    for k, v in index.items():
        if k not in new_index:
            new_index[k] = v
    errors = files.check(ranked, new_index, alerts_out)
    wall = time.perf_counter() - t0
    peak.stop.set()
    if errors:
        print(f"score: {len(errors)} contract error(s), nothing written:\n  " + "\n  ".join(errors[:20]),
              file=sys.stderr)
        return 1
    bands = {b: sum(i["risk_band"] == b for i in ranked) for b in ("critical", "high", "medium", "low")}
    ti_source = "enrichment.json" if enrichment is not None else None
    offline = bool(enrichment.get("offline")) if enrichment is not None else None
    stats = {"stage": "score", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20),
             "incidents": len(ranked), "bands": bands, "threat_intel_source": ti_source, "contract_errors": 0}
    score_doc = {"run": new_index["run"], "threat_intel_source": ti_source, "offline": offline,
                 "incidents": [{"incident_id": i["incident_id"], "number_before": before[i["incident_id"]],
                                "incident_number": i["incident_number"], "risk_score": i["risk_score"],
                                "risk_band": i["risk_band"], "risk_parts": i["risk_parts"]} for i in ranked]}
    files.write(run, ranked, new_index, alerts_out, {"score.json": score_doc, "score/_stats.json": stats})
    for i in ranked:
        print(f"#{i['incident_number']} {i['risk_score']:5.1f} {i['risk_band']:8s} {i['title']}")
    moved = sum(before[i["incident_id"]] != i["incident_number"] for i in ranked)
    print(f"\n{len(ranked)} incidents scored ({', '.join(f'{k} {v}' for k, v in bands.items())}), {moved} renumbered; "
          f"threat intel from {ti_source or 'nothing (enrichment.json not found; that part is 0)'}; "
          f"0 contract errors; {wall:.2f} s -> {run}")
    return 0
