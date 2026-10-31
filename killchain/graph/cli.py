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


# ── reach (P8) ───────────────────────────────────────────────────────────────

REACH_DOC = """python -m killchain reach --run data/runs/firex-10G [N] [--parsed DIR] [--force]

Without N: builds the access graph once per run (access_graph.parquet, access_hosts.parquet; reused when
present, --force rebuilds them) from <run>/events.duckdb or the --parsed folder, computes reach next for
every incident and writes reach.json, reach/_stats.json and the provisional bundle with the real `next` and
the path graph merged with reach nodes and edges. Nothing is written when any incident fails the contract
check. Stage order: detect -> correlate -> chain -> reach; re-running `chain` resets reach next to a
placeholder until `reach` runs again.

With N: prints incident N's reach list and sentence from incidents/N.json.
"""
REACH_INPUTS = {"chains.json": "chain", "incident_lines.parquet": "chain", "incidents.parquet": "correlate",
                "incident_alerts.parquet": "correlate", "alerts.json": "detect"}


def reach_text(inc: Dict[str, Any]) -> str:
    nxt = inc["next"]
    out = [f"#{inc['incident_number']} {inc['incident_id']} | {inc['title']}", nxt["sentence"], ""]
    for i, r in enumerate(nxt["reachable"], 1):
        via = "; ".join(f"{v['from']} {v['edge']}" + (f" x{v['count']}" if v["count"] else "") for v in r["via"])
        out.append(f"{i:>2}. {r['host']} zone {r['zone']} hop {r['hop']} {r['kind']} via {via}")
    if not nxt["reachable"]:
        out.append("reachable: none")
    out.append(f"likely next tactics: {', '.join(nxt['likely_tactics']) or 'none'}")
    return "\n".join(out)


def compute_reach(run: Path, con: Any, edges: Any, hosts: Any, net: Dict[str, Any], settings: Dict[str, Any]):
    """(bundle incidents, reach.json rows, index, alerts) with reach next, from chain's and correlate's output.
    One join of incident_lines to events on (source, line) gives every evidence line's src, dst, user and
    log_desc for footholds and the touched set."""
    import polars as pl

    from . import incident_files as files
    from .reach import access_digraph, reach_next

    incidents = pl.read_parquet(run / "incidents.parquet")
    members = pl.read_parquet(run / "incident_alerts.parquet")
    chains = json.loads((run / "chains.json").read_text(encoding="utf-8"))["incidents"]
    alerts_json = json.loads((run / "alerts.json").read_text(encoding="utf-8"))
    il = pl.read_parquet(run / "incident_lines.parquet").select("incident_number", "source", "line").unique()
    con.register("incident_lines_v", il)
    joined = con.sql("SELECT DISTINCT il.incident_number, e.src_ip, e.dst_ip, e.user, e.log_desc "
                     "FROM incident_lines_v il JOIN events e ON e.source = il.source AND e.line = il.line").pl()
    con.unregister("incident_lines_v")
    rows_by: Dict[int, List[Dict[str, Any]]] = {}
    for r in joined.iter_rows(named=True):
        rows_by.setdefault(int(r["incident_number"]), []).append(r)

    g = access_digraph(edges)
    by_id = {c["incident_id"]: c for c in chains}
    bundle, reach_rows = [], []
    for r in incidents.sort("incident_number").iter_rows(named=True):
        c = by_id[r["incident_id"]]
        base = files.assemble(r, c)
        nxt, graph, fh = reach_next(base, c["graph"], g, hosts, rows_by.get(base["incident_number"], []), net, settings)
        bundle.append(files.assemble(r, {**c, "graph": graph}, nxt))
        reach_rows.append({"incident_id": r["incident_id"], "incident_number": base["incident_number"],
                           "footholds": fh, "next": nxt, "graph": graph})
    index = files.index_rows(bundle, run.name)
    alerts_out = files.alerts_with_incidents(alerts_json, members)
    return bundle, reach_rows, index, alerts_out


def reach_main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain reach", description=REACH_DOC,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="run folder holding chain's output")
    ap.add_argument("number", nargs="?", type=int, help="print this incident's reach next instead of building")
    ap.add_argument("--parsed", help="parsed run folder, used when <run>/events.duckdb is missing")
    ap.add_argument("--force", action="store_true", help="rebuild access_graph.parquet and access_hosts.parquet")
    a = ap.parse_args(argv)
    run = Path(a.run)
    if a.number is not None:
        p = run / "incidents" / f"{a.number}.json"
        if not p.exists():
            print(f"reach: {p} not found; run `python -m killchain reach --run {run}` first", file=sys.stderr)
            return 1
        print(reach_text(json.loads(p.read_text(encoding="utf-8"))))
        return 0

    order = ("detect", "correlate", "chain")
    missing = [(n, s) for n, s in REACH_INPUTS.items() if not (run / n).exists()]
    if missing:
        stage = min((s for _, s in missing), key=order.index)
        print(f"reach: {', '.join(n for n, _ in missing)} not found in {run}; run "
              f"`python -m killchain {stage}` first (--run {run})", file=sys.stderr)
        return 1
    from .. import db
    if not (run / db.PREPARED_NAME).exists() and not a.parsed:
        print(f"reach: no {db.PREPARED_NAME} in {run}; give --parsed <folder> or run "
              f"`python -m killchain db --prepare --parsed <folder> --run {run}`", file=sys.stderr)
        return 1
    import polars as pl

    from ..detect.cli import _Peak
    from . import access
    from . import incident_files as files

    peak = _Peak()
    peak.start()
    t0 = time.perf_counter()
    settings = access.load_settings()
    net = db.load_network()
    con = db.connect(a.parsed, run)
    ag, ah = run / "access_graph.parquet", run / "access_hosts.parquet"
    rebuilt = a.force or not (ag.exists() and ah.exists())
    if rebuilt:
        edges, hosts = access.build_access(con, settings)
    else:
        edges, hosts = pl.read_parquet(ag), pl.read_parquet(ah)
    access_secs = time.perf_counter() - t0

    bundle, reach_rows, index, alerts_out = compute_reach(run, con, edges, hosts, net, settings)
    con.close()
    errors = files.check(bundle, index, alerts_out)
    wall = time.perf_counter() - t0
    peak.stop.set()
    if errors:
        print(f"reach: {len(errors)} contract error(s), nothing written:\n  " + "\n  ".join(errors[:20]),
              file=sys.stderr)
        return 1
    with_reach = sum(bool(x["next"]["reachable"]) for x in reach_rows)
    stats = {"stage": "reach", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20),
             "access_secs": round(access_secs, 2), "access_rebuilt": bool(rebuilt),
             "edges_by_kind": dict(sorted(edges.group_by("kind").len().iter_rows())) if edges.height else {},
             "access_sessions": int(edges["count"].sum()) if edges.height else 0,
             "hosts": hosts.height, "hosts_by_zone": dict(sorted(hosts.group_by("zone").len().iter_rows())),
             "incidents": len(reach_rows), "incidents_with_reach": with_reach,
             "incidents_empty": len(reach_rows) - with_reach,
             "reachable": sum(len(x["next"]["reachable"]) for x in reach_rows), "contract_errors": 0}
    extra: Dict[str, Any] = {"reach.json": {"run": run.name, "incidents": reach_rows}, "reach/_stats.json": stats}
    if rebuilt:
        extra.update({"access_graph.parquet": edges, "access_hosts.parquet": hosts})
    files.write(run, bundle, index, alerts_out, extra)
    for x in reach_rows:
        n = x["next"]
        top = n["reachable"][0]["host"] if n["reachable"] else "-"
        print(f"#{x['incident_number']} reach {len(n['reachable'])} top {top} | {n['sentence']}")
    print(f"\naccess graph {stats['edges_by_kind']} ({'built' if rebuilt else 'reused'} in {access_secs:.2f} s), "
          f"{hosts.height:,} internal hosts; {with_reach} incidents with reach, {stats['incidents_empty']} with a "
          f"stated reason, 0 contract errors; {wall:.2f} s -> {run}")
    return 0
