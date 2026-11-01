"""python -m killchain detect ...

  detect --run data/runs/firex-10G [--parsed data/parsed/firex-10G] [--rules rules] [--only ID ...]
  detect --validate [--rules rules] [--parsed ...|--run ...]

After the rules, records another product already raised (category vendor_alert) become alerts with
layer vendor (detect/vendor.py; --no-llm keeps the LLM out of their labels). Skipped with --only.

Uses the run's prepared events.duckdb when present, else views over --parsed.
--only runs a subset and writes the result to <run>/detect-only/ so the full
alert set is not overwritten while tuning one rule.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

import polars as pl

ROOT = Path(__file__).resolve().parents[2]


class _Peak(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        import psutil

        self.p, self.peak, self.stop = psutil.Process(), 0, threading.Event()

    def run(self):
        while not self.stop.is_set():
            self.peak = max(self.peak, self.p.memory_info().rss)
            self.stop.wait(0.2)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain detect", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", action="append", help="rule folder or file (repeatable; default rules/)")
    ap.add_argument("--run", help="run folder (output; also holds the prepared events.duckdb)")
    ap.add_argument("--parsed", help="parsed run folder, used when the run has no events.duckdb")
    ap.add_argument("--only", nargs="+", help="rule ids to run")
    ap.add_argument("--validate", action="store_true", help="check rule files (and their SQL if data is given), run nothing")
    ap.add_argument("--no-llm", action="store_true", help="vendor alerts: do not ask the LLM to label alert names "
                                                          "the vendor fields and keywords leave unlabelled")
    a = ap.parse_args(argv)
    from .. import db
    from . import engine, vendor
    from .rules import load_rules

    roots = a.rules or [str(ROOT / "rules")]
    rules, errors = load_rules(roots, a.only)
    con = None
    if a.run or a.parsed:
        con = db.connect(a.parsed, a.run)
        for r in rules:
            msg = engine.check_rule(con, r)
            if msg:
                errors.append(msg)
    if errors:
        print("rule errors:\n  " + "\n  ".join(errors), file=sys.stderr)
    if a.validate:
        print(f"{len(rules)} rules loaded, {len(errors)} errors")
        return 1 if errors else 0
    if errors:
        return 1
    if con is None:
        ap.error("give --run (and --parsed if the run is not prepared)")
    run = Path(a.run or ROOT / "data" / "runs" / Path(a.parsed).name)
    out = run / "detect-only" if a.only else run

    peak = _Peak()
    peak.start()
    t0 = time.perf_counter()
    alerts, evidence, per_rule = engine.run_rules(con, rules)
    vstats = None
    if not a.only:
        va, ve, vstats = vendor.run_vendor(con, no_llm=a.no_llm)
        if va.height:
            alerts = pl.concat([alerts, va], how="diagonal_relaxed").sort("ts_start", "rule_id") if alerts.height else va
            evidence = pl.concat([evidence, ve], how="diagonal_relaxed") if evidence.height else ve
    wall = time.perf_counter() - t0
    peak.stop.set()
    layers = {"rule": 0, "anomaly": 0}
    if alerts.height:
        for lay, n in alerts.group_by("layer").len().iter_rows():
            layers[lay] = n
    stats = {"stage": "detect", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20),
             "rules": len(rules), "alerts": alerts.height, "evidence_lines": evidence.height, "layers": layers,
             "per_rule": per_rule}
    if vstats and vstats.get("records"):
        stats["vendor"] = vstats
    bad = engine.write_outputs(out, alerts, evidence, stats)
    w = max([len(r["rule_id"]) for r in per_rule] + [10])
    for r in per_rule:
        print(f"{r['rule_id']:{w}s} {r['layer']:7s} {r['kind']:9s} alerts {r['alerts']:>5}  "
              f"lines {r['evidence_lines']:>7,}  {r['secs']:6.2f} s")
    print(f"\n{alerts.height} alerts, {evidence.height:,} evidence lines from {len(rules)} rules in {wall:.1f} s "
          f"(peak {stats['peak_rss_mb']} MB) -> {out}")
    print(f"rule layer {layers['rule']} alerts, anomaly layer {layers['anomaly']} alerts from "
          f"{sum(r.layer == 'anomaly' for r in rules)} detectors")
    if stats.get("vendor"):
        v = stats["vendor"]
        src = ", ".join(f"{k} {n}" for k, n in v["technique_sources"].items() if n)
        llm = v.get("llm") or {}
        print(f"vendor layer {layers.get('vendor', 0)} alerts from {v['records']:,} vendor alert records "
              f"({v.get('records_without_time', 0)} without a usable time skipped); techniques: {src}"
              + (f"; LLM skipped: {llm['skipped']}" if llm.get("skipped") and llm.get("names") else "")
              + (f"; LLM labelled {llm.get('names', 0)} names ({llm.get('calls', 0)} calls, cached {llm.get('cached')})"
                 if llm.get("names") and not llm.get("skipped") else ""))
    if bad:
        print("contract errors:\n  " + "\n  ".join(bad[:20]), file=sys.stderr)
        return 1
    return 0
