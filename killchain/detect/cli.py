"""python -m killchain detect ...

  detect --run data/runs/firex-10G [--parsed data/parsed/firex-10G] [--rules rules] [--only ID ...]
  detect --validate [--rules rules] [--parsed ...|--run ...]

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
    a = ap.parse_args(argv)
    from .. import db
    from . import engine
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
    wall = time.perf_counter() - t0
    peak.stop.set()
    stats = {"stage": "detect", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20),
             "rules": len(rules), "alerts": alerts.height, "evidence_lines": evidence.height, "per_rule": per_rule}
    bad = engine.write_outputs(out, alerts, evidence, stats)
    w = max([len(r["rule_id"]) for r in per_rule] + [10])
    for r in per_rule:
        print(f"{r['rule_id']:{w}s} {r['kind']:9s} alerts {r['alerts']:>5}  lines {r['evidence_lines']:>7,}  {r['secs']:6.2f} s")
    print(f"\n{alerts.height} alerts, {evidence.height:,} evidence lines from {len(rules)} rules in {wall:.1f} s "
          f"(peak {stats['peak_rss_mb']} MB) -> {out}")
    if bad:
        print("contract errors:\n  " + "\n  ".join(bad[:20]), file=sys.stderr)
        return 1
    return 0
