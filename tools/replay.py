"""Replay a saved log slice into a file that `python -m killchain live` tails.

  python tools/replay.py slice --raw data/raw/firex-10G.log --run data/runs/firex-10G \
      --ip 32.127.48.11 --out data/live/chainA.log
  python tools/replay.py play --slice data/live/chainA.log --to data/raw/live-demo.log --rate 500 --step-pause 6

`slice` cuts the attacker's rule-alert lines (one step per alert) plus a background sample out of a batch
run and writes <out>.meta.json with each step's line range. `play` appends the slice at --rate lines per
second, pausing --step-pause seconds before each step, so the incident appears and grows step by step.
It truncates the target first unless --append is given (live mode then resets its window).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from killchain.live import replay  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("slice", help="cut a slice around one attacker from a batch run")
    s.add_argument("--raw", required=True, help="the raw log the run was parsed from")
    s.add_argument("--run", required=True, help="batch run folder (alerts.json, alert_evidence.parquet, events.duckdb)")
    s.add_argument("--ip", required=True, help="attacker (or victim) IP whose rule alerts become the steps")
    s.add_argument("--out", required=True, help="slice file to write (plus <out>.meta.json)")
    s.add_argument("--background", type=int, default=2000, help="background lines sampled from the same span")
    s.add_argument("--seed", type=int, default=42)
    p = sub.add_parser("play", help="append a slice to the file live mode tails")
    p.add_argument("--slice", required=True)
    p.add_argument("--to", required=True, help="target file (live mode's --input)")
    p.add_argument("--rate", type=float, default=500, help="lines per second")
    p.add_argument("--step-pause", type=float, default=6.0, help="seconds to wait before each step after the first")
    p.add_argument("--append", action="store_true", help="append instead of truncating the target first")
    p.add_argument("--marks", help="write the per-step write times to this JSON file")
    a = ap.parse_args()
    if a.cmd == "slice":
        meta = replay.make_slice(a.raw, a.run, a.ip, a.out, a.background, a.seed)
        print(f"{meta['lines']} lines ({meta['background']} background) -> {a.out}")
        for st in meta["steps"]:
            print(f"  step {st['n']} {st['rule_id']}: slice lines {st['first']}-{st['last']} ({st['count']} lines)")
        return 0
    marks = replay.play(a.slice, a.to, rate=a.rate, step_pause=a.step_pause, truncate=not a.append,
                        on_step=lambda k: print(f"step {k} written", flush=True))
    if a.marks:
        Path(a.marks).write_text(json.dumps(marks, indent=1), encoding="utf-8")
    print(f"played {a.slice} -> {a.to}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
