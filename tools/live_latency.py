"""Measure live-mode latency on a replayed slice (killchain/live/latency.py).

  python tools/live_latency.py --slice data/live/chainA.log --to data/raw/live-demo.log \
      --run data/runs/live-demo --ip 32.127.48.11 --api http://127.0.0.1:8000 --out latency.json

Live mode (`python -m killchain live --input <--to> --run <--run>`) and, for the API column, the API on
the same run must already be running. The target is truncated first, so live mode resets its window.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from killchain.live.latency import measure  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slice", required=True)
    ap.add_argument("--to", required=True, help="file live mode tails")
    ap.add_argument("--run", required=True, help="live mode's run folder")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--api", help="API base URL, e.g. http://127.0.0.1:8000")
    ap.add_argument("--rate", type=float, default=500)
    ap.add_argument("--step-pause", type=float, default=8.0)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--out", help="write the result as JSON here")
    a = ap.parse_args()
    res = measure(a.slice, a.to, a.run, a.ip, a.api, a.rate, a.step_pause, a.timeout)
    print(f"{'step':>4} {'rule':32s} {'lines':>5} {'pipeline_s':>10} {'api_s':>7} {'pipe_first_s':>12} {'api_first_s':>11}")
    for s in res["steps"]:
        f = (lambda v: "-" if v is None else f"{v:.2f}")
        print(f"{s['n']:>4} {s['rule_id']:32s} {s['lines'] or 0:>5} {f(s['pipeline_s']):>10} {f(s['api_s']):>7} "
              f"{f(s['pipeline_from_first_s']):>12} {f(s['api_from_first_s']):>11}")
    if res["api_error_count"]:
        print(f"API poll errors: {res['api_error_count']} (e.g. {res['api_errors'][0]})")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
        print(f"-> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
