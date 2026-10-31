"""python -m killchain live --input data/raw/live-demo.log --run data/runs/live-demo

Tails one log file and keeps the run folder's bundle current: every --interval seconds (default 2) the new
lines are parsed into an in-memory window of the last --window-hours of event time (default 72), the rules
that fit the window rerun, and when the alerts changed the incidents are rebuilt and the bundle files
replaced in the same formats the batch run writes, so the API and the pages need nothing else.

Also writes <run>/live/status.json every tick, <run>/live/events.jsonl (one record per publish that
changed something; docs/contracts.md, "Live mode") and <run>/live/checkpoint.json, so a restart resumes.

A run folder that already holds a batch bundle (index.json and no live checkpoint) is refused unless
--overwrite is given. Exit codes: 0 clean stop, 1 rule errors or a fatal error, 2 usage or refused.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    from .settings import LIVE_YAML, ROOT, load_settings

    ap = argparse.ArgumentParser(prog="python -m killchain live", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=os.environ.get("KILLCHAIN_LIVE_INPUT"),
                    help="log file to tail (default: env KILLCHAIN_LIVE_INPUT)")
    ap.add_argument("--run", required=True, help="run folder the bundle is written to")
    ap.add_argument("--interval", type=float, help="seconds between ticks (default from config/live.yaml: 2)")
    ap.add_argument("--window-hours", type=float, help="event-time window kept in memory (default 72)")
    ap.add_argument("--config", default=str(LIVE_YAML), help="live settings (default config/live.yaml)")
    ap.add_argument("--rules", action="append", help="rule folder or file (repeatable; default rules/)")
    ap.add_argument("--assume-tz", default="+00:00", help="zone for timestamps that carry none")
    ap.add_argument("--from-start", action="store_true", help="ignore the checkpoint and read the file from the top")
    ap.add_argument("--overwrite", action="store_true", help="take over a run folder that holds a batch bundle")
    ap.add_argument("--once", action="store_true", help="start, run one tick, stop (for scripts and tests)")
    a = ap.parse_args(argv)
    if not a.input:
        ap.error("give --input <log file> or set KILLCHAIN_LIVE_INPUT")

    from .engine import GuardError, LiveEngine, StartError

    settings = load_settings(a.config)
    if a.interval is not None:
        settings["interval_s"] = a.interval
    if a.window_hours is not None:
        settings["window_hours"] = a.window_hours
    eng = LiveEngine(a.input, a.run, settings, a.rules or [str(ROOT / "rules")], a.assume_tz,
                     a.from_start, a.overwrite)
    try:
        info = eng.start()
    except GuardError as e:
        print(f"live: {e}", file=sys.stderr)
        return 2
    except StartError as e:
        print(f"live: {e}", file=sys.stderr)
        return 1
    print(f"live: {Path(a.input).name} -> {a.run} ({info['mode']} from line {info['backfill_from'][1]}); "
          f"{len(eng.rules)} rules active, {len(eng.skipped)} skipped "
          f"({', '.join(s['id'] for s in eng.skipped)}); every {eng.interval:g} s", flush=True)

    stop = threading.Event()

    def on_signal(signum, frame):  # noqa: ARG001
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, on_signal)
            except (OSError, ValueError):     # not the main thread, or not allowed on this platform
                pass

    def report(res) -> None:
        if res.record:
            rec = res.record
            print(f"live: +{res.new_lines} lines, {rec['counts']['alerts']} alerts, {rec['counts']['incidents']} "
                  f"incidents (new {len(rec['new'])}, changed {len(rec['changed'])}) in {res.timing_ms.get('total')} ms",
                  flush=True)
        if res.error:
            print(f"live: tick failed, retrying next tick: {res.error}", file=sys.stderr, flush=True)

    code = 0
    try:
        if a.once:
            report(eng.tick())
        else:
            eng.run(stop, report)
    except KeyboardInterrupt:
        pass
    except Exception as e:  # noqa: BLE001
        print(f"live: fatal: {type(e).__name__}: {e}", file=sys.stderr)
        code = 1
    finally:
        eng.close("stopped")
    print("live: stopped", flush=True)
    return code
