"""python -m killchain.bundle --run <run folder or name> [--parsed DIR] [--check]

Merges every stage's output in a run folder into the files the API serves:
incidents/<n>.json, index.json, alerts.json, unexplained.json, ti.json and
run_summary.json (docs/build-plan.md P11). Threat
intel (enrichment.json) and narrator reports (report.json) are merged in when
present. Nothing is written when any file fails the contract check.

Stage order: chain -> reach -> enrich -> score -> report -> bundle. Rerun
bundle after any of them; it takes about a second.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain.bundle", description=__doc__.split("\n\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="run folder, or a run name in data/runs or examples")
    ap.add_argument("--parsed", help="parsed run folder, for timings and data quality "
                                     "(default data/parsed/<run name> when it exists)")
    ap.add_argument("--check", action="store_true", help="build and check everything, write nothing")
    args = ap.parse_args(argv)

    from killchain.api.bundle import BundleError, resolve_run_dir

    from .build import BundleInputError, run_bundle

    try:
        run_dir = resolve_run_dir(args.run)
        res = run_bundle(run_dir, Path(args.parsed) if args.parsed else None, dry_run=args.check)
    except (BundleError, BundleInputError) as exc:
        print(f"bundle: {exc}", file=sys.stderr)
        return 1

    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    if res.errors:
        print(f"bundle: {len(res.errors)} contract error(s), nothing written:\n  " + "\n  ".join(res.errors[:20]),
              file=sys.stderr)
        return 1
    c, s = res.summary["counts"], res.summary
    ti = s["threat_intel"]
    print(f"{c['incidents']} incidents ({c['critical_incidents']} critical), {c['alerts']} alerts "
          f"({c['alerts_in_incidents']} in incidents, {c['unexplained']} unexplained), {c['steps']} steps, "
          f"{c['evidence_lines']:,} evidence lines")
    print(f"threat intel: {ti['indicators']} indicators, verdicts {ti['verdicts']}" if ti
          else "threat intel: none (run python -m killchain.enrich first to add it)")
    print(f"reports: {s['llm']['reports']} from the narrator, the rest template")
    dq = s["data_quality"]
    if dq:
        print(f"data quality: {dq['events']:,} events, {dq['events_frozen_clock']:,} frozen-clock, "
              f"{dq['junk_bytes'] / 2**20:,.1f} MB junk")
    print(f"{len(res.warnings)} warning(s), 0 contract errors; "
          + ("checked only, nothing written" if args.check else f"-> {run_dir}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
