"""python -m killchain eval ...

  eval silver --parsed data/parsed/firex-10G [--run data/runs/firex-10G]
      build the silver truth from eval/silver_truth.yaml, check every step's
      line count, write truth.parquet into the run folder
  eval score --run data/runs/firex-10G [--parsed ...] [--manifest FILE --raw FILE] [--api URL]
      score a run against the silver truth (default) or an organisers' manifest;
      writes metrics.json into the run folder and prints the table
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import score as sc
from . import truth as tr

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "eval" / "silver_truth.yaml"
REVIEWED = ROOT / "eval" / "reviewed.yml"


def _silver(parsed: str, spec: Path, run: Optional[Path] = None):
    """Uses the run's prepared events.duckdb when present (seconds), else views over parsed (minutes)."""
    from .. import db

    con = db.connect(parsed, run)
    return tr.build_silver(con, tr.load_silver_spec(spec))


def cmd_silver(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain eval silver")
    ap.add_argument("--parsed", required=True)
    ap.add_argument("--run", help="write truth.parquet here (default data/runs/<parsed name>)")
    ap.add_argument("--spec", default=str(SPEC))
    a = ap.parse_args(argv)
    t0 = time.perf_counter()
    run = Path(a.run or ROOT / "data" / "runs" / Path(a.parsed).name)
    run.mkdir(parents=True, exist_ok=True)
    truth, checks = _silver(a.parsed, Path(a.spec), run)
    truth.write_parquet(run / "truth.parquet")
    bad = [c for c in checks if not c["ok"]]
    for c in checks:
        mark = "ok " if c["ok"] else "BAD"
        print(f"{mark} #{c['incident_id']:>2} {c['incident_name']:34s} step {c['step_n']} "
              f"{c['step_name'][:40]:40s} expect {c['expect']:>5} got {c['got']:>5}")
    dup = truth.group_by("source", "line").len().filter(truth.group_by("source", "line").len()["len"] > 1).height
    print(f"\n{truth.height:,} truth lines in {truth['incident_id'].n_unique()} incidents; "
          f"{len(bad)} step counts off; {dup} lines in more than one step; {time.perf_counter() - t0:.1f} s")
    print(f"wrote {run / 'truth.parquet'}")
    return 1 if bad else 0


def cmd_score(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain eval score")
    ap.add_argument("--run", required=True, help="run folder with alerts.parquet, alert_evidence.parquet, incidents/")
    ap.add_argument("--parsed", help="parsed run, used to build the silver truth if truth.parquet is absent")
    ap.add_argument("--manifest", help="score against an organisers' manifest instead of the silver truth")
    ap.add_argument("--raw", action="append", default=[], help="stream=path of a raw log for --manifest, e.g. firewall=data/raw/x.log")
    ap.add_argument("--api", help="API base URL, to measure GET /incidents/{n}/path times")
    ap.add_argument("--reviewed", default=str(REVIEWED))
    ap.add_argument("--json", action="store_true", help="print metrics.json instead of the table")
    a = ap.parse_args(argv)
    run = Path(a.run)
    run.mkdir(parents=True, exist_ok=True)

    if a.manifest:
        sources = dict(r.split("=", 1) for r in a.raw)
        if not sources:
            sys.exit("--manifest needs --raw firewall=<log> (and windows=<log> if present)")
        try:
            truth = tr.load_manifest(a.manifest, sources)
        except tr.TruthError as e:
            print(str(e), file=sys.stderr)
            return 3
        truth_name = Path(a.manifest).name
    elif (run / "truth.parquet").exists():
        import polars as pl

        truth, truth_name = pl.read_parquet(run / "truth.parquet"), "silver (truth.parquet)"
    elif a.parsed:
        truth, _ = _silver(a.parsed, SPEC, run)
        truth.write_parquet(run / "truth.parquet")
        truth_name = "silver (built now)"
    else:
        sys.exit("no truth: pass --parsed to build the silver truth, or --manifest")

    data = sc.load_run(run)
    extra = []
    if a.parsed and (Path(a.parsed) / "_stats.json").exists():
        extra.append(json.loads((Path(a.parsed) / "_stats.json").read_text(encoding="utf-8")))
    opens = None
    if a.api and data["incidents"]:
        opens = sc.measure_open_times(a.api, [i["incident_number"] for i in data["incidents"]])
    result = sc.score(truth, data, sc.load_reviewed(a.reviewed), extra, opens)
    result["truth"] = truth_name
    (run / "metrics.json").write_text(json.dumps(result, indent=1, default=str), encoding="utf-8")
    if a.json:
        print(json.dumps(result["metrics"], indent=1))
    else:
        print(f"truth: {truth_name}\n")
        print(sc.render(result))
        print(f"\nwrote {run / 'metrics.json'}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmds = {"silver": cmd_silver, "score": cmd_score}
    if not argv or argv[0] not in cmds:
        print(__doc__)
        return 0 if not argv else 2
    return cmds[argv[0]](argv[1:])
