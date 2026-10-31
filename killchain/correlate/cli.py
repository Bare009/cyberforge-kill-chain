"""python -m killchain correlate --run data/runs/firex-10G [--config config/correlate.yaml]

Reads <run>/alerts.parquet and <run>/alert_evidence.parquet (from detect) and writes
incidents.parquet, incident_alerts.parquet, unexplained.parquet and correlate/_stats.json.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import List, Optional

from .entities import SETTINGS_YAML

IST = timedelta(hours=5, minutes=30)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain correlate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="run folder holding alerts.parquet and alert_evidence.parquet")
    ap.add_argument("--config", default=str(SETTINGS_YAML), help="correlation settings (default config/correlate.yaml)")
    a = ap.parse_args(argv)
    import polars as pl

    from .. import db
    from ..detect.cli import _Peak
    from . import engine
    from .entities import load_settings

    run = Path(a.run)
    need = [run / "alerts.parquet", run / "alert_evidence.parquet"]
    missing = [p.name for p in need if not p.exists()]
    if missing:
        print(f"correlate: {', '.join(missing)} not found in {run}; run `python -m killchain detect --run {run}` first",
              file=sys.stderr)
        return 1
    peak = _Peak()
    peak.start()
    t0 = time.perf_counter()
    alerts = pl.read_parquet(need[0])
    evidence = pl.read_parquet(need[1], columns=["alert_id", "source", "line"])
    res = engine.correlate(alerts, evidence, db.load_network(), load_settings(a.config))
    wall = time.perf_counter() - t0
    peak.stop.set()
    st = res["stats"]
    stats = {"stage": "correlate", "wall_secs": round(wall, 2), "peak_rss_mb": round(peak.peak / 2**20), **st}
    errors = engine.contract_errors(res, set(alerts["alert_id"].to_list()))
    engine.write_outputs(run, res, stats)

    steps = res["incident_alerts"]
    for inc in res["incidents"].iter_rows(named=True):
        rids = steps.filter(pl.col("incident_id") == inc["incident_id"])["rule_id"].to_list()
        print(f"#{inc['incident_number']} {inc['incident_id']} sev {inc['severity']} alerts {inc['merged']['alerts']} "
              f"(+{inc['anomaly_steps']} anomaly) events {inc['merged']['events']:,} "
              f"{(inc['ts_start'] + IST):%m-%d %H:%M}-{(inc['ts_end'] + IST):%m-%d %H:%M} IST "
              f"{' > '.join(rids)} | {inc['title']}")
    print(f"\n{st['incidents']} incidents ({st['anomaly_only_incidents']} anomaly-only) from {st['alerts']} alerts; "
          f"unexplained {st['unexplained']}, below bar {st['below_bar']}, largest incident "
          f"{st['largest_incident_alerts']} alerts; {wall:.2f} s -> {run}")
    print(f"hubs: {', '.join(st['hubs'])}")
    if errors:
        print("contract errors:\n  " + "\n  ".join(errors[:20]), file=sys.stderr)
        return 1
    return 0
