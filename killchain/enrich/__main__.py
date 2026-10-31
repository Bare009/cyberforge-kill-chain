"""python -m killchain.enrich --run <run folder or name> [--offline] [--parsed DIR] [--out FILE]

Looks up every IP, domain, URL and hash in the run's incidents and writes
<run>/enrichment.json (docs/build-plan.md P9). The API merges it into the
incidents it serves; the risk score reads it for its threat-intel part.

Keys come from .env (OTX_API_KEY). Without a key, or with --offline, only the
cache and local context are used and the run still finishes.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from .cache import TiCache
from .engine import enrich_run
from .settings import CACHE_PATH, load_dotenv


def _load_run(run_dir: Path):
    import orjson

    index = orjson.loads((run_dir / "index.json").read_bytes())
    incidents = {}
    for row in index.get("incidents") or []:
        n = row["incident_number"]
        incidents[n] = orjson.loads((run_dir / "incidents" / f"{n}.json").read_bytes())
    alerts_path = run_dir / "alerts.json"
    alerts = orjson.loads(alerts_path.read_bytes()) if alerts_path.exists() else []
    return incidents, alerts


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain.enrich", description=__doc__.split("\n\n")[1])
    ap.add_argument("--run", required=True, help="run folder, or a run name in data/runs or examples")
    ap.add_argument("--offline", action="store_true", help="no network: cache and local context only")
    ap.add_argument("--parsed", help="parsed run folder, for in-log history (optional)")
    ap.add_argument("--cache", default=str(CACHE_PATH), help="SQLite cache file (default data/cache/ti.sqlite)")
    ap.add_argument("--out", help="output file (default <run>/enrichment.json)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    from killchain.api.bundle import BundleError, resolve_run_dir

    try:
        run_dir = resolve_run_dir(args.run)
    except BundleError as exc:
        print(exc, file=sys.stderr)
        return 2
    load_dotenv()
    incidents, alerts = _load_run(run_dir)

    events = None
    if args.parsed:
        from killchain import db

        events = db.connect(parsed_dir=args.parsed, run_dir=run_dir)

    cache = TiCache(args.cache)
    doc = enrich_run(incidents, alerts, cache, offline=args.offline, events=events)
    out = Path(args.out) if args.out else run_dir / "enrichment.json"
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    s = doc["summary"]
    print(f"{s['indicators']} indicators ({s['sendable']} may be sent outside, {s['skipped_private']} kept local); "
          f"{s['lookups']} lookups, {s['cache_hits']} cache hits, {s['failures']} failures in {s['wall_secs']} s")
    print("providers: " + ", ".join(f"{k} {v}" for k, v in doc["providers"].items()))
    print("verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(s["verdicts"].items())))
    for e in s["errors"][:5]:
        print(f"  error: {e}")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
