"""python -m killchain.api [--run NAME_OR_PATH] [--host 127.0.0.1] [--port 8000]

Serves one run bundle. With no --run it uses KILLCHAIN_RUN, else the
committed sample in examples/sample-run.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain.api", description="Serve a run bundle over HTTP.")
    ap.add_argument("--run", help="run folder or run name (data/runs/<name> or examples/<name>)")
    ap.add_argument("--raw-dir", help="folder with the raw logs named in the evidence (default KILLCHAIN_RAW_DIR, else data/raw)")
    ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 inside Docker")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log-level", default="info")
    ap.add_argument("--no-watch", action="store_true",
                    help="do not reload the bundle when its files change (live mode needs the watcher)")
    args = ap.parse_args(argv)

    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(name)s: %(message)s")

    import uvicorn

    from .app import create_app
    from .bundle import BundleError

    try:
        app = create_app(args.run, raw_dir=args.raw_dir, watch=not args.no_watch)
    except BundleError as exc:
        print(f"cannot load the run: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    sys.exit(main())
