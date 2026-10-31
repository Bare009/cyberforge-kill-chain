"""python -m killchain <stage> ...

One entry point for every pipeline stage. Stages not built yet say which
phase of docs/build-plan.md will add them.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

PLANNED = {
    "detect": "P3", "correlate": "P6", "chain": "P7", "reach": "P8", "enrich": "P9",
    "score": "P10", "report": "P10", "agents": "P10b", "bundle": "P11", "serve": "P11",
    "eval": "P2", "run": "P13", "live": "P15",
}


def cmd_parse(rest: List[str]) -> int:
    from .parser.cli import main as parser_main

    parser_main(rest)
    return 0


def cmd_db(rest: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain db",
                                 description="Open the DuckDB views over a parsed run and print a summary or run SQL.")
    ap.add_argument("--parsed", required=True, help="parsed run folder, e.g. data/parsed/firex-10G")
    ap.add_argument("--sql", help="run this SQL against the views and print the result")
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args(rest)
    from . import db

    t0 = time.perf_counter()
    con = db.open_run(args.parsed)
    if args.sql:
        rel = con.sql(args.sql)
        rel.limit(args.limit).show(max_width=200, max_rows=args.limit)
    else:
        print(json.dumps(db.summary(con), indent=1))
    print(f"({time.perf_counter() - t0:.2f} s)", file=sys.stderr)
    return 0


COMMANDS: Dict[str, Callable[[List[str]], int]] = {"parse": cmd_parse, "db": cmd_db}


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    names = sorted(set(COMMANDS) | set(PLANNED))
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m killchain <stage> [options]\n\nstages:")
        for n in names:
            print(f"  {n:10s} {'ready' if n in COMMANDS else 'planned (' + PLANNED[n] + ')'}")
        return 0
    name, rest = argv[0], argv[1:]
    if name in COMMANDS:
        return COMMANDS[name](rest) or 0
    if name in PLANNED:
        print(f"'{name}' is not built yet; it arrives in phase {PLANNED[name]} (docs/build-plan.md).", file=sys.stderr)
        return 2
    print(f"unknown stage '{name}'. Stages: {', '.join(names)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
