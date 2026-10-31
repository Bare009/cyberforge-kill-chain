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

PLANNED: Dict[str, str] = {}


def cmd_parse(rest: List[str]) -> int:
    from .parser.cli import main as parser_main

    parser_main(rest)
    return 0


def cmd_db(rest: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain db",
                                 description="Open the DuckDB views over a parsed run and print a summary or run SQL.")
    ap.add_argument("--parsed", help="parsed run folder, e.g. data/parsed/firex-10G")
    ap.add_argument("--run", help="run folder; uses its prepared events.duckdb when present")
    ap.add_argument("--prepare", action="store_true",
                    help="store the derived columns as tables in <run>/events.duckdb (one-off, about 80 s on the 6.5 GB file)")
    ap.add_argument("--sql", help="run this SQL against the views and print the result")
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args(rest)
    from . import db

    t0 = time.perf_counter()
    if args.prepare:
        if not args.parsed:
            ap.error("--prepare needs --parsed")
        run = args.run or str(Path("data") / "runs" / Path(args.parsed).name)
        print(json.dumps(db.prepare_run(args.parsed, run), indent=1))
        return 0
    if not args.parsed and not args.run:
        ap.error("give --parsed or --run")
    con = db.connect(args.parsed, args.run)
    if args.sql:
        rel = con.sql(args.sql)
        rel.limit(args.limit).show(max_width=200, max_rows=args.limit)
    else:
        print(json.dumps(db.summary(con), indent=1))
    print(f"({time.perf_counter() - t0:.2f} s)", file=sys.stderr)
    return 0


def cmd_eval(rest: List[str]) -> int:
    from .eval.cli import main as eval_main

    return eval_main(rest)


def cmd_detect(rest: List[str]) -> int:
    from .detect.cli import main as detect_main

    return detect_main(rest)


def cmd_correlate(rest: List[str]) -> int:
    from .correlate.cli import main as correlate_main

    return correlate_main(rest)


def cmd_chain(rest: List[str]) -> int:
    from .graph.cli import main as chain_main

    return chain_main(rest)


def cmd_reach(rest: List[str]) -> int:
    from .graph.cli import reach_main

    return reach_main(rest)


def cmd_score(rest: List[str]) -> int:
    from .score.cli import main as score_main

    return score_main(rest)


def cmd_report(rest: List[str]) -> int:
    from .report.cli import main as report_main

    return report_main(rest)


def cmd_enrich(rest: List[str]) -> int:
    from .enrich.__main__ import main as enrich_main

    return enrich_main(rest)


def cmd_agents(rest: List[str]) -> int:
    from .agents.__main__ import main as agents_main

    return agents_main(rest)


def cmd_bundle(rest: List[str]) -> int:
    from .bundle.__main__ import main as bundle_main

    return bundle_main(rest)


def cmd_run(rest: List[str]) -> int:
    from .run.cli import main as run_main

    return run_main(rest)


def cmd_serve(rest: List[str]) -> int:
    from .api.__main__ import main as api_main

    return api_main(rest)


def cmd_live(rest: List[str]) -> int:
    from .live.cli import main as live_main

    return live_main(rest)


COMMANDS: Dict[str, Callable[[List[str]], int]] = {"parse": cmd_parse, "db": cmd_db, "eval": cmd_eval,
                                                   "detect": cmd_detect, "correlate": cmd_correlate,
                                                   "chain": cmd_chain, "reach": cmd_reach,
                                                   "score": cmd_score, "report": cmd_report,
                                                   "enrich": cmd_enrich, "agents": cmd_agents,
                                                   "bundle": cmd_bundle, "run": cmd_run, "serve": cmd_serve,
                                                   "live": cmd_live}


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
