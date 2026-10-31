"""python -m killchain.agents narrate --run <run> [--only N ...] [--llm | --no-llm] [--force] [--facts]

Writes <run>/report.json: one AI report and triage opinion per incident, each checked
against the incident's facts (docs/build-plan.md P10b). Incidents whose answer fails the
check keep their template report. Run `python -m killchain.bundle --run <run>` afterwards
to merge the reports into the incident files.

The LLM is off unless LLM_ENABLED=true in .env or --llm is given (free-tier budgets).
A rerun reuses every report whose facts and prompt did not change, and every answer is
cached in data/cache/llm.sqlite, so it costs nothing for unchanged incidents.
--facts prints each fact sheet's size and makes no call.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


HTTP_CLIENT = None          # tests put an httpx.Client with a mock transport here


def _load(run_dir: Path):
    import orjson

    index = orjson.loads((run_dir / "index.json").read_bytes())
    incidents = {r["incident_number"]: orjson.loads((run_dir / "incidents" / f"{r['incident_number']}.json").read_bytes())
                 for r in index.get("incidents") or []}
    alerts = orjson.loads((run_dir / "alerts.json").read_bytes()) if (run_dir / "alerts.json").exists() else []
    return incidents, alerts


def cmd_narrate(a: argparse.Namespace) -> int:
    from killchain.api.bundle import BundleError, resolve_run_dir

    from .facts import fact_sheet
    from .llm import LLMClient, LLMStore, estimate_tokens
    from .narrator import messages_for, narrate, reusable, run_accounts, summarise_calls
    from .settings import CACHE_PATH, endpoints, llm_config, llm_enabled

    try:
        run_dir = resolve_run_dir(a.run)
    except BundleError as exc:
        print(f"narrate: {exc}", file=sys.stderr)
        return 1
    incidents, alerts = _load(run_dir)
    chosen = [n for n in sorted(incidents) if not a.only or n in a.only]

    if a.facts:
        for n in chosen:
            toks = estimate_tokens(messages_for(fact_sheet(incidents[n])))
            print(f"#{n}: about {toks:,} prompt tokens, {len(incidents[n]['chain'])} steps")
        return 0
    on = (llm_enabled() or a.llm) and not a.no_llm
    if not on:
        print("narrate: the LLM is off (set LLM_ENABLED=true in .env or pass --llm); "
              "incidents keep their template reports. Nothing written.")
        return 0
    chain = endpoints("large")
    if not chain:
        print("narrate: no LLM endpoint with a key in .env (LLM_PRIMARY_API_KEY, LLM_FALLBACK_API_KEY); "
              "incidents keep their template reports.", file=sys.stderr)
        return 1

    out_path = run_dir / "report.json"
    prev = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else {}
    prev_entries = prev.get("incidents") or {}
    version = int((llm_config().get("narrator") or {}).get("prompt_version", 1))
    store = LLMStore(Path(a.cache) if a.cache else CACHE_PATH)
    client = LLMClient(chain, store, http_client=HTTP_CLIENT)
    accounts = run_accounts(alerts, incidents.values())

    entries = {} if a.force else {k: v for k, v in prev_entries.items()
                                  if k in {i["incident_id"] for i in incidents.values()}}
    failures = {}
    outcomes = []
    reused = 0
    for n in chosen:
        inc = incidents[n]
        old = prev_entries.get(inc["incident_id"])
        if not a.force and reusable(old, inc, version):
            reused += 1
            print(f"#{n}: unchanged, kept")
            continue
        o = narrate(inc, client, accounts)
        outcomes.append(o)
        if o.entry:
            entries[inc["incident_id"]] = o.entry
            c = o.calls[-1]
            print(f"#{n}: {o.entry['triage']['verdict']} ({o.entry['triage']['confidence']}) by {c.endpoint}"
                  f"{' (cached)' if o.entry['cached'] else ''}, {o.entry['attempts']} attempt(s)")
        else:
            entries.pop(inc["incident_id"], None)
            failures[inc["incident_id"]] = {"incident_number": n, "reason": o.failure}
            print(f"#{n}: template kept: {o.failure}")
    usage, model = summarise_calls(outcomes)
    doc = {
        "run": run_dir.name,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": model or prev.get("model"),
        "prompt_version": version,
        "usage": usage,
        "budget": client.budget(),
        "incidents": entries,
        "failures": failures,
    }
    tmp = out_path.with_name("report.json.tmp")
    tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, out_path)
    store.close()
    print(f"\n{len(entries)} AI reports ({reused} kept unchanged), {len(failures)} kept the template; "
          f"{usage['calls']} calls ({usage['cached']} from cache), {usage['tokens']:,} tokens -> {out_path}")
    print(f"next: python -m killchain.bundle --run {run_dir}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain.agents", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("narrate", help="AI report and triage opinion per incident -> <run>/report.json")
    n.add_argument("--run", required=True, help="run folder, or a run name in data/runs or examples")
    n.add_argument("--only", type=int, nargs="+", help="incident numbers")
    g = n.add_mutually_exclusive_group()
    g.add_argument("--llm", action="store_true", help="call the LLM even when LLM_ENABLED is false")
    g.add_argument("--no-llm", action="store_true", help="never call the LLM")
    n.add_argument("--force", action="store_true", help="redo every report, even unchanged ones (the cache still applies)")
    n.add_argument("--facts", action="store_true", help="print fact sheet sizes only")
    n.add_argument("--cache", help="SQLite cache (default data/cache/llm.sqlite)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    return cmd_narrate(a)


if __name__ == "__main__":
    sys.exit(main())
