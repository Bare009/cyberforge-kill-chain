"""python -m killchain schema --input <file> --name <run> [--no-llm] [--force] [--parse]

Detects the format of a log file of any security product, maps its fields to killchain's columns and
writes data/runs/<run>/schema.yaml, data/runs/<run>/schema_report.json and config/schemas/<fingerprint>.yaml,
then prints the report. With --parse it also parses the whole file into data/parsed/<run>/ (FortiGate
input goes to the existing parser).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]


def _pct(x: Optional[float]) -> str:
    return "-" if x is None else f"{100 * x:5.1f}%"


def render(report: Dict[str, Any]) -> str:
    out: List[str] = []
    w = out.append
    w(f"input     {report['input']}  ({report['bytes'] / 2**20:.1f} MB)")
    if report.get("plain_input"):
        w(f"plain     {report['plain_input']}")
    w(f"format    {report['format']}   parser: {report['parser']}   schema: {report['schema_source']}"
      + (f"   fingerprint {report['fingerprint']}" if report.get("fingerprint") else ""))
    s = report.get("sample") or {}
    rej = s.get("rejected") or {}
    w(f"sample    {s.get('records', 0):,} records" + (f" ({s.get('from_start', 0):,} from the start, "
      f"{s.get('from_middle', 0):,} from the middle)" if "from_start" in s else "")
      + (f"; rejected {rej}" if rej else ""))
    t = report.get("time") or {}
    tf = f"{t.get('date_field')} + {t.get('time_field')}" if t.get("date_field") else t.get("field")
    w(f"time      {tf or 'none'}  format {t.get('format') or '-'}"
      + (f"  zone field {t['tz_field']}" if t.get("tz_field") else "") + f"  parsed {_pct(t.get('coverage'))}")
    w("")
    w("categories: " + (", ".join(f"{k} {v:,}" for k, v in (report.get("categories") or {}).items()) or "none"))
    if report.get("groups"):
        w(f"  by {report.get('group_field')}: " + "; ".join(
            f"{g['value']} {g['records']:,}" + (f" -> {g['category']}" if g.get("category") else "")
            for g in report["groups"][:12]) + (" ..." if len(report["groups"]) > 12 else ""))
    w("")
    w(f"{'column':18s} {'method':9s} {'cover':>7s}  source field")
    for c in report["columns"]:
        if c["method"] == "unmapped":
            continue
        w(f"{c['column']:18s} {c['method']:9s} {_pct(c['coverage']):>7s}  {', '.join(c['fields']) or '-'}")
    unm = [c["column"] for c in report["columns"] if c["method"] == "unmapped"]
    if unm:
        w(f"unmapped columns: {', '.join(unm)}")
    v = report.get("validation") or {}
    bad = [c for c in v.get("checks") or [] if not c["ok"]]
    w("")
    w(f"validation: {len(v.get('checks') or []) - len(bad)} of {len(v.get('checks') or [])} field checks passed")
    for d in v.get("dropped") or []:
        w(f"  dropped {d['field']!r} for {d['column']}: {d['reason']}"
          + (f" e.g. {d['bad_examples']}" if d.get("bad_examples") else ""))
    for c, vals in (v.get("unknown_values") or {}).items():
        w(f"  {c}: values not in the value maps (kept as lower-case text): {', '.join(vals[:12])}")
    llm = report.get("llm") or {}
    if llm.get("used"):
        w(f"LLM: {llm.get('calls', 0)} call(s){' (cached)' if llm.get('cached') else ''}"
          f"{' via ' + llm['endpoint'] if llm.get('endpoint') else ''}; added "
          + (", ".join(f"{a['field']} -> {a['column']}" for a in llm.get("added") or []) or "nothing")
          + ("; " + "; ".join(llm.get("notes")) if llm.get("notes") else ""))
    else:
        w(f"LLM: not used ({llm.get('reason') or 'nothing left to map'})")
    r = report.get("rules") or {}
    w("")
    w(f"rules: {r.get('counts', {}).get('can_run', 0)} can run, {r.get('counts', {}).get('skipped', 0)} skipped")
    w("  can run: " + ", ".join(x["id"].split("-")[0] for x in r.get("can_run") or []))
    for x in r.get("skipped") or []:
        w(f"  skipped {x['id']}: missing {', '.join(x['missing'])}")
    if report.get("unmapped_fields"):
        u = report["unmapped_fields"]
        w("")
        w(f"fields kept in extra ({len(u)}): " + ", ".join(u[:30]) + (" ..." if len(u) > 30 else ""))
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m killchain schema", description=__doc__.split("\n\n")[0])
    ap.add_argument("--input", required=True, help="log file (any supported format; .gz and .zip are read too)")
    ap.add_argument("--name", required=True, help="run name: writes data/runs/<name>/schema.yaml")
    ap.add_argument("--no-llm", action="store_true", help="do not ask the LLM about fields the synonyms do not know")
    ap.add_argument("--force", action="store_true", help="build a new mapping even if config/schemas has one")
    ap.add_argument("--parse", action="store_true", help="also parse the whole file into data/parsed/<name>/")
    ap.add_argument("--data-dir", default=os.environ.get("KILLCHAIN_DATA_DIR") or str(ROOT / "data"))
    ap.add_argument("--assume-tz", default="+00:00", help="zone for times that carry none (e.g. +05:30)")
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--schemas-dir", default=None, help="saved mappings (default config/schemas)")
    a = ap.parse_args(argv)
    from . import SchemaError, parse, prepare
    from .prepare import SCHEMAS_DIR

    data = Path(a.data_dir)
    if not data.is_absolute():
        data = ROOT / data
    run_dir = data / "runs" / a.name
    try:
        fmt, mapping, report = prepare(a.input, run_dir, no_llm=a.no_llm, force=a.force, assume_tz=a.assume_tz,
                                       schemas_dir=a.schemas_dir or SCHEMAS_DIR)
    except SchemaError as e:
        print(f"schema: {e}", file=sys.stderr)
        return 3
    print(render(report))
    print(f"\nwrote {run_dir / 'schema.yaml'} and schema_report.json ({report['secs']} s)")
    if a.parse:
        t0 = time.perf_counter()
        st = parse(a.input, data / "parsed" / a.name, mapping, workers=a.workers)
        rows = sum(v.get("rows", 0) for v in (st.get("streams") or {}).values())
        print(f"parsed {st['bytes'] / 2**20:.1f} MB, {st['lines']:,} lines -> {rows:,} rows in {st['wall_secs']} s "
              f"({st['mb_per_sec']} MB/s, {st['lines_per_sec']:,} lines/s); lines {st.get('lines_by_class')}; "
              f"total {time.perf_counter() - t0:.1f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
