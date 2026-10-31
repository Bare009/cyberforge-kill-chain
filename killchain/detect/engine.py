"""Run rules over the event tables and write alerts (contract B).

Outputs in the run folder:
  alerts.parquet            one row per alert (timestamps as UTC)
  alerts.json               the same in contract B form (ISO strings), for the API
  alert_evidence.parquet    every member line: alert_id, source, line, byte_offset, ts, technique, role
  detect/_stats.json        per-rule timings and counts, wall time, peak memory
"""

from __future__ import annotations

import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb
import polars as pl

from ..contracts import validate_alert
from . import compile as cp
from .rules import Rule

ALERT_COLS = ["alert_id", "rule_id", "layer", "title", "technique", "alt_techniques", "technique_name", "tactic",
              "stage_no", "kill_chain_stage", "severity", "confidence", "ts_start", "ts_end", "src_ip", "dst_ip",
              "host", "user", "domain", "url", "event_count", "blocked_share", "success", "summary", "action_text",
              "incident_number", "promote", "kind", "group_key", "src_count", "dst_count", "distinct_count",
              "passed", "status"]
EVIDENCE_SCHEMA = {"alert_id": pl.Utf8, "source": pl.Utf8, "line": pl.Int64, "byte_offset": pl.Int64,
                   "ts": pl.Datetime("us", "UTC"), "technique": pl.Utf8, "role": pl.Utf8}


class _Fmt(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _iso(ts: Optional[datetime]) -> Optional[str]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def check_rule(con: duckdb.DuckDBPyConnection, r: Rule) -> Optional[str]:
    """Bind the rule's SQL without reading data; returns an error message or None."""
    try:
        con.execute(f"SELECT * FROM ({cp.members_sql(r)}) LIMIT 0")
        if r.entities or r.success:
            exprs = [f"({e}) AS x{i}" for i, e in enumerate(r.entities.values())] + [f"({r.success}) AS ok"]
            con.execute(f"SELECT {', '.join(exprs)} FROM {r.table} e LIMIT 0")
        con.execute(f"SELECT {cp.technique_case(r)} FROM {r.table} e LIMIT 0")
    except duckdb.Error as e:
        return f"{r.path.name} ({r.id}): SQL does not compile: {str(e).splitlines()[0]}"
    return None


def run_rule(con: duckdb.DuckDBPyConnection, r: Rule) -> Tuple[pl.DataFrame, pl.DataFrame, Dict[str, Any]]:
    t0 = time.perf_counter()
    con.execute("DROP TABLE IF EXISTS _m")
    con.execute(f"CREATE TEMP TABLE _m AS {cp.members_sql(r)}")
    n_members = con.execute("SELECT count(*) FROM _m").fetchone()[0]
    t_members = time.perf_counter() - t0
    if n_members == 0:
        return _empty_alerts(), pl.DataFrame(schema=EVIDENCE_SCHEMA), {
            "rule_id": r.id, "kind": r.kind, "alerts": 0, "evidence_lines": 0,
            "secs": round(time.perf_counter() - t0, 3), "members_secs": round(t_members, 3)}

    gnames = [n for _, n in r.group_by]
    ent = ", ".join(f"mode({e}) AS {k}" for k, e in r.entities.items())
    ent = (", " + ent) if ent else ""
    gsel = "".join(f", any_value(m.g_{n}) AS g_{n}" for n in gnames)
    dist = f", count(DISTINCT e.{r.field}) AS distinct_count" if r.kind == "distinct" and r.field else ", NULL::BIGINT AS distinct_count"
    con.execute("DROP TABLE IF EXISTS _a")
    con.execute(f"""
        CREATE TEMP TABLE _a AS
        SELECT m.grp, m.seg, min(e.ts_utc) AS ts_start, max(e.ts_utc) AS ts_end, count(*) AS event_count,
               count(*) FILTER (WHERE {r.success}) AS passed, count(DISTINCT e.src_ip) AS src_count,
               count(DISTINCT e.dst_ip) AS dst_count{dist}{ent}{gsel}
        FROM _m m JOIN {r.table} e ON e.source = m.source AND e.line = m.line
        GROUP BY m.grp, m.seg""")
    con.execute(f"ALTER TABLE _a ADD COLUMN alert_id VARCHAR")
    con.execute(f"UPDATE _a SET alert_id = substr(md5({cp._lit(r.id)} || '|' || grp || '|' || "
                f"strftime(ts_start, '%Y-%m-%dT%H:%M:%S.%f')), 1, 16)")
    a = con.sql("SELECT * FROM _a ORDER BY ts_start").pl()
    ev = con.sql(f"""
        SELECT a.alert_id, m.source, m.line, e.byte_offset, e.ts, {cp.technique_case(r)} AS technique, m.role
        FROM _m m JOIN _a a USING (grp, seg) JOIN {r.table} e ON e.source = m.source AND e.line = m.line
        ORDER BY a.alert_id, m.line""").pl()
    alerts = _to_alerts(r, a, gnames)
    stats = {"rule_id": r.id, "kind": r.kind, "alerts": alerts.height, "evidence_lines": ev.height,
             "secs": round(time.perf_counter() - t0, 3), "members_secs": round(t_members, 3)}
    return alerts, ev.cast({k: v for k, v in EVIDENCE_SCHEMA.items() if k in ev.columns}), stats


def _empty_alerts() -> pl.DataFrame:
    return pl.DataFrame(schema={c: pl.Utf8 for c in ALERT_COLS})


def _minutes(a: datetime, b: datetime) -> str:
    m = (b - a).total_seconds() / 60
    return f"{m:.0f}" if m >= 10 else f"{m:.1f}".rstrip("0").rstrip(".") or "0"


def _to_alerts(r: Rule, a: pl.DataFrame, gnames: List[str]) -> pl.DataFrame:
    rows = []
    for row in a.iter_rows(named=True):
        n = int(row["event_count"])
        passed = int(row["passed"])
        vals = _Fmt({k: v for k, v in row.items() if v is not None})
        for g in gnames:
            vals[g] = row.get(f"g_{g}")
        vals.update(event_count=f"{n:,}", minutes=_minutes(row["ts_start"], row["ts_end"]), passed=f"{passed:,}",
                    blocked=f"{n - passed:,}", src_count=f"{row['src_count']:,}", dst_count=f"{row['dst_count']:,}",
                    distinct_count=f"{row['distinct_count']:,}" if row.get("distinct_count") is not None else "",
                    hours=f"{(row['ts_end'] - row['ts_start']).total_seconds() / 3600:.1f}",
                    days=f"{(row['ts_end'] - row['ts_start']).total_seconds() / 86400:.1f}")
        try:
            text = r.action_text.format_map(vals)
        except (ValueError, KeyError):
            text = r.action_text
        group_key = {g: (str(row.get(f"g_{g}")) if row.get(f"g_{g}") is not None else None) for g in gnames}
        rows.append({
            "alert_id": row["alert_id"], "rule_id": r.id, "layer": r.layer, "title": r.title,
            **r.label, "alt_techniques": r.alt_techniques, "severity": r.severity, "confidence": r.confidence,
            "ts_start": row["ts_start"], "ts_end": row["ts_end"],
            **{k: (str(row[k]) if row.get(k) is not None else None) for k in ("src_ip", "dst_ip", "host", "user",
                                                                             "domain", "url")},
            "event_count": n, "blocked_share": round(1 - passed / n, 4) if n else 0.0, "success": passed > 0,
            "summary": text, "action_text": text, "incident_number": None, "promote": r.promote, "kind": r.kind,
            "group_key": json.dumps(group_key, ensure_ascii=False), "src_count": int(row["src_count"]),
            "dst_count": int(row["dst_count"]),
            "distinct_count": int(row["distinct_count"]) if row.get("distinct_count") is not None else None,
            "passed": passed, "status": r.status,
        })
    return pl.DataFrame(rows, schema_overrides={"alt_techniques": pl.List(pl.Utf8), "incident_number": pl.Int64,
                                                "distinct_count": pl.Int64}, infer_schema_length=None)


def run_rules(con: duckdb.DuckDBPyConnection, rules: List[Rule]) -> Tuple[pl.DataFrame, pl.DataFrame, List[Dict[str, Any]]]:
    alerts, evidence, stats = [], [], []
    for r in rules:
        a, ev, st = run_rule(con, r)
        stats.append(st)
        if a.height:
            alerts.append(a)
            evidence.append(ev)
    if alerts:
        A = pl.concat(alerts, how="diagonal_relaxed").sort("ts_start", "rule_id")
        E = pl.concat(evidence, how="diagonal_relaxed")
    else:
        A, E = _empty_alerts(), pl.DataFrame(schema=EVIDENCE_SCHEMA)
    return A, E, stats


def alerts_json(alerts: pl.DataFrame) -> List[Dict[str, Any]]:
    out = []
    for row in alerts.iter_rows(named=True):
        d = dict(row)
        d["ts_start"], d["ts_end"] = _iso(d["ts_start"]), _iso(d["ts_end"])
        d["alt_techniques"] = list(d["alt_techniques"] or [])
        for k in ("blocked_share", "confidence"):
            if isinstance(d[k], float) and math.isnan(d[k]):
                d[k] = 0.0
        out.append(d)
    return out


def write_outputs(run: Path, alerts: pl.DataFrame, evidence: pl.DataFrame, stats: Dict[str, Any]) -> List[str]:
    """Write the files; returns contract errors found in the alerts (empty when all valid)."""
    run.mkdir(parents=True, exist_ok=True)
    js = alerts_json(alerts) if alerts.height else []
    errors = [e for i, a in enumerate(js) for e in validate_alert(a, f"alert[{i}] {a['rule_id']}")]
    alerts.write_parquet(run / "alerts.parquet")
    evidence.write_parquet(run / "alert_evidence.parquet")
    (run / "alerts.json").write_text(json.dumps(js, indent=1, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    (run / "detect").mkdir(exist_ok=True)
    (run / "detect" / "_stats.json").write_text(json.dumps(stats, indent=1, default=str), encoding="utf-8")
    return errors
