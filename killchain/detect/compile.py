"""Rule -> DuckDB SQL.

Every kind compiles to one query returning the alert's member lines:

    grp      text key of the group (group_by values joined)
    seg      segment number inside the group (separate bursts of the same key)
    source, line   the evidence line
    role     trigger | window
    g_<name> the group_by values, for the alert text

The engine (engine.py) aggregates members into alerts and evidence. Keeping
the kinds to "which lines belong to which alert" makes each kind small and the
alert shape identical for all of them.
"""

from __future__ import annotations

from typing import List

from .rules import Rule

SEP = "chr(31)"   # unit separator between group values


def _lit(v) -> str:
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"


NOT_VENDOR = "category IS DISTINCT FROM 'vendor_alert'"


def time_filter(r: Rule) -> str:
    """Rows a rule may read: valid times (unless time_quality any), and never a vendor alert record:
    another product's detection, which detect/vendor.py turns into an alert of its own (a rule over the
    same record would report it twice). category is NULL on a FortiGate run, so every row stays there."""
    return f"ts_valid AND {NOT_VENDOR}" if r.time_quality == "valid" else NOT_VENDOR


def _group_cols(r: Rule) -> str:
    return "".join(f", ({e}) AS g_{n}" for e, n in r.group_by)


def _grp_expr(r: Rule) -> str:
    if not r.group_by:
        return "'all'"
    parts = ", ".join(f"coalesce(CAST(({e}) AS VARCHAR), '-')" for e, _ in r.group_by)
    return f"concat_ws({SEP}, {parts})"


def _gnames(r: Rule, prefix: str = "") -> str:
    return "".join(f", {prefix}g_{n}" for _, n in r.group_by)


def _base(r: Rule, where: str, extra: str = "") -> str:
    return (f"SELECT source, line, ts_utc AS ts, {_grp_expr(r)} AS grp{_group_cols(r)}{extra} "
            f"FROM {r.table} WHERE {time_filter(r)} AND ({where})")


def _segments(src: str, gap_s: int) -> str:
    """CTE bodies that number bursts: a gap longer than gap_s starts a new segment."""
    return (f"S AS (SELECT *, CASE WHEN lag(ts) OVER w IS NULL OR ts - lag(ts) OVER w > INTERVAL {gap_s} SECOND "
            f"THEN 1 ELSE 0 END AS nw FROM {src} WINDOW w AS (PARTITION BY grp ORDER BY ts, line)), "
            f"G AS (SELECT *, sum(nw) OVER (PARTITION BY grp ORDER BY ts, line ROWS UNBOUNDED PRECEDING) AS seg FROM S)")


def compile_match(r: Rule) -> str:
    having = f" HAVING {r.having_sql('count(*)')}" if r.having else ""
    return (f"WITH F AS ({_base(r, r.where)}), {_segments('F', r.split_gap_s)}, "
            f"Q AS (SELECT grp, seg FROM G GROUP BY grp, seg{having}) "
            f"SELECT G.grp, G.seg, source, line, 'trigger' AS role{_gnames(r, 'G.')} FROM G JOIN Q USING (grp, seg)")


def compile_window(r: Rule) -> str:
    """count and distinct: lines inside any window that meets `having`; overlapping windows merge."""
    w = r.window_s
    if r.kind == "distinct":
        extra, agg = f", ({r.field}) AS fv", "count(DISTINCT fv)"
    else:
        extra, agg = "", "count(*)"
    return (
        f"WITH F AS ({_base(r, r.where, extra)}), "
        f"C AS (SELECT *, {agg} OVER (PARTITION BY grp ORDER BY ts RANGE BETWEEN INTERVAL {w} SECOND PRECEDING "
        f"AND CURRENT ROW) AS c FROM F), "
        f"T AS (SELECT *, ({r.having_sql('c')}) AS trig FROM C), "
        f"W AS (SELECT *, max(CAST(trig AS INTEGER)) OVER (PARTITION BY grp ORDER BY ts RANGE BETWEEN CURRENT ROW "
        f"AND INTERVAL {w} SECOND FOLLOWING) AS inw FROM T), "
        f"K AS (SELECT * FROM W WHERE inw = 1), {_segments('K', w)} "
        f"SELECT grp, seg, source, line, CASE WHEN trig THEN 'trigger' ELSE 'window' END AS role{_gnames(r)} FROM G"
    )


def compile_sequence(r: Rule) -> str:
    """Steps 1..N in order for the same key, all within `within`, ending at a line of step N."""
    n = len(r.steps)
    w = r.within_s
    parts = [f"SELECT {k} AS step, * FROM ({_base(r, s['where'])})" for k, s in enumerate(r.steps, start=1)]
    pivots = ", ".join(f"count(*) FILTER (WHERE s.step = {k}) AS n{k}, min(s.ts) FILTER (WHERE s.step = {k}) AS f{k}"
                       for k in range(1, n))
    conds = [f"n{k} >= {int(s['min'])}" for k, s in enumerate(r.steps[:-1], start=1)]
    conds += [f"f{k} <= f{k + 1}" for k in range(1, n - 1)]
    conds.append(f"f{n - 1} <= ets")
    return (
        f"WITH ST AS ({' UNION ALL '.join(parts)}), "
        f"E AS (SELECT * FROM ST WHERE step = {n}), "
        f"P AS (SELECT e.grp, e.line AS eline, e.ts AS ets, {pivots} FROM E e JOIN ST s ON s.grp = e.grp "
        f"AND s.step < {n} AND s.ts BETWEEN e.ts - INTERVAL {w} SECOND AND e.ts GROUP BY e.grp, e.line, e.ts), "
        f"A AS (SELECT grp, eline, ets FROM P WHERE {' AND '.join(conds)}), "
        f"M AS (SELECT DISTINCT s.* FROM ST s JOIN A a ON s.grp = a.grp AND ((s.step < {n} AND s.ts BETWEEN "
        f"a.ets - INTERVAL {w} SECOND AND a.ets) OR (s.step = {n} AND s.line = a.eline))), "
        f"{_segments('M', w)} "
        f"SELECT grp, seg, source, line, CASE WHEN step = {n} THEN 'trigger' ELSE 'window' END AS role"
        f"{_gnames(r)} FROM G"
    )


def compile_sql(r: Rule) -> str:
    """User SQL returning alert_key, source, line. One alert per distinct alert_key,
    so the key must also separate bursts if the rule needs that. Placeholders:
    {events} = the rule's table with the time filter, {all_events} = the whole table."""
    body = r.sql.replace("{events}", f"(SELECT * FROM {r.table} WHERE {time_filter(r)})").replace(
        "{all_events}", r.table)
    return (f"SELECT CAST(alert_key AS VARCHAR) AS grp, CAST(1 AS BIGINT) AS seg, source, line, 'trigger' AS role "
            f"FROM ({body})")


def members_sql(r: Rule) -> str:
    if r.kind == "match":
        return compile_match(r)
    if r.kind in ("count", "distinct"):
        return compile_window(r)
    if r.kind == "sequence":
        return compile_sequence(r)
    return compile_sql(r)


def technique_case(r: Rule) -> str:
    """Per-line technique: technique_by overrides, else the rule's technique."""
    whens: List[str] = []
    for col, mapping in r.technique_by.items():
        for val, tech in mapping.items():
            whens.append(f"WHEN e.{col} = {_lit(val)} THEN {_lit(tech)}")
    tech = _lit(r.label["technique"])
    return f"CASE {' '.join(whens)} ELSE {tech} END" if whens else tech
