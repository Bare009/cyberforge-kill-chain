"""Numbered attack chains (docs/build-plan.md P7).

One step per alert. Order rule, sort key (ts_start, stage_no, rule_id, alert_id):
  - steps are sorted by when they start;
  - steps that start at the same instant put the lower kill chain stage first, then the rule id
    (alert_id only makes the order total);
  - a long step (beaconing, exfiltration) keeps one number at its start and shows its own ts_end;
    it is `ongoing` when a later step starts while it is still running.
Contract C requires ts_start never to decrease along the chain, so an overlap is shown with `ongoing`
rather than by moving a later-starting, lower-stage step ahead of an earlier one.

Unobserved tactics between the first and last observed stage go in `gaps`; they are never numbered.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import polars as pl

from .. import attack

IST = timedelta(hours=5, minutes=30)
SAMPLE_LINES = 20
NO_GAP = ("resource-development",)   # never visible in network logs


# ── time helpers ─────────────────────────────────────────────────────────────

def _utc(ts: datetime) -> datetime:
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def iso_z(ts: datetime) -> str:
    """ISO 8601 UTC with microseconds and a Z; naive datetimes are UTC."""
    return _utc(ts).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ist(ts: datetime) -> str:
    """Display time in IST (+05:30), YYYY-MM-DD HH:MM:SS."""
    return (_utc(ts) + IST).strftime("%Y-%m-%d %H:%M:%S")


# ── ordering, ongoing, gaps, text ────────────────────────────────────────────

def sort_key(a: Dict[str, Any]) -> Tuple[Any, ...]:
    return (_utc(a["ts_start"]), int(a["stage_no"]), str(a["rule_id"]), str(a["alert_id"]))


def order_steps(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Alerts in chain order (module docstring)."""
    return sorted(alerts, key=sort_key)


def ongoing_flags(steps: List[Dict[str, Any]]) -> List[bool]:
    """True for a step that is still running when a later step starts (strictly after it starts and
    before it ends). Steps that start at the same instant do not count."""
    out = []
    for s in steps:
        s0, s1 = _utc(s["ts_start"]), _utc(s["ts_end"])
        out.append(any(s0 < _utc(o["ts_start"]) < s1 for o in steps))
    return out


def tactic_name(t: str) -> str:
    try:
        return attack.tactic_info(t)["name"]
    except (KeyError, ValueError):
        return str(t)


def gaps(stage_nos: Iterable[int]) -> List[str]:
    """One sentence per tactic strictly between the lowest and highest observed stage with no step."""
    seen = {int(s) for s in stage_nos}
    if len(seen) < 2:
        return []
    lo, hi = min(seen), max(seen)
    return [f"No {t['name']} evidence in the logs" for t in attack.all_tactics()
            if lo < t["stage_no"] < hi and t["stage_no"] not in seen and t["shortname"] not in NO_GAP]


def chain_text(steps: List[Dict[str, Any]]) -> str:
    """'1. Reconnaissance → 2-3. Initial Access → ...'; consecutive steps of one tactic share a range."""
    parts: List[Tuple[int, int, str]] = []
    for s in steps:
        if parts and parts[-1][2] == s["tactic"]:
            parts[-1] = (parts[-1][0], s["n"], s["tactic"])
        else:
            parts.append((s["n"], s["n"], s["tactic"]))
    return " → ".join(f"{a}. {tactic_name(t)}" if a == b else f"{a}-{b}. {tactic_name(t)}" for a, b, t in parts)


# ── steps ────────────────────────────────────────────────────────────────────

def hub_domains(net: Optional[Dict[str, Any]]) -> set:
    return {str(d).strip().lower() for d in ((net or {}).get("hubs") or {}).get("domains") or []}


def step_dst(a: Dict[str, Any], hubs: set) -> Optional[str]:
    if a.get("dst_ip"):
        return a["dst_ip"]
    d = a.get("domain")
    return d if d and str(d).strip().lower() not in hubs else None


def evidence_rows(ev: Optional[pl.DataFrame], alert_id: str) -> List[Dict[str, Any]]:
    """Up to SAMPLE_LINES evidence objects for an alert, trigger rows first, then by ts and line."""
    if ev is None or not ev.height:
        return []
    g = ev.filter(pl.col("alert_id") == alert_id)
    if "role" in g.columns:
        g = g.with_columns((pl.col("role") != "trigger").alias("_w")).sort(["_w", "ts", "line"])
    else:
        g = g.sort(["ts", "line"])
    return [{"source": r["source"], "line": int(r["line"]), "byte_offset": int(r["byte_offset"]),
             "ts": iso_z(r["ts"])} for r in g.head(SAMPLE_LINES).iter_rows(named=True)]


def build_steps(alerts: Iterable[Dict[str, Any]], evidence: Optional[pl.DataFrame],
                net: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Contract-C steps (contracts.STEP) numbered 1..N in chain order."""
    hubs = hub_domains(net)
    ordered = order_steps(alerts)
    flags = ongoing_flags(ordered)
    totals: Dict[str, int] = {}
    if evidence is not None and evidence.height:
        totals = dict(evidence.filter(pl.col("alert_id").is_in([a["alert_id"] for a in ordered]))
                      .group_by("alert_id").len().iter_rows())
    steps = []
    for n, (a, on) in enumerate(zip(ordered, flags), 1):
        steps.append({
            "n": n, "ts_start": iso_z(a["ts_start"]), "ts_end": iso_z(a["ts_end"]),
            "ts_start_ist": ist(a["ts_start"]), "ts_end_ist": ist(a["ts_end"]), "ongoing": bool(on),
            "action": a.get("action_text") or a.get("summary") or a.get("title") or a["rule_id"],
            "rule_id": a["rule_id"], "alert_id": a["alert_id"],
            "technique": a["technique"], "technique_name": a.get("technique_name"), "tactic": a["tactic"],
            "stage_no": int(a["stage_no"]), "kill_chain_stage": a.get("kill_chain_stage") or
            attack.kill_chain_stage(a["tactic"]),
            "src": a.get("src_ip"), "dst": step_dst(a, hubs),
            "event_count": int(a.get("event_count") or 0), "success": bool(a.get("success")),
            "line_sample": evidence_rows(evidence, a["alert_id"]),
            "line_total": int(totals.get(a["alert_id"], 0)),
            "enrichment_flags": [], "confidence": float(a["confidence"]), "layer": a.get("layer") or "rule",
        })
    return steps


def _unique(xs: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    for x in xs:
        if x is not None and x not in out:
            out.append(x)
    return out


def build_chains(incidents: pl.DataFrame, members: pl.DataFrame, alerts: pl.DataFrame,
                 evidence: pl.DataFrame, net: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], pl.DataFrame]:
    """Per incident {incident_id, incident_number, chain_text, chain, gaps, tactics, techniques, graph},
    in incident_number order, plus the incident_lines frame (every evidence row of every step)."""
    from .path import path_graph

    A = {r["alert_id"]: r for r in alerts.iter_rows(named=True)}
    ev = evidence.filter(pl.col("alert_id").is_in(members["alert_id"].unique().to_list()))
    by_alert = {k[0]: g for k, g in ev.partition_by("alert_id", as_dict=True).items()} if ev.height else {}
    out, step_rows = [], []
    for inc in incidents.sort("incident_number").iter_rows(named=True):
        ids = members.filter(pl.col("incident_id") == inc["incident_id"])["alert_id"].to_list()
        sub = pl.concat([by_alert[x] for x in ids if x in by_alert]) if any(x in by_alert for x in ids) else None
        steps = build_steps([A[x] for x in ids], sub, net)
        out.append({
            "incident_id": inc["incident_id"], "incident_number": int(inc["incident_number"]),
            "chain_text": chain_text(steps), "chain": steps, "gaps": gaps(s["stage_no"] for s in steps),
            "tactics": _unique(s["tactic"] for s in steps), "techniques": _unique(s["technique"] for s in steps),
            "graph": path_graph(steps, A, net),
        })
        step_rows += [{"incident_id": inc["incident_id"], "incident_number": int(inc["incident_number"]),
                       "step": s["n"], "alert_id": s["alert_id"]} for s in steps]
    sm = pl.DataFrame(step_rows, schema={"incident_id": pl.Utf8, "incident_number": pl.Int64, "step": pl.Int64,
                                         "alert_id": pl.Utf8})
    cols = [c for c in ("source", "line", "byte_offset", "ts", "technique", "role") if c in evidence.columns]
    lines = (sm.join(evidence.select("alert_id", *cols), on="alert_id", how="inner")
             .sort("incident_number", "step", "ts", "line"))
    return out, lines
