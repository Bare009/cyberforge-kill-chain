"""Numbered attack chains (docs/build-plan.md P7).

What gets a number: when an incident has at least one rule-layer alert, only its rule alerts become
numbered steps; every anomaly alert is attached to exactly one rule step as `supporting` evidence. An
incident made only of anomaly alerts numbers those alerts, and every step has `supporting: []`.

Attachment rule (anomaly X, rule steps R): X goes to the R with the smallest key
  (no shared entity, gap in seconds between the time ranges (0 when they overlap or touch),
   different tactic, |X.ts_start - R.ts_start|, R.n).
Entities compared: src_ip, dst_ip, user, host, domain (lower-cased). relation is `during` when the gap
is 0, `before` when X ends before R starts, else `after`.

One step per numbered alert. Order rule, sort key (ts_start, stage_no, rule_id, alert_id):
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


def gaps(stage_nos: Iterable[int], also_seen: Iterable[int] = ()) -> List[str]:
    """One sentence per tactic strictly between the lowest and highest numbered stage with no evidence.
    The range comes from stage_nos (numbered steps); also_seen (supporting entries) only fills gaps."""
    seen = {int(s) for s in stage_nos}
    if len(seen) < 2:
        return []
    lo, hi = min(seen), max(seen)
    seen |= {int(s) for s in also_seen}
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


ENTITY_KEYS = ("src_ip", "dst_ip", "user", "host", "domain")


def _layer(a: Dict[str, Any]) -> str:
    return a.get("layer") or "rule"


def shares_entity(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """True when any non-null value among src_ip, dst_ip, user, host, domain of a equals one of b's."""
    va = {str(a[k]).strip().lower() for k in ENTITY_KEYS if a.get(k)}
    vb = {str(b[k]).strip().lower() for k in ENTITY_KEYS if b.get(k)}
    return bool(va & vb)


def gap_secs(a: Dict[str, Any], b: Dict[str, Any]) -> float:
    """Seconds between the closed time ranges of a and b; 0 when they overlap or touch."""
    a0, a1, b0, b1 = _utc(a["ts_start"]), _utc(a["ts_end"]), _utc(b["ts_start"]), _utc(b["ts_end"])
    if a1 < b0:
        return (b0 - a1).total_seconds()
    if b1 < a0:
        return (a0 - b1).total_seconds()
    return 0.0


def relation(x: Dict[str, Any], r: Dict[str, Any]) -> str:
    if gap_secs(x, r) == 0:
        return "during"
    return "before" if _utc(x["ts_end"]) < _utc(r["ts_start"]) else "after"


def attach_supporting(rules: List[Dict[str, Any]], anomalies: Iterable[Dict[str, Any]]
                      ) -> Dict[str, List[Tuple[Dict[str, Any], str]]]:
    """rule alert_id -> [(anomaly alert, relation)] in chain order. rules: rule alerts in chain order
    (step n = position + 1). Each anomaly goes to the rule step with the smallest attachment key
    (module docstring)."""
    out: Dict[str, List[Tuple[Dict[str, Any], str]]] = {r["alert_id"]: [] for r in rules}
    if not rules:
        return out
    for x in order_steps(anomalies):
        def key(item: Tuple[int, Dict[str, Any]]) -> Tuple[Any, ...]:
            n, r = item
            return (not shares_entity(x, r), gap_secs(x, r), x["tactic"] != r["tactic"],
                    abs((_utc(x["ts_start"]) - _utc(r["ts_start"])).total_seconds()), n)
        _, best = min(enumerate(rules, 1), key=key)
        out[best["alert_id"]].append((x, relation(x, best)))
    return out


def _action(a: Dict[str, Any]) -> str:
    return a.get("action_text") or a.get("summary") or a.get("title") or a["rule_id"]


def support_entry(a: Dict[str, Any], rel: str, line_total: int, hubs: set) -> Dict[str, Any]:
    """A contracts.SUPPORT entry; values are filled like the step fields of the same name."""
    return {
        "alert_id": a["alert_id"], "rule_id": a["rule_id"], "layer": _layer(a),
        "title": a.get("title") or a["rule_id"], "action": _action(a),
        "technique": a["technique"], "technique_name": a.get("technique_name"), "tactic": a["tactic"],
        "stage_no": int(a["stage_no"]),
        "kill_chain_stage": a.get("kill_chain_stage") or attack.kill_chain_stage(a["tactic"]),
        "ts_start": iso_z(a["ts_start"]), "ts_end": iso_z(a["ts_end"]),
        "ts_start_ist": ist(a["ts_start"]), "ts_end_ist": ist(a["ts_end"]),
        "src": a.get("src_ip"), "dst": step_dst(a, hubs),
        "event_count": int(a.get("event_count") or 0), "success": bool(a.get("success")),
        "line_total": int(line_total), "confidence": float(a["confidence"]), "relation": rel,
    }


def build_steps(alerts: Iterable[Dict[str, Any]], evidence: Optional[pl.DataFrame],
                net: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Contract-C steps (contracts.STEP plus `supporting`) numbered 1..N in chain order (module docstring)."""
    hubs = hub_domains(net)
    alerts = list(alerts)
    rules = [a for a in alerts if _layer(a) == "rule"]
    if rules:
        ordered = order_steps(rules)
        attached = attach_supporting(ordered, [a for a in alerts if _layer(a) != "rule"])
    else:
        ordered = order_steps(alerts)
        attached = {}
    flags = ongoing_flags(ordered)
    totals: Dict[str, int] = {}
    if evidence is not None and evidence.height:
        totals = dict(evidence.filter(pl.col("alert_id").is_in([a["alert_id"] for a in alerts]))
                      .group_by("alert_id").len().iter_rows())
    steps = []
    for n, (a, on) in enumerate(zip(ordered, flags), 1):
        steps.append({
            "n": n, "ts_start": iso_z(a["ts_start"]), "ts_end": iso_z(a["ts_end"]),
            "ts_start_ist": ist(a["ts_start"]), "ts_end_ist": ist(a["ts_end"]), "ongoing": bool(on),
            "action": _action(a),
            "rule_id": a["rule_id"], "alert_id": a["alert_id"],
            "technique": a["technique"], "technique_name": a.get("technique_name"), "tactic": a["tactic"],
            "stage_no": int(a["stage_no"]), "kill_chain_stage": a.get("kill_chain_stage") or
            attack.kill_chain_stage(a["tactic"]),
            "src": a.get("src_ip"), "dst": step_dst(a, hubs),
            "event_count": int(a.get("event_count") or 0), "success": bool(a.get("success")),
            "line_sample": evidence_rows(evidence, a["alert_id"]),
            "line_total": int(totals.get(a["alert_id"], 0)),
            "enrichment_flags": [], "confidence": float(a["confidence"]), "layer": _layer(a),
            "supporting": [support_entry(x, rel, totals.get(x["alert_id"], 0), hubs)
                           for x, rel in attached.get(a["alert_id"], [])],
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
    in incident_number order, plus the incident_lines frame (every evidence row of every step and of its
    supporting alerts, which carry the parent step's number)."""
    from .path import path_graph

    A = {r["alert_id"]: r for r in alerts.iter_rows(named=True)}
    ev = evidence.filter(pl.col("alert_id").is_in(members["alert_id"].unique().to_list()))
    by_alert = {k[0]: g for k, g in ev.partition_by("alert_id", as_dict=True).items()} if ev.height else {}
    out, step_rows = [], []
    for inc in incidents.sort("incident_number").iter_rows(named=True):
        ids = members.filter(pl.col("incident_id") == inc["incident_id"])["alert_id"].to_list()
        sub = pl.concat([by_alert[x] for x in ids if x in by_alert]) if any(x in by_alert for x in ids) else None
        steps = build_steps([A[x] for x in ids], sub, net)
        sup = [x for s in steps for x in s["supporting"]]
        out.append({
            "incident_id": inc["incident_id"], "incident_number": int(inc["incident_number"]),
            "chain_text": chain_text(steps), "chain": steps,
            "gaps": gaps((s["stage_no"] for s in steps), (x["stage_no"] for x in sup)),
            "tactics": _unique([s["tactic"] for s in steps] + [x["tactic"] for x in sup]),
            "techniques": _unique([s["technique"] for s in steps] + [x["technique"] for x in sup]),
            "graph": path_graph(steps, A, net),
        })
        step_rows += [{"incident_id": inc["incident_id"], "incident_number": int(inc["incident_number"]),
                       "step": s["n"], "alert_id": aid}
                      for s in steps for aid in [s["alert_id"]] + [x["alert_id"] for x in s["supporting"]]]
    sm = pl.DataFrame(step_rows, schema={"incident_id": pl.Utf8, "incident_number": pl.Int64, "step": pl.Int64,
                                         "alert_id": pl.Utf8})
    cols = [c for c in ("source", "line", "byte_offset", "ts", "technique", "role") if c in evidence.columns]
    lines = (sm.join(evidence.select("alert_id", *cols), on="alert_id", how="inner")
             .sort("incident_number", "step", "ts", "line"))
    return out, lines
