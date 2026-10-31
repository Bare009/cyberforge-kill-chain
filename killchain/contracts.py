"""Contracts B (alerts) and C (incidents): the files the two tracks exchange.

Frozen on day 1. `docs/contracts.md` describes the same fields in prose. A
change here must be agreed by both tracks and made in the same commit as the
doc and `examples/sample-run/`.

Use `validate_bundle()` in tests and before writing a run, so both the
pipeline (track A) and the API (track B) can rely on the shapes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

TACTICS = (
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
)
KILL_CHAIN_STAGES = (
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation",
    "Command and Control", "Actions on Objectives",
)
LAYERS = ("rule", "anomaly")
ZONES = ("internet", "dmz", "server", "desktop", "iot", "lan", "mgmt", "public", "unknown")
NODE_KINDS = ("external_ip", "internal_host", "server", "firewall", "account", "domain")
EDGE_KINDS = ("step", "reach_observed", "reach_inferred")
REACH_KINDS = ("observed", "inferred")
VERDICTS = ("known-malicious", "suspicious", "no-reports", "unknown")
TRIAGE = ("looks_real", "likely_noise")
REPORT_SOURCES = ("ai", "template")
RISK_BANDS = ("critical", "high", "medium", "low")
RISK_PARTS = ("severity", "stage", "breadth", "success", "asset", "reach", "threat_intel")

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")       # UTC, ISO 8601
TS_IST_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")                 # display time, IST

S, I, F, B, L, D = str, int, float, bool, list, dict
NUM = (int, float)

# name -> (type, nullable). Types are Python types after JSON loading.
ALERT: Dict[str, Tuple[Any, bool]] = {
    "alert_id": (S, False), "rule_id": (S, False), "layer": (S, False), "title": (S, False),
    "technique": (S, False), "alt_techniques": (L, False), "technique_name": (S, True),
    "tactic": (S, False), "stage_no": (I, False), "kill_chain_stage": (S, False),
    "severity": (I, False), "confidence": (NUM, False),
    "ts_start": (S, False), "ts_end": (S, False),
    "src_ip": (S, True), "dst_ip": (S, True), "host": (S, True), "user": (S, True),
    "domain": (S, True), "url": (S, True),
    "event_count": (I, False), "blocked_share": (NUM, False), "success": (B, False),
    "summary": (S, False), "action_text": (S, False), "incident_number": (I, True),
}
EVIDENCE: Dict[str, Tuple[Any, bool]] = {
    "line": (I, False), "byte_offset": (I, False), "source": (S, False), "ts": (S, False),
}
STEP: Dict[str, Tuple[Any, bool]] = {
    "n": (I, False), "ts_start": (S, False), "ts_end": (S, False),
    "ts_start_ist": (S, False), "ts_end_ist": (S, False), "ongoing": (B, False),
    "action": (S, False), "rule_id": (S, False), "alert_id": (S, False),
    "technique": (S, False), "technique_name": (S, True), "tactic": (S, False),
    "stage_no": (I, False), "kill_chain_stage": (S, False), "src": (S, True), "dst": (S, True),
    "event_count": (I, False), "success": (B, False), "line_sample": (L, False), "line_total": (I, False),
    "enrichment_flags": (L, False), "confidence": (NUM, False), "layer": (S, False),
}
NODE: Dict[str, Tuple[Any, bool]] = {
    "id": (S, False), "label": (S, False), "kind": (S, False), "zone": (S, False), "importance": (NUM, False),
}
EDGE: Dict[str, Tuple[Any, bool]] = {
    "source": (S, False), "target": (S, False), "step": (I, True), "technique": (S, True),
    "tactic": (S, True), "label": (S, False), "kind": (S, False),
}
REACH: Dict[str, Tuple[Any, bool]] = {
    "host": (S, False), "zone": (S, False), "hop": (I, False), "kind": (S, False), "via": (L, False),
}
INCIDENT: Dict[str, Tuple[Any, bool]] = {
    "incident_number": (I, False), "incident_id": (S, False), "title": (S, False),
    "risk_score": (NUM, False), "risk_band": (S, False), "risk_parts": (D, False), "severity": (I, False),
    "ts_start": (S, False), "ts_end": (S, False), "ts_start_ist": (S, False), "ts_end_ist": (S, False),
    "merged": (D, False), "entities": (D, False), "tactics": (L, False), "techniques": (L, False),
    "chain_text": (S, False), "chain": (L, False), "gaps": (L, False), "graph": (D, False),
    "enrichment": (D, False), "next": (D, False), "report": (D, False), "report_source": (S, False),
    "layers": (L, False),
}
INDEX_ROW: Dict[str, Tuple[Any, bool]] = {
    "incident_number": (I, False), "incident_id": (S, False), "title": (S, False),
    "risk_score": (NUM, False), "risk_band": (S, False), "severity": (I, False),
    "ts_start": (S, False), "ts_end": (S, False), "ts_start_ist": (S, False), "ts_end_ist": (S, False),
    "merged": (D, False), "tactics": (L, False), "techniques": (L, False),
    "triage_verdict": (S, True), "ti_verdict": (S, True),
}


def _check(obj: Any, spec: Dict[str, Tuple[Any, bool]], where: str, errors: List[str]) -> None:
    if not isinstance(obj, dict):
        errors.append(f"{where}: expected an object")
        return
    for name, (typ, nullable) in spec.items():
        if name not in obj:
            errors.append(f"{where}.{name}: missing")
            continue
        v = obj[name]
        if v is None:
            if not nullable:
                errors.append(f"{where}.{name}: must not be null")
            continue
        if typ is I and isinstance(v, bool) or not isinstance(v, typ):
            errors.append(f"{where}.{name}: expected {getattr(typ, '__name__', typ)}, got {type(v).__name__}")


def _enum(v: Any, allowed: Iterable[str], where: str, errors: List[str]) -> None:
    if v is not None and v not in allowed:
        errors.append(f"{where}: {v!r} is not one of {list(allowed)}")


def _ts(v: Any, where: str, errors: List[str], ist: bool = False) -> None:
    rx = TS_IST_RE if ist else TS_RE
    if isinstance(v, str) and not rx.match(v):
        errors.append(f"{where}: {v!r} is not {'YYYY-MM-DD HH:MM:SS (IST)' if ist else 'ISO 8601 UTC ending in Z'}")


def validate_alert(a: Dict[str, Any], where: str = "alert") -> List[str]:
    e: List[str] = []
    _check(a, ALERT, where, e)
    if e:
        return e
    _enum(a["layer"], LAYERS, f"{where}.layer", e)
    _enum(a["tactic"], TACTICS, f"{where}.tactic", e)
    _enum(a["kill_chain_stage"], KILL_CHAIN_STAGES, f"{where}.kill_chain_stage", e)
    if not TECHNIQUE_RE.match(a["technique"]) and a["technique"] != "unknown":
        e.append(f"{where}.technique: {a['technique']!r} is not a technique id")
    for t in a["alt_techniques"]:
        if not isinstance(t, str) or not TECHNIQUE_RE.match(t):
            e.append(f"{where}.alt_techniques: {t!r} is not a technique id")
    if not 1 <= a["stage_no"] <= 14:
        e.append(f"{where}.stage_no: must be 1-14")
    if not 1 <= a["severity"] <= 5:
        e.append(f"{where}.severity: must be 1-5")
    for k in ("confidence", "blocked_share"):
        if not 0 <= a[k] <= 1:
            e.append(f"{where}.{k}: must be 0-1")
    _ts(a["ts_start"], f"{where}.ts_start", e)
    _ts(a["ts_end"], f"{where}.ts_end", e)
    return e


def validate_incident(inc: Dict[str, Any], where: str = "incident") -> List[str]:
    e: List[str] = []
    _check(inc, INCIDENT, where, e)
    if e:
        return e
    _enum(inc["risk_band"], RISK_BANDS, f"{where}.risk_band", e)
    _enum(inc["report_source"], REPORT_SOURCES, f"{where}.report_source", e)
    if not 0 <= inc["risk_score"] <= 100:
        e.append(f"{where}.risk_score: must be 0-100")
    missing = set(RISK_PARTS) - set(inc["risk_parts"])
    if missing:
        e.append(f"{where}.risk_parts: missing {sorted(missing)}")
    for k, p in inc["risk_parts"].items():
        if not (isinstance(p, dict) and all(isinstance(p.get(x), NUM) for x in ("value", "weight", "points"))):
            e.append(f"{where}.risk_parts.{k}: needs numbers value, weight, points")
        elif not 0 <= p["value"] <= 1:
            e.append(f"{where}.risk_parts.{k}.value: must be 0-1")
    if all(isinstance(p, dict) and isinstance(p.get("points"), NUM) for p in inc["risk_parts"].values()):
        total = sum(p["points"] for p in inc["risk_parts"].values())
        if abs(total - inc["risk_score"]) > 0.5:
            e.append(f"{where}.risk_score: {inc['risk_score']} is not the sum of risk_parts points ({total:.1f})")
    for k in ("alerts", "events"):
        if not isinstance(inc["merged"].get(k), int):
            e.append(f"{where}.merged.{k}: expected int")
    for k in ("ips", "hosts", "users", "domains"):
        if not isinstance(inc["entities"].get(k), list):
            e.append(f"{where}.entities.{k}: expected a list")
    for k in ("ts_start", "ts_end"):
        _ts(inc[k], f"{where}.{k}", e)
    for k in ("ts_start_ist", "ts_end_ist"):
        _ts(inc[k], f"{where}.{k}", e, ist=True)
    for i, s in enumerate(inc["chain"]):
        w = f"{where}.chain[{i}]"
        _check(s, STEP, w, e)
        if isinstance(s, dict) and "n" in s and s["n"] != i + 1:
            e.append(f"{w}.n: steps must be numbered 1..N in order (got {s['n']})")
        if isinstance(s, dict):
            _enum(s.get("tactic"), TACTICS, f"{w}.tactic", e)
            _enum(s.get("layer"), LAYERS, f"{w}.layer", e)
            for j, ln in enumerate(s.get("line_sample") or []):
                _check(ln, EVIDENCE, f"{w}.line_sample[{j}]", e)
    starts = [s.get("ts_start") for s in inc["chain"] if isinstance(s, dict)]
    if starts != sorted(starts):
        e.append(f"{where}.chain: ts_start must not decrease")
    nodes = inc["graph"].get("nodes")
    edges = inc["graph"].get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        e.append(f"{where}.graph: needs lists 'nodes' and 'edges'")
    else:
        ids = set()
        for i, n in enumerate(nodes):
            _check(n, NODE, f"{where}.graph.nodes[{i}]", e)
            if isinstance(n, dict):
                ids.add(n.get("id"))
                _enum(n.get("kind"), NODE_KINDS, f"{where}.graph.nodes[{i}].kind", e)
                _enum(n.get("zone"), ZONES, f"{where}.graph.nodes[{i}].zone", e)
        for i, ed in enumerate(edges):
            _check(ed, EDGE, f"{where}.graph.edges[{i}]", e)
            if isinstance(ed, dict):
                _enum(ed.get("kind"), EDGE_KINDS, f"{where}.graph.edges[{i}].kind", e)
                for end in ("source", "target"):
                    if ed.get(end) not in ids:
                        e.append(f"{where}.graph.edges[{i}].{end}: {ed.get(end)!r} is not a node id")
    nxt = inc["next"]
    if not isinstance(nxt.get("reachable"), list) or not isinstance(nxt.get("sentence"), str):
        e.append(f"{where}.next: needs 'reachable' (list) and 'sentence' (string)")
    else:
        for i, r in enumerate(nxt["reachable"]):
            _check(r, REACH, f"{where}.next.reachable[{i}]", e)
            if isinstance(r, dict):
                _enum(r.get("kind"), REACH_KINDS, f"{where}.next.reachable[{i}].kind", e)
    for value, ent in inc["enrichment"].items():
        if isinstance(ent, dict):
            _enum(ent.get("verdict"), VERDICTS, f"{where}.enrichment[{value}].verdict", e)
    rep = inc["report"]
    if not isinstance(rep.get("markdown"), str):
        e.append(f"{where}.report.markdown: expected a string")
    _enum(rep.get("source"), REPORT_SOURCES, f"{where}.report.source", e)
    tri = rep.get("triage")
    if tri is not None:
        _enum(tri.get("verdict"), TRIAGE, f"{where}.report.triage.verdict", e)
    return e


def validate_bundle(incident: Dict[str, Any], index: Dict[str, Any], alerts: List[Dict[str, Any]]) -> List[str]:
    """Check one incident, the run index and the alert list against the contracts and each other."""
    e = validate_incident(incident, f"incidents/{incident.get('incident_number')}.json")
    for i, a in enumerate(alerts):
        e += validate_alert(a, f"alerts.json[{i}]")
    rows = index.get("incidents")
    if not isinstance(rows, list):
        return e + ["index.json: needs a list 'incidents'"]
    for i, r in enumerate(rows):
        _check(r, INDEX_ROW, f"index.json.incidents[{i}]", e)
    nums = [r.get("incident_number") for r in rows]
    if incident.get("incident_number") not in nums:
        e.append("index.json: does not list the incident")
    alert_ids = {a.get("alert_id") for a in alerts}
    for s in incident.get("chain") or []:
        if isinstance(s, dict) and s.get("alert_id") not in alert_ids:
            e.append(f"chain step {s.get('n')}: alert_id {s.get('alert_id')!r} is not in alerts.json")
    return e
