"""The fact sheet an agent sees for one incident (docs/build-plan.md P10b).

Only facts from contract C: the numbered chain, entities, merged counts, threat-intel
verdicts, reach next, risk parts and gaps. No raw log lines; each step lists up to three
evidence line numbers the narrator may cite. Kept small (about 1,200 tokens) so a batch
run fits the free-tier daily token limit.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Dict, List, Set

MAX_LINES_PER_STEP = 3
MAX_SUPPORTING = 3
MAX_REACH = 5


def _is_ip(v: Any) -> bool:
    try:
        ipaddress.ip_address(str(v))
        return True
    except ValueError:
        return False


def fact_sheet(inc: Dict[str, Any]) -> Dict[str, Any]:
    ents = inc.get("entities") or {}
    steps = []
    for s in inc.get("chain") or []:
        step = {
            "n": s["n"],
            "time_ist": s.get("ts_start_ist"),
            "until_ist": s.get("ts_end_ist") if s.get("ongoing") else None,
            "tactic": s.get("tactic"),
            "technique": s.get("technique"),
            "technique_name": s.get("technique_name"),
            "src": s.get("src"),
            "dst": s.get("dst"),
            "what": s.get("action"),
            "events": s.get("event_count"),
            "got_through": bool(s.get("success")),
            "evidence_lines": [ln["line"] for ln in (s.get("line_sample") or [])[:MAX_LINES_PER_STEP]],
            "evidence_total": s.get("line_total"),
        }
        flags = s.get("enrichment_flags") or []
        if flags:
            step["threat_intel_flags"] = flags[:3]
        sup = s.get("supporting") or []
        if sup:
            step["also_seen"] = [f"{x.get('action')} ({x.get('relation')} this step)" for x in sup[:MAX_SUPPORTING]]
        steps.append({k: v for k, v in step.items() if v is not None})

    nxt = inc.get("next") or {}
    reach = [{"host": r.get("host"), "zone": r.get("zone"), "hop": r.get("hop"), "kind": r.get("kind")}
             for r in (nxt.get("reachable") or [])[:MAX_REACH]]
    ti = {v: e.get("verdict") for v, e in (inc.get("enrichment") or {}).items()
          if e.get("verdict") in ("known-malicious", "suspicious")}
    parts = inc.get("risk_parts") or {}
    scored = float(inc.get("risk_score") or 0) > 0
    sheet: Dict[str, Any] = {
        "incident": inc["incident_number"],
        "title": inc.get("title"),
        "severity_1_to_5": inc.get("severity"),
        "risk": ({"score": inc.get("risk_score"), "band": inc.get("risk_band"),
                  "parts": {k: p.get("points") for k, p in parts.items() if p.get("points")}}
                 if scored else "not scored yet"),
        "start_ist": inc.get("ts_start_ist"),
        "end_ist": inc.get("ts_end_ist"),
        "merged": inc.get("merged"),
        "entities": {k: list(ents.get(k) or []) for k in ("ips", "hosts", "users", "domains") if ents.get(k)},
        "chain": steps,
        "gaps": list(inc.get("gaps") or []),
        "reach_next": {"sentence": nxt.get("sentence"), "hosts": reach, "likely_tactics": nxt.get("likely_tactics") or []},
        "threat_intel": ti or "no outside reports for these entities",
    }
    return sheet


def facts_hash(sheet: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(sheet, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:16]


def allowed_values(inc: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Every IP, account, domain, technique id and line number the incident's facts contain."""
    ips: Set[str] = set()
    users: Set[str] = set()
    domains: Set[str] = set()
    techniques: Set[str] = set()
    lines: Set[int] = set()
    ents = inc.get("entities") or {}
    for v in (ents.get("ips") or []) + (ents.get("hosts") or []):
        (ips if _is_ip(v) else domains).add(str(v))
    users.update(ents.get("users") or [])
    domains.update(d.lower() for d in ents.get("domains") or [])
    for s in inc.get("chain") or []:
        for v in (s.get("src"), s.get("dst")):
            if v and _is_ip(v):
                ips.add(v)
        if s.get("technique"):
            techniques.add(s["technique"].upper())
        for x in s.get("supporting") or []:
            if x.get("technique"):
                techniques.add(x["technique"].upper())
            for v in (x.get("src"), x.get("dst")):
                if v and _is_ip(v):
                    ips.add(v)
        lines.update(int(ln["line"]) for ln in (s.get("line_sample") or [])[:MAX_LINES_PER_STEP])
    for n in (inc.get("graph") or {}).get("nodes") or []:
        if _is_ip(n.get("id")):
            ips.add(n["id"])
    for r in (inc.get("next") or {}).get("reachable") or []:
        if _is_ip(r.get("host")):
            ips.add(r["host"])
        for via in r.get("via") or []:
            if _is_ip(via.get("from")):
                ips.add(via["from"])
    return {"ips": ips, "users": users, "domains": domains, "techniques": techniques, "lines": lines}


def required_values(inc: Dict[str, Any]) -> Dict[str, Any]:
    """What the narrator must mention: every step number, every chain IP and every account."""
    ips: List[str] = []
    for s in inc.get("chain") or []:
        for v in (s.get("src"), s.get("dst")):
            if v and _is_ip(v) and v not in ips:
                ips.append(v)
    return {"steps": [s["n"] for s in inc.get("chain") or []], "ips": ips,
            "users": list((inc.get("entities") or {}).get("users") or [])}
