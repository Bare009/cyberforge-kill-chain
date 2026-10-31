"""Everything the run knows about one entity: an IP, host, account or domain (P11: GET /entities/{value}).

Used by the entity drawer in the UI: click a node in the attack path graph and
see every incident and alert involving that value, its role in each incident,
and its threat-intel result.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from .bundle import RunBundle

MAX_ALERTS = 200
_ALERT_FIELDS = ("src_ip", "dst_ip", "host", "user", "domain")


def guess_kind(value: str) -> str:
    """ip | domain | account, from the value's shape (used when no graph node says otherwise)."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    return "domain" if "." in value and " " not in value else "account"


def _roles_in_incident(inc: Dict[str, Any], value: str) -> List[str]:
    roles = set()
    for s in inc.get("chain") or []:
        if s.get("src") == value:
            roles.add("source")
        if s.get("dst") == value:
            roles.add("target")
    if any(r.get("host") == value for r in (inc.get("next") or {}).get("reachable") or []):
        roles.add("reachable next")
    ents = inc.get("entities") or {}
    if value in (ents.get("users") or []):
        roles.add("account")
    if value in (ents.get("domains") or []):
        roles.add("domain")
    return sorted(roles)


def _mentions(inc: Dict[str, Any], value: str) -> bool:
    ents = inc.get("entities") or {}
    if any(value in (ents.get(k) or []) for k in ("ips", "hosts", "users", "domains")):
        return True
    if any(n.get("id") == value for n in (inc.get("graph") or {}).get("nodes") or []):
        return True
    return any(s.get("src") == value or s.get("dst") == value for s in inc.get("chain") or [])


def entity_view(b: RunBundle, value: str) -> Optional[Dict[str, Any]]:
    """The entity's incidents, alerts, graph node and threat intel; None if the run never mentions it."""
    value = value.strip()
    node: Optional[Dict[str, Any]] = None
    enrichment: Optional[Dict[str, Any]] = None
    incidents = []
    by_number = {r["incident_number"]: r for r in b.index_rows}

    for n in sorted(b.incidents):
        inc = b.incidents[n]
        if not _mentions(inc, value):
            continue
        for g in (inc.get("graph") or {}).get("nodes") or []:
            if g.get("id") == value and (node is None or "reach" in node):
                node = g                       # prefer a node seen in a step over a reach-only node
        if enrichment is None and value in (inc.get("enrichment") or {}):
            enrichment = inc["enrichment"][value]
        row = by_number.get(n) or {}
        incidents.append({
            "incident_number": n,
            "title": inc.get("title"),
            "risk_score": inc.get("risk_score"),
            "risk_band": inc.get("risk_band"),
            "ts_start_ist": inc.get("ts_start_ist"),
            "tactics": row.get("tactics") or inc.get("tactics") or [],
            "roles": _roles_in_incident(inc, value),
            "steps": [s["n"] for s in inc.get("chain") or [] if value in (s.get("src"), s.get("dst"))],
        })

    alerts = []
    total_alerts = 0
    for a in b.alerts:
        fields = [f for f in _ALERT_FIELDS if a.get(f) == value]
        if not fields:
            continue
        total_alerts += 1
        if len(alerts) < MAX_ALERTS:
            alerts.append({
                "alert_id": a.get("alert_id"), "rule_id": a.get("rule_id"), "title": a.get("title"),
                "technique": a.get("technique"), "tactic": a.get("tactic"), "severity": a.get("severity"),
                "ts_start": a.get("ts_start"), "event_count": a.get("event_count"), "success": a.get("success"),
                "incident_number": a.get("incident_number"), "as": fields, "summary": a.get("summary"),
            })

    if not incidents and not alerts:
        return None
    alerts.sort(key=lambda a: a.get("ts_start") or "")
    return {
        "value": value,
        "kind": (node or {}).get("kind") or guess_kind(value),
        "label": (node or {}).get("label") or value,
        "zone": (node or {}).get("zone"),
        "importance": (node or {}).get("importance"),
        "enrichment": enrichment,
        "incidents": incidents,
        "alerts": alerts,
        "alerts_total": total_alerts,
    }
