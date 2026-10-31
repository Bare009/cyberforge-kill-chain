"""The path graph of one incident (docs/build-plan.md P7).

Nodes are external IPs, internal hosts and servers, the firewall, accounts and domains, classified with
config/network.yaml. Node ids are the raw entity values (the API matches entities on them). Every step
draws one main directed edge labelled "{n}. {rule words} x{event_count}"; a step with a user goes
source -> user -> target. Built with NetworkX and exported as {nodes, edges}.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

import networkx as nx

from ..correlate.entities import classify_ip
from .chain import hub_domains

INTERNET_IMPORTANCE = 0.25
ACCOUNT_IMPORTANCE = 0.5
UNKNOWN_IMPORTANCE = 0.5
FIREWALL_ROLES = ("firewall-management", "firewall-public-ip")
LABELS = {"web-portal": "portal ({v})", "firewall-management": "firewall ({v})",
          "firewall-public-ip": "firewall public IP ({v})"}


def _importance(value: str, net: Dict[str, Any]) -> Optional[float]:
    try:
        ip = int(ipaddress.ip_network(str(value).strip(), strict=False).network_address)
    except ValueError:
        return None
    for z in net["zones"]:
        if z["_lo"] <= ip <= z["_hi"]:
            return float(z["importance"])
    return None


def node_for(value: str, kind: str, net: Dict[str, Any]) -> Dict[str, Any]:
    """Contract-C node for an entity. kind: 'ip', 'host', 'user' or 'domain'."""
    v = str(value)
    if kind == "user":
        return {"id": v, "label": v, "kind": "account", "zone": "unknown", "importance": ACCOUNT_IMPORTANCE}
    if kind == "domain":
        zone = "unknown" if v.lower().endswith(".local") else "internet"
        return {"id": v, "label": v, "kind": "domain", "zone": zone, "importance": INTERNET_IMPORTANCE}
    internal, zone, role = classify_ip(v, net)
    if internal is None:          # a host name that is not an IP
        return {"id": v, "label": v, "kind": "internal_host", "zone": "unknown", "importance": UNKNOWN_IMPORTANCE}
    label = LABELS.get(role, "{v}").format(v=v)
    if role in FIREWALL_ROLES:
        return {"id": v, "label": label, "kind": "firewall", "zone": zone,
                "importance": _importance(v, net) or 1.0}
    if zone == "internet" or not internal:
        return {"id": v, "label": label, "kind": "external_ip", "zone": "internet",
                "importance": INTERNET_IMPORTANCE}
    return {"id": v, "label": label, "kind": "server" if zone in ("server", "dmz") else "internal_host",
            "zone": zone, "importance": _importance(v, net) or UNKNOWN_IMPORTANCE}


def rule_words(rule_id: str) -> str:
    """'R16-web-sql-injection' -> 'web sql injection'."""
    head, _, rest = str(rule_id).partition("-")
    return (rest or head).replace("-", " ")


def path_graph(steps: List[Dict[str, Any]], alerts_by_id: Dict[str, Dict[str, Any]],
               net: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    hubs = hub_domains(net)
    g = nx.MultiDiGraph()
    order = 0

    def node(value: str, kind: str) -> str:
        if value not in g:
            d = node_for(value, kind, net)
            g.add_node(d.pop("id"), **d)
        return value

    def edge(src: str, dst: str, s: Dict[str, Any], label: str) -> None:
        nonlocal order
        g.add_edge(src, dst, step=s["n"], technique=s["technique"], tactic=s["tactic"], label=label,
                   kind="step", _i=order)
        order += 1

    for s in steps:
        a = alerts_by_id.get(s["alert_id"], {})
        n = s["n"]
        if a.get("src_ip"):
            src = node(a["src_ip"], "ip")
        else:
            cnt = a.get("src_count")
            src = f"sources of step {n}"
            if src not in g:
                g.add_node(src, label=f"{cnt:,} sources" if cnt else "many sources", kind="external_ip",
                           zone="internet", importance=INTERNET_IMPORTANCE)
        dom = a.get("domain")
        dom = dom if dom and str(dom).strip().lower() not in hubs else None
        if a.get("dst_ip"):
            dst = node(a["dst_ip"], "ip")
        elif dom:
            dst = node(dom, "domain")
        elif a.get("host"):
            dst = node(a["host"], "host")
        else:
            dst = None
        main = f"{n}. {rule_words(s['rule_id'])} x{s['event_count']}"
        user = a.get("user")
        if user:
            u = node(user, "user")
            if dst is None:
                edge(src, u, s, main)
            else:
                edge(src, u, s, f"{n}. signs in as {user}")
                edge(u, dst, s, main)
        elif dst is not None:
            edge(src, dst, s, main)
        if dom and dom != dst:
            edge(src, node(dom, "domain"), s, f"{n}. {dom}")

    nodes = [{"id": k, **d} for k, d in g.nodes(data=True)]
    edges = sorted(({"source": u, "target": v, **d} for u, v, d in g.edges(data=True)),
                   key=lambda e: (e["step"], e["_i"]))
    for e in edges:
        del e["_i"]
    return {"nodes": nodes, "edges": edges}
