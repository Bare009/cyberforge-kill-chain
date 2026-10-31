"""Reach next (docs/build-plan.md P8): where the attacker can go from what the incident shows they control.

1. Footholds: internal targets of successful steps (not reconnaissance, discovery or impact: a scanned or
   flooded host is not taken), internal sources of steps (internal attacker or infected host), and accounts
   with a successful admin login among the incident's evidence lines.
2. Breadth-first search over the access graph (access.py) plus inferred zone_neighbour edges from server
   and DMZ footholds to the other server and DMZ hosts in their /24, up to max_hops. Nodes already in the
   incident are traversed but not reported, except a firewall management address reached over a
   `controls` edge: the step shows the login, and reach next states what that login gives.
3. Rank = importance(target) x strength(best edge in) x hop factor x ln(1 + max(count, 1)). The max keeps
   inferred edges (count 0) from ranking 0.
4. One sentence from a template; likely_tactics = the next tactics after the furthest stage reached.

reach_next() also merges the reported hosts into the incident's path graph as reach nodes and edges.
"""

from __future__ import annotations

import copy
import math
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx
import polars as pl

from .. import attack
from ..correlate.entities import classify_ip
from .access import NOT_INTERNAL_ZONES
from .chain import NO_GAP, iso_z
from .path import node_for

FIREWALL_MGMT = "firewall-management"
EMPTY = "No internal reach observed in the logs: {reason}."


# ── helpers ──────────────────────────────────────────────────────────────────

def _key(v: Any) -> str:
    return str(v).strip().lower()


def is_internal(v: Optional[str], net: Dict[str, Any]) -> bool:
    if not v:
        return False
    internal, zone, _ = classify_ip(v, net)
    return bool(internal) and zone not in NOT_INTERNAL_ZONES


def _is_ip(v: str, net: Dict[str, Any]) -> bool:
    return classify_ip(v, net)[0] is not None


def _node(v: str, net: Dict[str, Any]) -> Dict[str, Any]:
    return node_for(v, "ip" if _is_ip(v, net) else "user", net)


def _net24(ip: str) -> Optional[str]:
    parts = str(ip).split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else None


def _names(xs: List[str], cap: int = 3) -> str:
    if len(xs) <= 1:
        return "".join(xs)
    if len(xs) <= cap:
        return ", ".join(xs[:-1]) + " and " + xs[-1]
    return ", ".join(xs[:cap]) + f" and {len(xs) - cap} more"


def _unique(xs: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    for x in xs:
        if x and x not in out:
            out.append(x)
    return out


def edge_label(kind: str, count: int, ports: List[int], zone: str) -> str:
    p = "/".join(str(x) for x in (ports or [])[:3])
    if kind == "controls":
        return f"admin login x{count}"
    if kind == "admin_port":
        return f"admin port {p} x{count}"
    if kind == "allowed_flow":
        return f"allowed port {p} x{count}"
    return f"same {zone} subnet (inferred)"


# ── footholds, touched, likely tactics ───────────────────────────────────────

def footholds(chain: List[Dict[str, Any]], login_accounts: Iterable[str], net: Dict[str, Any],
              settings: Dict[str, Any]) -> List[str]:
    skip = set(settings["foothold_skip_tactics"])
    dst = [s["dst"] for s in chain if s.get("success") and s["tactic"] not in skip and is_internal(s.get("dst"), net)]
    src = [s["src"] for s in chain if is_internal(s.get("src"), net)]
    return _unique(dst + src + list(login_accounts))


def touched(incident: Dict[str, Any], line_rows: Iterable[Dict[str, Any]]) -> Set[str]:
    """Lower-cased values already part of the incident: its entities, step ends and evidence-line entities."""
    ents = incident.get("entities") or {}
    out = {_key(v) for k in ("ips", "hosts", "users", "domains") for v in ents.get(k) or []}
    out |= {_key(s[k]) for s in incident.get("chain") or [] for k in ("src", "dst") if s.get(k)}
    out |= {_key(r[k]) for r in line_rows for k in ("src_ip", "dst_ip", "user") if r.get(k)}
    return out


def likely_tactics(stage_nos: Iterable[int], n: int = 3) -> List[str]:
    seen = [int(s) for s in stage_nos]
    if not seen:
        return []
    hi = max(seen)
    return [t["shortname"] for t in attack.all_tactics() if t["stage_no"] > hi and t["shortname"] not in NO_GAP][:n]


# ── search ───────────────────────────────────────────────────────────────────

def access_digraph(edges: pl.DataFrame) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for r in edges.iter_rows(named=True):
        g.add_edge(r["src"], r["dst"], key=r["kind"], kind=r["kind"], strength=float(r["strength"]),
                   count=int(r["count"]), ports=list(r["ports"] or []), lines=list(r["lines"] or []))
    return g


def _evidence(lines: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"source": x["source"], "line": int(x["line"]), "byte_offset": int(x["byte_offset"]), "ts": iso_z(x["ts"])}
            for x in lines]


def reach_next(incident: Dict[str, Any], chain_graph: Dict[str, Any], edges: Any, hosts: pl.DataFrame,
               line_rows: List[Dict[str, Any]], net: Dict[str, Any],
               settings: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """(next, merged graph, footholds) for one incident.
    edges: access_graph frame or a prebuilt access_digraph(); hosts: access_hosts frame;
    line_rows: the incident's evidence lines joined to events (src_ip, dst_ip, user, log_desc)."""
    st = settings["strengths"]
    chain = incident["chain"]
    logins = set(settings["login_success_desc"])
    accounts = sorted({r["user"] for r in line_rows if r.get("user") and r.get("log_desc") in logins})
    fh = footholds(chain, accounts, net, settings)
    seen = touched(incident, line_rows)
    tactics = likely_tactics((s["stage_no"] for s in chain), settings.get("likely_next", 3))

    g = (edges if isinstance(edges, nx.MultiDiGraph) else access_digraph(edges)).copy()
    host_rows = {r["ip"]: r for r in hosts.iter_rows(named=True)}
    zones = set(settings["neighbour_zones"])
    by_net: Dict[str, List[str]] = {}
    for r in host_rows.values():
        if r["zone"] in zones and r["net24"]:
            by_net.setdefault(r["net24"], []).append(r["ip"])
    for f in fh:
        g.add_node(f)
        if not _is_ip(f, net) or classify_ip(f, net)[1] not in zones:
            continue
        for h in by_net.get(_net24(f), []):
            if h != f and not g.has_edge(f, h, key="zone_neighbour"):
                g.add_edge(f, h, key="zone_neighbour", kind="zone_neighbour", strength=float(st["zone_neighbour"]),
                           count=0, ports=[], lines=[])

    hop: Dict[str, int] = {}
    for i, layer in enumerate(nx.bfs_layers(g, fh) if fh else []):
        if i > settings["max_hops"]:
            break
        for v in layer:
            hop[v] = i
    fset = set(fh)

    def vias(v: str, h: int) -> List[Dict[str, Any]]:
        out = [{"from": u, **d} for u, _, d in g.in_edges(v, data=True) if hop.get(u) == h - 1]
        return sorted(out, key=lambda e: (-e["strength"], -e["count"], e["from"]))

    observed: Dict[str, bool] = {f: True for f in fh}
    found: Dict[str, Dict[str, Any]] = {}
    for v, h in sorted(hop.items(), key=lambda x: (x[1], x[0])):
        if h == 0:
            continue
        vs = vias(v, h)
        best = vs[0]
        observed[v] = best["kind"] != "zone_neighbour" and (h == 1 or observed.get(best["from"], False))
        role = classify_ip(v, net)[2] if _is_ip(v, net) else None
        if v in fset or (_key(v) in seen and not (best["kind"] == "controls" and role == FIREWALL_MGMT)):
            continue
        found[v] = {"hop": h, "via": vs, "observed": observed[v]}
    # the firewall an incident account logged in to is reported even when it is a foothold itself
    for a in fh:
        if not g.has_node(a) or _is_ip(a, net):
            continue
        for _, fw, d in g.out_edges(a, data=True):
            if d["kind"] == "controls" and fw not in found and _is_ip(fw, net) and classify_ip(fw, net)[2] == FIREWALL_MGMT:
                vs = sorted(({"from": u, **e} for u, _, e in g.in_edges(fw, data=True)
                             if u in fset and e["kind"] == "controls"), key=lambda e: (-e["count"], e["from"]))
                found[fw] = {"hop": 1, "via": vs, "observed": True}

    rows = []
    for v, e in found.items():
        best = e["via"][0]
        hr = host_rows.get(v) or {}
        node = _node(v, net)
        imp = float(hr.get("importance") if hr.get("importance") is not None else node["importance"])
        rank = imp * best["strength"] * settings["hop_factor"][e["hop"]] * math.log(1 + max(best["count"], 1))
        rows.append({**e, "host": v, "zone": node["zone"], "rank": rank, "events": int(hr.get("events") or 0),
                     "best": best, "label": node["label"]})
    rows.sort(key=lambda r: (-r["rank"], r["hop"], not r["observed"], -r["events"], r["host"]))
    kept = rows[: settings["max_reachable"]]
    reachable = [{"host": r["host"], "zone": r["zone"], "hop": r["hop"],
                  "kind": "observed" if r["observed"] else "inferred",
                  "via": [{"from": x["from"], "edge": x["kind"], "count": x["count"], "lines": _evidence(x["lines"])}
                          for x in r["via"][: settings["max_via"]]]} for r in kept]

    labels = [_node(f, net)["label"] for f in fh]
    obs_inside = any(h > 0 and observed.get(v) and v not in found for v, h in hop.items())
    sentence = _sentence(rows, labels, fh, hop, net, obs_inside)
    nxt = {"reachable": reachable, "sentence": sentence, "likely_tactics": tactics}
    return nxt, merge_graph(chain_graph, kept, net, settings), fh


def _sentence(rows: List[Dict[str, Any]], labels: List[str], fh: List[str], hop: Dict[str, int],
              net: Dict[str, Any], obs_inside: bool = False) -> str:
    """obs_inside: connections were seen from the footholds, but only to hosts already in the incident."""
    fl = _names(labels)
    if not rows:
        if not fh:
            reason = "no successful step reached an internal host or signed in to an account"
        elif not any(h > 0 for h in hop.values()):
            reason = (f"{fl} opened no allowed sessions to other internal hosts, and inferred neighbours are only "
                      f"drawn for server and DMZ subnets")
        else:
            reason = f"every host reachable from {fl} is already part of this incident"
        return EMPTY.format(reason=reason)
    ctl = [r for r in rows if r["best"]["kind"] == "controls" and _is_ip(r["host"], net)
           and classify_ip(r["host"], net)[2] == FIREWALL_MGMT]
    rest = [r for r in rows if r not in ctl]
    obs = [r for r in rest if r["observed"]]
    inf = [r for r in rest if not r["observed"]]
    parts = []
    for r in ctl:
        accts = _unique(x["from"] for x in r["via"] if x["kind"] == "controls")
        parts.append(f"{_names(accts)} logged in to the firewall management interface {r['label']}, "
                     f"which controls every zone.")
    if obs:
        k, top = len(obs), obs[0]
        b = top["best"]
        words = edge_label(b["kind"], b["count"], b["ports"], top["zone"])
        parts.append(f"From {fl}, {k} internal host{'s were' if k != 1 else ' was'} reached over connections "
                     f"seen in the logs; the top one is {top['label']} ({words}).")
        if inf:
            parts.append(f"{len(inf)} more {'are' if len(inf) != 1 else 'is'} inferred from the subnet.")
    elif inf:
        m, top = len(inf), inf[0]
        zs = [r["zone"] for r in inf]
        zone = max(_unique(zs), key=zs.count)          # most common zone; ties go to the best-ranked host
        head = (f"Every connection seen from {fl} goes to hosts already in this incident" if obs_inside
                else f"No internal connections from {fl} were observed")
        parts.append(f"{head}; {m} host{'s' if m != 1 else ''} in the "
                     f"same {zone} subnet (e.g. {top['label']}) "
                     f"{'are the likely next targets' if m != 1 else 'is the likely next target'} (inferred).")
    return " ".join(parts)


# ── graph merge ──────────────────────────────────────────────────────────────

def merge_graph(chain_graph: Dict[str, Any], kept: List[Dict[str, Any]], net: Dict[str, Any],
                settings: Dict[str, Any]) -> Dict[str, Any]:
    """The P7 path graph plus reach nodes (with `reach`) and one reach edge per via entry."""
    g = copy.deepcopy(chain_graph)
    ids = {n["id"] for n in g["nodes"]}
    for r in kept:
        if r["host"] not in ids:
            g["nodes"].append({**_node(r["host"], net), "reach": "observed" if r["observed"] else "inferred"})
            ids.add(r["host"])
    for r in kept:
        for x in r["via"][: settings["max_via"]]:
            if x["from"] not in ids:
                g["nodes"].append(_node(x["from"], net))
                ids.add(x["from"])
            g["edges"].append({"source": x["from"], "target": r["host"], "step": None, "technique": None,
                               "tactic": None, "label": edge_label(x["kind"], x["count"], x["ports"], r["zone"]),
                               "kind": "reach_inferred" if x["kind"] == "zone_neighbour" else "reach_observed"})
    return g
