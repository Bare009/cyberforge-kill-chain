"""Access graph build, reach next (footholds, ranking, sentence, likely tactics), graph merge and the reach CLI."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import polars as pl
import pytest

from killchain import contracts as C
from killchain import db
from killchain.correlate.entities import classify_ip
from killchain.graph import access
from killchain.graph import incident_files as files
from killchain.graph import reach as rc
from killchain.graph.cli import compute_reach, main as chain_main, reach_main
from killchain.graph.path import node_for

from test_chain import _bundle, _run_folder

ROOT = Path(__file__).resolve().parents[1]
REAL_RUN = ROOT / "data" / "runs" / "firex-10G"
NET = db.load_network()
S = access.load_settings()
T0 = datetime(2026, 10, 27, 4, 0, tzinfo=timezone.utc)


# ── access graph ─────────────────────────────────────────────────────────────

def _side(ip):
    internal, zone, role = classify_ip(ip, NET)
    if internal is None:
        return None, None, None, None, None
    imp = node_for(ip, "ip", NET)["importance"] if zone not in ("internet",) else 0.25
    parts = ip.split(".")
    return internal, zone, role, imp, ".".join(parts[:3]) + ".0/24"


def ev(line, src, dst, port=None, action="accept", log_type="traffic", log_desc=None, user=None, valid=True,
       source="x.log", minutes=None):
    s, d = _side(src), _side(dst)
    return {"ts_valid": valid, "log_type": log_type, "log_desc": log_desc, "action": action, "user": user,
            "src_ip": src, "dst_ip": dst, "dst_port": port, "src_internal": s[0], "dst_internal": d[0],
            "src_zone": s[1], "dst_zone": d[1], "src_role": s[2], "dst_role": d[2], "src_importance": s[3],
            "dst_importance": d[3], "src_net24": s[4], "dst_net24": d[4], "source": source, "line": line,
            "byte_offset": line * 100, "ts": T0 + timedelta(minutes=line if minutes is None else minutes)}


EV_SCHEMA = {"ts_valid": pl.Boolean, "log_type": pl.Utf8, "log_desc": pl.Utf8, "action": pl.Utf8, "user": pl.Utf8,
             "src_ip": pl.Utf8, "dst_ip": pl.Utf8, "dst_port": pl.Int64, "src_internal": pl.Boolean,
             "dst_internal": pl.Boolean, "src_zone": pl.Utf8, "dst_zone": pl.Utf8, "src_role": pl.Utf8,
             "dst_role": pl.Utf8, "src_importance": pl.Float64, "dst_importance": pl.Float64, "src_net24": pl.Utf8,
             "dst_net24": pl.Utf8, "source": pl.Utf8, "line": pl.Int64, "byte_offset": pl.Int64,
             "ts": pl.Datetime("us", "UTC")}


def events_con(rows, path=":memory:"):
    con = duckdb.connect(str(path))
    con.execute("SET TimeZone = 'UTC'")
    df = pl.DataFrame(rows, schema=EV_SCHEMA)
    con.register("ev_df", df)
    con.execute("CREATE TABLE events AS SELECT * FROM ev_df")
    con.unregister("ev_df")
    return con


def access_rows():
    rows = [ev(i, "203.228.177.117", "10.10.99.1", log_type="event", action="login", user="Deepika.Khan",
               log_desc="Admin login successful") for i in (1, 2, 3)]
    rows += [ev(10 + i, "10.10.10.44", "10.10.20.10", 445, minutes=100 - i) for i in range(7)]   # newest first
    rows.append(ev(30, "10.10.10.44", "10.10.20.11", 8080))
    rows.append(ev(31, "10.10.10.44", "10.10.20.12", 445, action="deny"))
    rows.append(ev(32, "10.10.10.44", "198.51.100.32", 445))
    rows.append(ev(33, "10.10.10.44", "10.10.20.13", 3389, valid=False))
    return rows


def test_access_edges():
    edges, hosts = access.build_access(events_con(access_rows()), S)
    e = {(r["src"], r["dst"], r["kind"]): r for r in edges.iter_rows(named=True)}
    assert set(e) == {("Deepika.Khan", "10.10.99.1", "controls"), ("10.10.10.44", "10.10.20.10", "admin_port"),
                      ("10.10.10.44", "10.10.20.11", "allowed_flow")}
    c = e[("Deepika.Khan", "10.10.99.1", "controls")]
    assert (c["strength"], c["count"], c["ports"]) == (1.0, 3, [])
    ap = e[("10.10.10.44", "10.10.20.10", "admin_port")]
    assert (ap["strength"], ap["count"], ap["ports"]) == (0.8, 7, [445])
    assert len(ap["lines"]) == 5
    assert [x["line"] for x in ap["lines"]] == [16, 15, 14, 13, 12]            # earliest first
    assert ap["first_ts"] < ap["last_ts"]
    af = e[("10.10.10.44", "10.10.20.11", "allowed_flow")]
    assert (af["strength"], af["ports"]) == (0.4, [8080])
    assert edges.schema == pl.Schema(access.EDGE_SCHEMA)


def test_access_hosts():
    _, hosts = access.build_access(events_con(access_rows()), S)
    h = {r["ip"]: r for r in hosts.iter_rows(named=True)}
    assert "198.51.100.32" not in h and "203.228.177.117" not in h and "10.10.20.13" not in h
    assert h["10.10.10.44"]["zone"] == "desktop" and h["10.10.10.44"]["events"] == 10
    assert h["10.10.99.1"]["zone"] == "mgmt" and h["10.10.99.1"]["events"] == 3
    assert h["10.10.20.10"]["net24"] == "10.10.20.0/24" and h["10.10.20.10"]["importance"] == 0.75
    assert h["10.10.20.12"]["events"] == 1            # a denied session still shows the host exists


# ── reach next ───────────────────────────────────────────────────────────────

def edges_df(rows):
    """rows: (src, dst, kind, count[, ports])."""
    out = []
    for r in rows:
        src, dst, kind, count = r[:4]
        out.append({"src": src, "dst": dst, "kind": kind, "strength": S["strengths"][kind], "count": count,
                    "first_ts": T0, "last_ts": T0, "ports": list(r[4]) if len(r) > 4 else [445],
                    "lines": [{"source": "x.log", "line": 900 + i, "byte_offset": 9000 + i, "ts": T0} for i in range(min(count, 5))]})
    return pl.DataFrame(out, schema=access.EDGE_SCHEMA)


def hosts_df(ips, events=None):
    rows = []
    for ip in ips:
        _, zone, role, imp, net24 = _side(ip)
        rows.append({"ip": ip, "zone": zone, "role": role, "net24": net24, "importance": float(imp),
                     "events": (events or {}).get(ip, 1)})
    return pl.DataFrame(rows, schema=access.HOST_SCHEMA)


def step(n, src, dst, tactic="initial-access", success=True, stage=None):
    return {"n": n, "src": src, "dst": dst, "tactic": tactic, "success": success,
            "stage_no": stage or {"initial-access": 3, "discovery": 9, "impact": 14, "reconnaissance": 1,
                                  "exfiltration": 13, "lateral-movement": 10}[tactic]}


def incident(steps, ips=(), users=()):
    return {"chain": steps, "entities": {"ips": list(ips), "hosts": [], "users": list(users), "domains": []}}


def run(inc, edges, hosts, lines=(), settings=None, graph=None):
    return rc.reach_next(inc, graph or {"nodes": [], "edges": []}, edges, hosts, list(lines), NET, settings or S)


def hostsof(nxt):
    return [r["host"] for r in nxt["reachable"]]


def test_observed_admin_port_outranks_inferred_neighbour():
    inc = incident([step(1, "32.127.48.11", "10.10.20.20")])
    nxt, _, fh = run(inc, edges_df([("10.10.20.20", "10.10.30.5", "admin_port", 10)]),
                     hosts_df(["10.10.20.20", "10.10.20.30", "10.10.20.31", "10.10.30.5"]))
    assert fh == ["10.10.20.20"]
    assert hostsof(nxt)[0] == "10.10.30.5" and nxt["reachable"][0]["kind"] == "observed"
    assert {r["kind"] for r in nxt["reachable"][1:]} == {"inferred"}
    assert nxt["reachable"][1]["via"] == [{"from": "10.10.20.20", "edge": "zone_neighbour", "count": 0, "lines": []}]
    assert "1 internal host was reached" in nxt["sentence"] and "2 more are inferred" in nxt["sentence"]


def test_hop_two_is_halved():
    inc = incident([step(1, "10.10.10.44", "8.8.8.8")])
    e = edges_df([("10.10.10.44", "10.10.20.10", "admin_port", 5), ("10.10.20.10", "10.10.99.5", "admin_port", 5)])
    nxt, _, _ = run(inc, e, hosts_df(["10.10.10.44", "10.10.20.10", "10.10.99.5"]))
    # mgmt (1.0) at hop 2 = 0.5 x 0.8 < server (0.75) at hop 1 = 0.6
    assert hostsof(nxt) == ["10.10.20.10", "10.10.99.5"]
    h2 = nxt["reachable"][1]
    assert h2["hop"] == 2 and h2["kind"] == "observed" and h2["via"][0]["from"] == "10.10.20.10"
    # the same mgmt host at hop 1 would come first
    e1 = edges_df([("10.10.10.44", "10.10.20.10", "admin_port", 5), ("10.10.10.44", "10.10.99.5", "admin_port", 5)])
    assert hostsof(run(inc, e1, hosts_df(["10.10.20.10", "10.10.99.5"]))[0]) == ["10.10.99.5", "10.10.20.10"]


def test_importance_order():
    inc = incident([step(1, "10.10.10.44", "8.8.8.8")])
    e = edges_df([("10.10.10.44", x, "admin_port", 5) for x in ("10.10.10.9", "10.10.20.10", "10.10.99.5")])
    nxt, _, _ = run(inc, e, hosts_df(["10.10.10.9", "10.10.20.10", "10.10.99.5"]))
    assert hostsof(nxt) == ["10.10.99.5", "10.10.20.10", "10.10.10.9"]


def test_more_sessions_rank_higher():
    inc = incident([step(1, "10.10.10.44", "8.8.8.8")])
    e = edges_df([("10.10.10.44", "10.10.20.10", "admin_port", 2), ("10.10.10.44", "10.10.20.11", "admin_port", 50)])
    nxt, _, _ = run(inc, e, hosts_df(["10.10.20.10", "10.10.20.11"]))
    assert hostsof(nxt) == ["10.10.20.11", "10.10.20.10"]
    assert nxt["reachable"][0]["via"][0]["count"] == 50


def test_cap_and_counts_in_sentence():
    inc = incident([step(1, "32.127.48.11", "10.10.20.20")])
    ips = [f"10.10.20.{i}" for i in range(30, 42)]
    nxt, _, _ = run(inc, edges_df([("10.10.20.20", "10.10.30.5", "admin_port", 3)]),
                    hosts_df(["10.10.20.20", "10.10.30.5"] + ips))
    assert len(nxt["reachable"]) == S["max_reachable"] == 10
    assert "1 internal host was reached" in nxt["sentence"] and "12 more are inferred" in nxt["sentence"]
    assert "the top one is 10.10.30.5 (admin port 445 x3)" in nxt["sentence"]


def test_inferred_only_sentence():
    inc = incident([step(1, "32.127.48.11", "10.10.20.20")])
    nxt, _, _ = run(inc, edges_df([]), hosts_df(["10.10.20.20", "10.10.20.30", "10.10.20.31"], {"10.10.20.31": 9}))
    assert hostsof(nxt) == ["10.10.20.31", "10.10.20.30"]            # equal rank: busier host first
    assert nxt["sentence"] == ("No internal connections from portal (10.10.20.20) were observed; 2 hosts in the same "
                               "server subnet (e.g. 10.10.20.31) are the likely next targets (inferred).")
    # connections were seen, but only to hosts already in the incident
    inc = incident([step(1, "32.127.48.11", "10.10.20.20")], ips=["10.10.30.5"])
    nxt, _, _ = run(inc, edges_df([("10.10.20.20", "10.10.30.5", "admin_port", 4)]),
                    hosts_df(["10.10.20.20", "10.10.20.30", "10.10.30.5"]))
    assert nxt["sentence"] == ("Every connection seen from portal (10.10.20.20) goes to hosts already in this incident; "
                               "1 host in the same server subnet (e.g. 10.10.20.30) is the likely next target (inferred).")


def test_touched_traversed_not_reported():
    inc = incident([step(1, "10.10.10.44", "8.8.8.8")], ips=["10.10.20.10"])
    e = edges_df([("10.10.10.44", "10.10.20.10", "admin_port", 5), ("10.10.20.10", "10.10.99.5", "admin_port", 5)])
    nxt, _, _ = run(inc, e, hosts_df(["10.10.20.10", "10.10.99.5"]))
    assert hostsof(nxt) == ["10.10.99.5"] and nxt["reachable"][0]["hop"] == 2
    # an evidence-line entity counts as touched too
    nxt, _, _ = run(incident([step(1, "10.10.10.44", "8.8.8.8")]), e, hosts_df(["10.10.20.10", "10.10.99.5"]),
                    lines=[{"src_ip": "10.10.10.44", "dst_ip": "10.10.20.10", "user": None, "log_desc": None}])
    assert hostsof(nxt) == ["10.10.99.5"]


def test_footholds_rules():
    chain = [step(1, "32.127.48.11", "10.10.20.20", success=False),
             step(2, "32.127.48.11", "10.10.20.21", tactic="discovery"),
             step(3, "32.127.48.11", "10.10.20.22", tactic="reconnaissance"),
             step(4, None, "10.10.20.23", tactic="impact"),
             step(5, "32.127.48.11", "198.51.100.7"),                 # documentation range, zone internet
             step(6, "32.127.48.11", "10.10.20.24"),
             step(7, "10.10.10.118", "7.154.5.35", tactic="exfiltration")]
    assert rc.footholds(chain, ["parul.sinha"], NET, S) == ["10.10.20.24", "10.10.10.118", "parul.sinha"]


def test_footholds_include_supporting():
    # the only successful step to an internal host is a supporting anomaly under a blocked rule step
    sup = {**step(1, "203.228.177.117", "10.10.99.1"), "rule_id": "A01-rare-event", "alert_id": "x1",
           "ts_start": "2026-10-29T00:00:01.000000Z"}
    rule = {**step(1, "203.228.177.117", "10.10.20.20", tactic="discovery", success=False),
            "rule_id": "R02-port-scan", "alert_id": "r1", "ts_start": "2026-10-29T00:00:00.000000Z",
            "supporting": [sup]}
    inc = incident([rule])
    assert [s["alert_id"] for s in rc.evidence_steps(inc["chain"])] == ["r1", "x1"]
    nxt, _, fh = run(inc, edges_df([]), hosts_df(["10.10.99.1"]))
    assert fh == ["10.10.99.1"]
    assert {"203.228.177.117", "10.10.99.1", "10.10.20.20"} <= rc.touched(inc, [])
    assert nxt["likely_tactics"] == rc.likely_tactics([9, 3])


def test_desktop_foothold_gets_inferred_neighbours():
    inc = incident([step(1, "10.10.10.118", "7.154.5.35", tactic="exfiltration")])
    nxt, g, fh = run(inc, edges_df([]), hosts_df(["10.10.10.118", "10.10.10.119", "10.10.10.120"]),
                     graph={"nodes": [], "edges": []})
    assert fh == ["10.10.10.118"]
    assert hostsof(nxt) == ["10.10.10.119", "10.10.10.120"]
    for r in nxt["reachable"]:
        assert (r["hop"], r["kind"], r["zone"]) == (1, "inferred", "desktop")
        assert r["via"] == [{"from": "10.10.10.118", "edge": "zone_neighbour", "count": 0, "lines": []}]
    assert nxt["sentence"] == ("No internal connections from 10.10.10.118 were observed; 2 hosts in the same desktop "
                               "subnet (e.g. 10.10.10.119) are the likely next targets (inferred).")
    assert {n["id"]: n.get("reach") for n in g["nodes"] if "reach" in n} == \
        {"10.10.10.119": "inferred", "10.10.10.120": "inferred"}
    assert [(x["kind"], x["label"]) for x in g["edges"]] == [("reach_inferred", "same desktop subnet (inferred)")] * 2


def test_desktop_neighbour_leads_to_servers_inferred():
    inc = incident([step(1, "10.10.10.118", "7.154.5.35", tactic="exfiltration")])
    nxt, _, _ = run(inc, edges_df([("10.10.10.44", "10.10.20.10", "admin_port", 5)]),
                    hosts_df(["10.10.10.118", "10.10.10.44", "10.10.20.10"]))
    r0, r1 = nxt["reachable"]
    assert (r0["host"], r0["hop"], r0["kind"]) == ("10.10.20.10", 2, "inferred")
    assert (r0["via"][0]["from"], r0["via"][0]["edge"]) == ("10.10.10.44", "admin_port")
    assert (r1["host"], r1["hop"], r1["kind"]) == ("10.10.10.44", 1, "inferred")
    assert nxt["sentence"] == ("No internal connections from 10.10.10.118 were observed; 1 host in the same desktop "
                               "subnet and 1 host they connect to (e.g. 10.10.20.10, server) are the likely next "
                               "targets (inferred).")


def test_lan_foothold_keeps_reason():
    inc = incident([step(1, "32.127.48.11", "10.10.30.5")])
    nxt, _, fh = run(inc, edges_df([]), hosts_df(["10.10.30.5", "10.10.30.6"]))
    assert fh == ["10.10.30.5"] and nxt["reachable"] == []
    assert nxt["sentence"] == ("No internal reach observed in the logs: 10.10.30.5 opened no allowed sessions to "
                               "other internal hosts, and inferred neighbours are only drawn for server, DMZ and "
                               "desktop subnets.")


def test_lonely_desktop_reason():
    inc = incident([step(1, "10.10.10.118", "7.154.5.35", tactic="exfiltration")])
    nxt, _, _ = run(inc, edges_df([]), hosts_df(["10.10.10.118"]))
    assert nxt["reachable"] == []
    assert nxt["sentence"] == ("No internal reach observed in the logs: 10.10.10.118 opened no allowed sessions to "
                               "other internal hosts, and no other host in its subnet appears in the logs.")


def test_controls_exception():
    inc = incident([step(1, "203.228.177.117", "10.10.99.1")], ips=["10.10.99.1", "203.228.177.117"],
                   users=["deepika.khan"])
    lines = [{"src_ip": "203.228.177.117", "dst_ip": "10.10.99.1", "user": "Deepika.Khan",
              "log_desc": "Admin login successful"}]
    nxt, g, fh = run(inc, edges_df([("Deepika.Khan", "10.10.99.1", "controls", 3, [])]), hosts_df(["10.10.99.1"]),
                     lines=lines)
    assert fh == ["10.10.99.1", "Deepika.Khan"]
    assert hostsof(nxt) == ["10.10.99.1"]
    r = nxt["reachable"][0]
    assert (r["zone"], r["hop"], r["kind"], r["via"][0]["edge"], r["via"][0]["from"]) == \
        ("mgmt", 1, "observed", "controls", "Deepika.Khan")
    assert nxt["sentence"] == ("Deepika.Khan logged in to the firewall management interface firewall (10.10.99.1), "
                               "which controls every zone.")
    assert "controls every zone" in nxt["sentence"]
    assert any(e["label"] == "admin login x3" and e["source"] == "Deepika.Khan" for e in g["edges"])
    # without the login line the account is no foothold, and the firewall stays unreported
    nxt, _, _ = run(inc, edges_df([("Deepika.Khan", "10.10.99.1", "controls", 3, [])]), hosts_df(["10.10.99.1"]))
    assert nxt["reachable"] == []


def test_empty_reasons():
    none = run(incident([step(1, "32.127.48.11", "10.10.20.20", success=False)]), edges_df([]),
               hosts_df(["10.10.20.20", "10.10.20.30"]))[0]
    assert none["sentence"] == ("No internal reach observed in the logs: no successful step reached an internal host "
                                "or signed in to an account.")
    alltouched = run(incident([step(1, "32.127.48.11", "10.10.20.20")], ips=["10.10.20.30"]), edges_df([]),
                     hosts_df(["10.10.20.20", "10.10.20.30"]))[0]
    assert alltouched["reachable"] == [] and alltouched["sentence"] == (
        "No internal reach observed in the logs: every host reachable from portal (10.10.20.20) is already part of "
        "this incident.")


def test_likely_tactics():
    assert rc.likely_tactics([3, 9, 13]) == ["impact"]
    assert rc.likely_tactics([3]) == ["execution", "persistence", "privilege-escalation"]
    assert rc.likely_tactics([14]) == [] and rc.likely_tactics([]) == []
    assert rc.likely_tactics([1]) == ["initial-access", "execution", "persistence"]     # skips resource-development
    nxt, _, _ = run(incident([step(1, "32.127.48.11", "10.10.20.20")]), edges_df([]), hosts_df([]))
    assert nxt["likely_tactics"] == ["execution", "persistence", "privilege-escalation"]


def _merge_case():
    inc = incident([step(1, "10.10.10.44", "8.8.8.8")])
    e = edges_df([("10.10.10.44", "10.10.20.10", "admin_port", 5, [445, 3389, 22, 135]),
                  ("10.10.20.10", "10.10.99.5", "allowed_flow", 2, [8080])])
    base = {"nodes": [node_for("10.10.10.44", "ip", NET), node_for("8.8.8.8", "ip", NET)],
            "edges": [{"source": "10.10.10.44", "target": "8.8.8.8", "step": 1, "technique": "T1041",
                       "tactic": "exfiltration", "label": "1. x x1", "kind": "step"}]}
    return inc, e, base


def test_merged_graph():
    inc, e, base = _merge_case()
    h = hosts_df(["10.10.10.44", "10.10.20.10", "10.10.99.5"])
    nxt, g, _ = run(inc, e, h, graph=base)
    ids = {n["id"] for n in g["nodes"]}
    assert base["nodes"] == g["nodes"][:2] and "reach" not in g["nodes"][0]      # input graph untouched
    reach_nodes = {n["id"]: n["reach"] for n in g["nodes"] if "reach" in n}
    assert reach_nodes == {"10.10.20.10": "observed", "10.10.99.5": "observed"}
    reach_edges = [x for x in g["edges"] if x["kind"] != "step"]
    assert [(x["source"], x["target"], x["label"]) for x in reach_edges] == [
        ("10.10.10.44", "10.10.20.10", "admin port 445/3389/22 x5"), ("10.10.20.10", "10.10.99.5", "allowed port 8080 x2")]
    for x in g["edges"]:
        assert x["source"] in ids and x["target"] in ids and x["kind"] in C.EDGE_KINDS
        errs = []
        C._check(x, C.EDGE, "edge", errs)
        assert errs == []
    assert all(x["step"] is None and x["kind"] == "reach_observed" for x in reach_edges)
    assert run(inc, e, h, graph=base)[1] == g                                      # idempotent
    for r in nxt["reachable"]:
        errs = []
        C._check(r, C.REACH, "r", errs)
        for v in r["via"]:
            assert v["edge"] in access.EDGE_KINDS
            for ln in v["lines"]:
                C._check(ln, C.EVIDENCE, "line", errs)
                assert C.TS_RE.match(ln["ts"])
        assert errs == [] and r["zone"] in C.ZONES and r["kind"] in C.REACH_KINDS
    # an inferred neighbour gets a reach_inferred edge
    _, gi, _ = run(incident([step(1, "32.127.48.11", "10.10.20.20")]), edges_df([]),
                   hosts_df(["10.10.20.20", "10.10.20.30"]), graph={"nodes": [], "edges": []})
    assert [(x["kind"], x["label"]) for x in gi["edges"]] == [("reach_inferred", "same server subnet (inferred)")]
    assert {n["id"]: n.get("reach") for n in gi["nodes"]} == {"10.10.20.30": "inferred", "10.10.20.20": None}


def test_assembled_incident_with_reach_is_valid():
    xs, alerts, ev_, res, aj = _bundle()
    from killchain.graph import chain as ch

    chains, _ = ch.build_chains(res["incidents"], res["incident_alerts"], alerts, ev_, NET)
    row = res["incidents"].row(0, named=True)
    base = files.assemble(row, chains[0])
    nxt, g, _ = rc.reach_next(base, chains[0]["graph"],
                              edges_df([("10.10.20.20", "10.10.30.5", "admin_port", 4)]),
                              hosts_df(["10.10.20.20", "10.10.20.30", "10.10.30.5"]), [], NET, S)
    assert nxt["reachable"]
    inc = files.assemble(row, {**chains[0], "graph": g}, nxt)
    index = files.index_rows([inc], "t")
    assert C.validate_bundle(inc, index, files.alerts_with_incidents(aj, res["incident_alerts"])) == []


# ── CLI ──────────────────────────────────────────────────────────────────────

def _events_db(tmp_path):
    rows = [ev(i, "32.127.48.11", "10.10.20.20", 443, minutes=i) for i in range(1, 10)]     # the evidence lines
    rows += [ev(100 + i, "10.10.20.20", "10.10.20.30", 22, source="y.log") for i in range(4)]
    rows.append(ev(200, "10.10.10.5", "10.10.20.31", 443, source="y.log"))
    events_con(rows, tmp_path / db.PREPARED_NAME).close()


def test_cli_reach(tmp_path, capsys):
    _run_folder(tmp_path)
    assert reach_main(["--run", str(tmp_path)]) == 1
    assert "`python -m killchain chain` first" in capsys.readouterr().err
    assert chain_main(["--run", str(tmp_path)]) == 0
    assert reach_main(["--run", str(tmp_path)]) == 1                         # no events.duckdb, no --parsed
    assert "--parsed" in capsys.readouterr().err
    _events_db(tmp_path)
    assert reach_main(["--run", str(tmp_path)]) == 0
    for name in ("access_graph.parquet", "access_hosts.parquet", "reach.json", "reach/_stats.json", "incidents/1.json"):
        assert (tmp_path / name).exists(), name
    inc = json.loads((tmp_path / "incidents" / "1.json").read_text(encoding="utf-8"))
    assert inc["next"] != files.NEXT_PLACEHOLDER
    assert [r["host"] for r in inc["next"]["reachable"]] == ["10.10.20.30", "10.10.20.31"]
    assert [r["kind"] for r in inc["next"]["reachable"]] == ["observed", "inferred"]
    assert any(n.get("reach") for n in inc["graph"]["nodes"])
    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    aj = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert C.validate_bundle(inc, index, aj) == []
    st = json.loads((tmp_path / "reach" / "_stats.json").read_text(encoding="utf-8"))
    assert st["stage"] == "reach" and st["access_rebuilt"] is True and st["edges_by_kind"] == {"admin_port": 1, "allowed_flow": 1}
    assert isinstance(st["wall_secs"], float) and st["incidents_with_reach"] == 1

    m0 = (tmp_path / "access_graph.parquet").stat().st_mtime_ns
    assert reach_main(["--run", str(tmp_path)]) == 0
    assert (tmp_path / "access_graph.parquet").stat().st_mtime_ns == m0
    assert json.loads((tmp_path / "reach" / "_stats.json").read_text(encoding="utf-8"))["access_rebuilt"] is False
    assert json.loads((tmp_path / "incidents" / "1.json").read_text(encoding="utf-8")) == inc     # idempotent
    os.utime(tmp_path / "access_graph.parquet", ns=(1, 1))
    assert reach_main(["--run", str(tmp_path), "--force"]) == 0
    assert (tmp_path / "access_graph.parquet").stat().st_mtime_ns != 1

    capsys.readouterr()
    assert reach_main(["--run", str(tmp_path), "1"]) == 0
    out = capsys.readouterr().out
    assert inc["next"]["sentence"] in out and "10.10.20.30 zone server hop 1 observed" in out
    assert reach_main(["--run", str(tmp_path), "9"]) == 1


def test_cli_reach_contract_error_writes_nothing(tmp_path, monkeypatch, capsys):
    _run_folder(tmp_path)
    assert chain_main(["--run", str(tmp_path)]) == 0
    _events_db(tmp_path)
    before = (tmp_path / "incidents" / "1.json").read_bytes()
    monkeypatch.setattr(files, "check", lambda *a, **k: ["boom"])
    assert reach_main(["--run", str(tmp_path)]) == 1
    assert "boom" in capsys.readouterr().err
    assert not (tmp_path / "reach.json").exists() and not (tmp_path / "access_graph.parquet").exists()
    assert (tmp_path / "incidents" / "1.json").read_bytes() == before


# ── real run ─────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not ((REAL_RUN / db.PREPARED_NAME).exists() and (REAL_RUN / "chains.json").exists()),
                    reason="real run not built")
def test_real_run_reach():
    con = db.connect(None, REAL_RUN)
    edges, hosts = access.build_access(con, S)
    bundle, rows, index, alerts = compute_reach(REAL_RUN, con, edges, hosts, NET, S)
    con.close()
    kinds = dict(edges.group_by("kind").len().iter_rows())
    assert kinds == {"controls": 3, "admin_port": 90}
    for inc in bundle:
        assert C.validate_bundle(inc, index, alerts) == []
        n = inc["next"]
        assert n["reachable"] or n["sentence"].startswith("No internal reach observed in the logs")

    def controls(inc):
        return any(r["host"] == "10.10.99.1" and r["via"][0]["edge"] == "controls" for r in inc["next"]["reachable"]) \
            and "controls every zone" in inc["next"]["sentence"]

    for user in ("svc_backup30", "deepika.khan"):
        hit = [i for i in bundle if user in [u.lower() for u in i["entities"]["users"]]
               and any(s["rule_id"].startswith(("R05", "R06", "R07")) for s in i["chain"])]
        assert hit and all(controls(i) for i in hit), user
    r07 = [i for i in bundle if any(s["rule_id"].startswith("R07") for s in i["chain"])]
    assert r07 and all(controls(i) for i in r07)
    a = next(i for i in bundle if any(s["src"] == "32.127.48.11" and s["rule_id"].startswith("R16") for s in i["chain"]))
    inferred = [r for r in a["next"]["reachable"] if r["kind"] == "inferred"]
    assert inferred and all(r["host"].startswith("10.10.20.") and r["zone"] == "server" for r in inferred)
    b = next(i for i in bundle if any(s["src"] == "10.10.10.118" and s["rule_id"].startswith("R24") for s in i["chain"]))
    rb = b["next"]["reachable"]
    assert rb and all(r["kind"] == "inferred" for r in rb)
    assert all(r["zone"] == "desktop" and r["host"].startswith("10.10.10.") for r in rb if r["hop"] == 1)
    assert all(r["via"][0]["from"].startswith("10.10.10.") for r in rb if r["hop"] == 2)
    assert "(inferred)" in b["next"]["sentence"]
