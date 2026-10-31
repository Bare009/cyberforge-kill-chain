"""Numbered chains (ordering, ongoing, gaps, chain_text), path graphs, provisional bundle files and the chain CLI."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import pytest

from killchain import contracts as C
from killchain import db
from killchain.correlate import engine as ce
from killchain.correlate.cli import main as correlate_main
from killchain.correlate.entities import load_settings
from killchain.graph import chain as ch
from killchain.graph import incident_files as files
from killchain.graph import path as gp
from killchain.graph.cli import main as chain_main

ROOT = Path(__file__).resolve().parents[1]
REAL_RUN = ROOT / "data" / "runs" / "firex-10G"
T0 = datetime(2026, 10, 26, 2, 0)          # naive = UTC, as in alerts.parquet
NET = db.load_network()

TACTIC_STAGE = {"reconnaissance": 1, "initial-access": 3, "execution": 4, "persistence": 5,
                "credential-access": 8, "discovery": 9, "lateral-movement": 10, "command-and-control": 12,
                "exfiltration": 13, "impact": 14}
PHASE = {1: "Reconnaissance", 3: "Delivery", 4: "Exploitation", 5: "Installation", 8: "Exploitation",
         9: "Reconnaissance", 10: "Actions on Objectives", 12: "Command and Control", 13: "Actions on Objectives",
         14: "Actions on Objectives"}


def al(alert_id, rule_id, start, minutes=5, tactic="discovery", **kw):
    """A full alert dict; start and minutes are minutes after T0."""
    stage = TACTIC_STAGE[tactic]
    s = T0 + timedelta(minutes=start)
    d = {"alert_id": alert_id, "rule_id": rule_id, "layer": "rule", "title": rule_id, "technique": "T1046",
         "technique_name": None, "tactic": tactic, "stage_no": stage, "kill_chain_stage": PHASE[stage],
         "alt_techniques": [], "severity": 4, "confidence": 0.85, "ts_start": s, "ts_end": s + timedelta(minutes=minutes),
         "src_ip": None, "dst_ip": None, "host": None, "user": None, "domain": None, "url": None,
         "event_count": 10, "blocked_share": 0.0, "success": True, "summary": f"{rule_id} happened",
         "action_text": f"{rule_id} happened", "incident_number": None, "src_count": 1}
    d.update(kw)
    return d


def evidence_for(alerts, per=3, window=0):
    rows, line = [], 1
    for a in alerts:
        for i in range(per + window):
            rows.append({"alert_id": a["alert_id"], "source": "x.log", "line": line, "byte_offset": line * 100,
                         "ts": (a["ts_start"] + timedelta(seconds=i)).replace(tzinfo=timezone.utc),
                         "technique": a["technique"], "role": "window" if i < window else "trigger"})
            line += 1
    return pl.DataFrame(rows, schema={"alert_id": pl.Utf8, "source": pl.Utf8, "line": pl.Int64,
                                      "byte_offset": pl.Int64, "ts": pl.Datetime("us", "UTC"),
                                      "technique": pl.Utf8, "role": pl.Utf8})


def ids(steps):
    return [s["alert_id"] for s in steps]


# ── ordering ─────────────────────────────────────────────────────────────────

def test_sorted_by_start():
    xs = [al("c", "R3", 30), al("a", "R1", 0), al("b", "R2", 10)]
    assert ids(ch.order_steps(xs)) == ["a", "b", "c"]


def test_tie_breaks_stage_then_rule_then_alert():
    xs = [al("e", "R12", 0, tactic="exfiltration"), al("d", "R02", 0, tactic="discovery"),
          al("i", "A09", 0, tactic="initial-access"), al("z", "R02", 0, tactic="discovery"),
          al("y", "R01", 0, tactic="discovery")]
    assert ids(ch.order_steps(xs)) == ["i", "y", "d", "z", "e"]
    for seed in range(5):
        random.Random(seed).shuffle(xs)
        assert ids(ch.order_steps(xs)) == ["i", "y", "d", "z", "e"]


def test_overlap_keeps_start_order():
    # a lower-stage step that starts later while a higher-stage step runs is numbered after it,
    # because contract C forbids ts_start decreasing; the long step is marked ongoing instead
    xs = [al("x", "R12", 0, minutes=120, tactic="exfiltration"), al("s", "R16", 30, tactic="initial-access")]
    steps = ch.build_steps(xs, None, NET)
    assert ids(steps) == ["x", "s"] and [s["ongoing"] for s in steps] == [True, False]


def test_numbering_and_start_never_decreases():
    xs = [al(f"a{i}", f"R{i:02d}", random.Random(i).randint(0, 500)) for i in range(12)]
    steps = ch.build_steps(xs, None, NET)
    assert [s["n"] for s in steps] == list(range(1, 13))
    starts = [s["ts_start"] for s in steps]
    assert starts == sorted(starts)


# ── ongoing ──────────────────────────────────────────────────────────────────

def test_ongoing():
    xs = [al("long", "R11", 0, minutes=600, tactic="command-and-control"), al("mid", "R12", 60, tactic="exfiltration"),
          al("last", "R13", 700)]
    assert ch.ongoing_flags(ch.order_steps(xs)) == [True, False, False]
    # an equal-start tie does not make a step ongoing
    tie = [al("scan", "R02", 0, minutes=1), al("big", "A10", 0, minutes=600, tactic="exfiltration")]
    assert ch.ongoing_flags(ch.order_steps(tie)) == [False, False]
    # a later step starting exactly at the end does not count
    edge = [al("a", "R1", 0, minutes=10), al("b", "R2", 10)]
    assert ch.ongoing_flags(ch.order_steps(edge)) == [False, False]


def test_long_step_keeps_one_number_and_its_end():
    xs = [al("long", "R11", 0, minutes=600, tactic="command-and-control"), al("mid", "R12", 60, tactic="exfiltration")]
    steps = ch.build_steps(xs, None, NET)
    assert steps[0]["n"] == 1 and steps[0]["ongoing"] is True
    assert steps[0]["ts_end"] == "2026-10-26T12:00:00.000000Z" and steps[0]["ts_end_ist"] == "2026-10-26 17:30:00"


def chain_b(outlier_start):
    """R24 malware, R11 beaconing, A10 + R12 long exfiltration, A04/A08 hourly outliers (minutes after T0)."""
    return [al("m", "R24-malware", 0, minutes=4, tactic="execution"),
            al("b", "R11-beaconing", 53, minutes=33 * 60, tactic="command-and-control"),
            al("x1", "A10-lopsided", 37 * 60, minutes=133, tactic="exfiltration", layer="anomaly"),
            al("x2", "R12-transfer", 37 * 60, minutes=133, tactic="exfiltration"),
            al("o1", "A04-outlier", outlier_start, minutes=60, tactic="discovery", layer="anomaly"),
            al("o2", "A08-outlier", outlier_start, minutes=60, tactic="exfiltration", layer="anomaly")]


def sup_ids(step):
    return [x["alert_id"] for x in step["supporting"]]


def test_chain_b_rule_steps_and_supporting():
    steps = ch.build_steps(chain_b(37 * 60 + 6), None, NET)
    assert ids(steps) == ["m", "b", "x2"]
    assert [sup_ids(s) for s in steps] == [[], [], ["x1", "o1", "o2"]]
    assert {x["relation"] for x in steps[2]["supporting"]} == {"during"}
    assert ch.chain_text(steps) == "1. Execution → 2. Command and Control → 3. Exfiltration"
    assert [s["ongoing"] for s in steps] == [False, False, False]


def test_outlier_during_beaconing_attaches_to_beaconing():
    steps = ch.build_steps(chain_b(10 * 60), None, NET)
    assert ids(steps) == ["m", "b", "x2"]
    assert sup_ids(steps[1]) == ["o1", "o2"] and sup_ids(steps[2]) == ["x1"]


AB = {"src_ip": "32.127.48.11", "dst_ip": "10.10.20.20"}


def chain_a():
    return [al("a09", "A09-denied-then-allowed", 0, minutes=500, tactic="initial-access", layer="anomaly", **AB),
            al("r02", "R02-port-scan", 0, minutes=1, **AB),
            al("a10", "A10-lopsided-pair", 0, minutes=680, tactic="exfiltration", layer="anomaly", **AB),
            al("r16", "R16-web-sql-injection", 16, minutes=4, tactic="initial-access", **AB),
            al("r20", "R20-rare-path", 50, minutes=20, tactic="persistence", **AB),
            al("a11", "A11-too-regular", 500, minutes=150, tactic="command-and-control", layer="anomaly", **AB),
            al("r12", "R12-transfer", 500, minutes=150, tactic="exfiltration", **AB)]


def test_chain_a_supporting():
    steps = ch.build_steps(chain_a(), None, NET)
    assert ids(steps) == ["r02", "r16", "r20", "r12"]
    assert [sup_ids(s) for s in steps] == [[], ["a09"], [], ["a10", "a11"]]
    assert all(s["layer"] == "rule" for s in steps)
    sup = [x["stage_no"] for s in steps for x in s["supporting"]]
    g = ch.gaps([s["stage_no"] for s in steps], sup)
    assert not any("Command and Control" in x for x in g)
    assert any("Command and Control" in x for x in ch.gaps([s["stage_no"] for s in steps]))


def test_attach_prefers_shared_entity():
    near = al("r1", "R01", 0, minutes=60, src_ip="1.1.1.1", dst_ip="10.10.20.9")
    far = al("r2", "R02", 600, minutes=5, src_ip="10.10.10.118")
    x = al("x", "A04", 10, minutes=10, layer="anomaly", src_ip="10.10.10.118")
    out = ch.attach_supporting([near, far], [x])
    assert out == {"r1": [], "r2": [(x, "before")]}
    assert ch.shares_entity(x, far) and not ch.shares_entity(x, near)
    assert ch.shares_entity({"domain": "Bad.Example"}, {"domain": "bad.example"})


def test_attach_before_and_after():
    rules = [al("r1", "R01", 100, minutes=10), al("r2", "R02", 200, minutes=10)]
    early = al("e", "A01", 0, minutes=30, layer="anomaly")
    late = al("l", "A02", 400, minutes=5, layer="anomaly")
    touch = al("t", "A03", 210, minutes=5, layer="anomaly")       # starts exactly when r2 ends
    out = ch.attach_supporting(rules, [late, early, touch])
    assert out == {"r1": [(early, "before")], "r2": [(touch, "during"), (late, "after")]}
    assert ch.gap_secs(early, rules[0]) == 70 * 60 and ch.gap_secs(touch, rules[1]) == 0


def test_attach_tie_breaks():
    r1 = al("r1", "R01", 0, minutes=100, tactic="discovery")
    r2 = al("r2", "R02", 20, minutes=100, tactic="exfiltration")
    same_tactic = al("x", "A08", 50, minutes=5, tactic="exfiltration", layer="anomaly")
    assert ch.attach_supporting([r1, r2], [same_tactic])["r2"] == [(same_tactic, "during")]
    nearest = al("y", "A11", 18, minutes=5, tactic="command-and-control", layer="anomaly")
    assert ch.attach_supporting([r1, r2], [nearest])["r2"] == [(nearest, "during")]
    middle = al("z", "A11", 10, minutes=5, tactic="command-and-control", layer="anomaly")
    assert ch.attach_supporting([r1, r2], [middle])["r1"] == [(middle, "during")]


def test_anomaly_only_incident_is_numbered():
    xs = [al("x2", "A04", 20, layer="anomaly"), al("x1", "A01", 0, layer="anomaly"),
          al("x3", "A10", 40, tactic="exfiltration", layer="anomaly")]
    steps = ch.build_steps(xs, None, NET)
    assert ids(steps) == ["x1", "x2", "x3"] and [s["n"] for s in steps] == [1, 2, 3]
    assert all(s["layer"] == "anomaly" and s["supporting"] == [] for s in steps)


def test_supporting_fields():
    xs = chain_a()
    ev = evidence_for(xs, per=4, window=1)
    steps = ch.build_steps(xs, ev, NET)
    entries = [x for s in steps for x in s["supporting"]]
    assert len(entries) == 3
    for x in entries:
        assert set(x) == set(C.SUPPORT)
        errs = []
        C._check(x, C.SUPPORT, "sup", errs)
        assert errs == [] and x["line_total"] == 5 and x["layer"] == "anomaly"
        assert all(C.TS_RE.match(x[k]) for k in ("ts_start", "ts_end"))
        assert all(C.TS_IST_RE.match(x[k]) for k in ("ts_start_ist", "ts_end_ist"))
        assert x["src"] == "32.127.48.11" and x["dst"] == "10.10.20.20"
    assert steps[1]["supporting"][0]["action"] == "A09-denied-then-allowed happened"


# ── gaps and chain_text ──────────────────────────────────────────────────────

def test_gaps_interior_only():
    g = ch.gaps([3, 9, 13])
    assert g == ["No Execution evidence in the logs", "No Persistence evidence in the logs",
                 "No Privilege Escalation evidence in the logs", "No Defense Evasion evidence in the logs",
                 "No Credential Access evidence in the logs", "No Lateral Movement evidence in the logs",
                 "No Collection evidence in the logs", "No Command and Control evidence in the logs"]
    assert len(set(g)) == len(g)
    assert not any("Resource Development" in x for x in ch.gaps([1, 3]))
    assert ch.gaps([1, 3]) == []
    assert ch.gaps([3, 3, 3]) == [] and ch.gaps([]) == []


def test_gaps_are_never_steps():
    xs = [al("a", "R1", 0, tactic="initial-access"), al("b", "R2", 10, tactic="exfiltration")]
    steps = ch.build_steps(xs, None, NET)
    assert len(steps) == 2 and {s["tactic"] for s in steps} == {"initial-access", "exfiltration"}


def test_chain_text_ranges():
    xs = [al(f"a{i}", "R05", i, tactic="initial-access") for i in range(4)]
    assert ch.chain_text(ch.build_steps(xs, None, NET)) == "1-4. Initial Access"
    xs = [al("a", "R02", 0), al("b", "R16", 1, tactic="initial-access"),
          al("c", "A10", 2, tactic="exfiltration"), al("d", "R12", 3, tactic="exfiltration")]
    assert ch.chain_text(ch.build_steps(xs, None, NET)) == "1. Discovery → 2. Initial Access → 3-4. Exfiltration"


# ── step contents ────────────────────────────────────────────────────────────

def test_step_fields_and_evidence():
    xs = [al("a", "R16-web-sql-injection", 0, tactic="initial-access", src_ip="32.127.48.11",
             dst_ip="10.10.20.20", domain="portal.corp.local"),
          al("b", "R04-malware", 5, tactic="command-and-control", src_ip="10.10.10.118", domain="bad.example.org")]
    ev = evidence_for(xs, per=25, window=2)
    steps = ch.build_steps(xs, ev, NET)
    for s in steps:
        assert set(s) == set(C.STEP) | {"supporting"}
        errs = []
        C._check(s, C.STEP, "step", errs)
        assert errs == []
        assert len(s["line_sample"]) <= 20 and s["line_total"] == 27
        assert all(C.TS_RE.match(x["ts"]) for x in s["line_sample"])
        assert all(C.TS_RE.match(s[k]) for k in ("ts_start", "ts_end"))
        assert all(C.TS_IST_RE.match(s[k]) for k in ("ts_start_ist", "ts_end_ist"))
    # trigger rows first: the two window rows (lines 1-2) are not in the 20-line sample
    assert [x["line"] for x in steps[0]["line_sample"]][:2] == [3, 4]
    assert steps[0]["src"] == "32.127.48.11" and steps[0]["dst"] == "10.10.20.20"
    assert steps[1]["dst"] == "bad.example.org"           # non-hub domain when there is no dst_ip
    assert steps[0]["ts_start"] == "2026-10-26T02:00:00.000000Z" and steps[0]["ts_start_ist"] == "2026-10-26 07:30:00"


# ── path graph ───────────────────────────────────────────────────────────────

def test_node_classification():
    assert gp.node_for("32.127.48.11", "ip", NET) == {"id": "32.127.48.11", "label": "32.127.48.11",
                                                      "kind": "external_ip", "zone": "internet", "importance": 0.25}
    assert gp.node_for("10.10.20.20", "ip", NET) == {"id": "10.10.20.20", "label": "portal (10.10.20.20)",
                                                     "kind": "server", "zone": "dmz", "importance": 0.75}
    fw = gp.node_for("10.10.99.1", "ip", NET)
    assert (fw["kind"], fw["zone"], fw["importance"], fw["label"]) == ("firewall", "mgmt", 1.0, "firewall (10.10.99.1)")
    pub = gp.node_for("203.0.113.5", "ip", NET)
    assert (pub["kind"], pub["zone"]) == ("firewall", "public")
    assert gp.node_for("71.54.76.0/24", "ip", NET)["kind"] == "external_ip"
    assert gp.node_for("198.51.100.7", "ip", NET)["kind"] == "external_ip"
    d = gp.node_for("10.10.10.118", "ip", NET)
    assert (d["kind"], d["zone"], d["importance"]) == ("internal_host", "desktop", 0.25)
    assert gp.node_for("Deepika.Khan", "user", NET) == {"id": "Deepika.Khan", "label": "Deepika.Khan",
                                                        "kind": "account", "zone": "unknown", "importance": 0.5}
    assert gp.node_for("kjhsdf.duckdns.org", "domain", NET)["zone"] == "internet"


def _graph(xs):
    steps = ch.build_steps(xs, None, NET)
    return steps, gp.path_graph(steps, {a["alert_id"]: a for a in xs}, NET)


def _valid_graph(g):
    errs = []
    nodes = {n["id"] for n in g["nodes"]}
    for n in g["nodes"]:
        C._check(n, C.NODE, "node", errs)
        assert n["kind"] in C.NODE_KINDS and n["zone"] in C.ZONES
    for e in g["edges"]:
        C._check(e, C.EDGE, "edge", errs)
        assert e["kind"] in C.EDGE_KINDS and e["source"] in nodes and e["target"] in nodes
    assert errs == []


def test_graph_edges():
    xs = [al("a", "R02-port-scan", 0, src_ip="32.127.48.11", dst_ip="10.10.20.20", event_count=240),
          al("b", "R16-web-sql-injection", 10, tactic="initial-access", src_ip="32.127.48.11", dst_ip="10.10.20.20",
             domain="portal.corp.local", event_count=60),
          al("c", "R24-malware", 20, tactic="execution", src_ip="10.10.10.118", dst_ip="7.154.5.35",
             domain="kjhsdf.duckdns.org", event_count=3),
          al("d", "R05-admin-login-odd-hour", 30, tactic="initial-access", src_ip="203.228.177.117",
             dst_ip="10.10.99.1", user="Deepika.Khan", event_count=3),
          al("e", "R22-http-flood", 40, tactic="impact", dst_ip="10.10.20.20", src_count=6005, event_count=6005)]
    steps, g = _graph(xs)
    _valid_graph(g)
    ids_ = {n["id"] for n in g["nodes"]}
    assert "portal.corp.local" not in ids_ and "kjhsdf.duckdns.org" in ids_
    main = [e for e in g["edges"] if e["step"] == 2]
    assert main == [{"source": "32.127.48.11", "target": "10.10.20.20", "step": 2, "technique": "T1046",
                     "tactic": "initial-access", "label": "2. web sql injection x60", "kind": "step"}]
    login = [(e["source"], e["target"], e["label"]) for e in g["edges"] if e["step"] == 4]
    assert login == [("203.228.177.117", "Deepika.Khan", "4. signs in as Deepika.Khan"),
                     ("Deepika.Khan", "10.10.99.1", "4. admin login odd hour x3")]
    dom = [(e["source"], e["target"]) for e in g["edges"] if e["step"] == 3]
    assert dom == [("10.10.10.118", "7.154.5.35"), ("10.10.10.118", "kjhsdf.duckdns.org")]
    flood = [e for e in g["edges"] if e["step"] == 5]
    assert flood[0]["source"] == "sources of step 5"
    assert {n["id"]: n["label"] for n in g["nodes"]}["sources of step 5"] == "6,005 sources"
    assert [e["step"] for e in g["edges"]] == sorted(e["step"] for e in g["edges"])
    assert {e["step"] for e in g["edges"]} == {1, 2, 3, 4, 5}
    assert not any("supporting" in e for e in g["edges"])


def test_graph_draws_supporting_edges():
    xs = chain_a()
    xs[2]["event_count"] = 840
    steps, g = _graph(xs)
    _valid_graph(g)
    sup = [e for e in g["edges"] if e.get("supporting")]
    assert [(e["step"], e["label"]) for e in sup] == [
        (2, "2. denied then allowed x10 (anomaly)"), (4, "4. lopsided pair x840 (anomaly)"),
        (4, "4. too regular x10 (anomaly)")]
    assert all(e["supporting"] is True and e["kind"] == "step" for e in sup)
    assert [e["tactic"] for e in sup] == ["initial-access", "exfiltration", "command-and-control"]
    main = [e for e in g["edges"] if not e.get("supporting")]
    assert [e["label"] for e in main] == ["1. port scan x10", "2. web sql injection x10", "3. rare path x10",
                                          "4. transfer x10"]
    assert [e["step"] for e in g["edges"]] == [1, 2, 2, 3, 4, 4, 4]          # each anomaly next to its parent


def test_incident_lines_and_tactics_include_supporting():
    xs = chain_a()
    alerts = pl.DataFrame(xs).with_columns(pl.col("host", "user", "url", "technique_name").cast(pl.Utf8),
                                           pl.col("incident_number").cast(pl.Int64))
    ev = evidence_for(xs, per=2)
    incs = pl.DataFrame({"incident_id": ["i1"], "incident_number": [1]})
    mem = pl.DataFrame({"incident_id": ["i1"] * len(xs), "alert_id": [a["alert_id"] for a in xs]})
    chains, lines = ch.build_chains(incs, mem, alerts, ev, NET)
    c = chains[0]
    assert lines.height == 14
    step_of = dict(lines.select("alert_id", "step").unique().iter_rows())
    assert step_of == {"r02": 1, "a09": 2, "r16": 2, "r20": 3, "a10": 4, "a11": 4, "r12": 4}
    assert c["tactics"] == ["discovery", "initial-access", "persistence", "exfiltration", "command-and-control"]
    assert c["chain_text"] == "1. Discovery → 2. Initial Access → 3. Persistence → 4. Exfiltration"
    assert not any("Command and Control" in x for x in c["gaps"])
    assert {e["step"] for e in c["graph"]["edges"]} == {1, 2, 3, 4}


# ── provisional bundle files ─────────────────────────────────────────────────

def _bundle(tmp_path=None):
    xs = [al("a1", "R02-port-scan", 0, src_ip="32.127.48.11", dst_ip="10.10.20.20"),
          al("a2", "R16-web-sql-injection", 16, tactic="initial-access", src_ip="32.127.48.11", dst_ip="10.10.20.20"),
          al("a3", "R12-transfer", 400, tactic="exfiltration", src_ip="32.127.48.11", dst_ip="10.10.20.20")]
    alerts = pl.DataFrame(xs).with_columns(pl.col("host", "user", "url", "technique_name").cast(pl.Utf8),
                                           pl.col("incident_number").cast(pl.Int64))
    ev = evidence_for(xs)
    res = ce.correlate(alerts, ev, NET, load_settings())
    alerts_json = [{**{k: v for k, v in a.items() if k != "src_count"}, "ts_start": ch.iso_z(a["ts_start"]),
                    "ts_end": ch.iso_z(a["ts_end"])} for a in xs]
    return xs, alerts, ev, res, alerts_json


def test_assembled_incident_is_valid():
    xs, alerts, ev, res, aj = _bundle()
    chains, lines = ch.build_chains(res["incidents"], res["incident_alerts"], alerts, ev, NET)
    inc = files.assemble(res["incidents"].row(0, named=True), chains[0])
    index = files.index_rows([inc], "t")
    out = files.alerts_with_incidents(aj, res["incident_alerts"])
    assert files.check([inc], index, out) == []
    assert C.validate_bundle(inc, index, out) == []
    assert inc["risk_score"] == sum(p["points"] for p in inc["risk_parts"].values())
    assert {a["incident_number"] for a in out} == {1}
    assert lines.height == 9 and set(lines["step"]) == {1, 2, 3}


def test_write_replaces_old_incidents(tmp_path):
    xs, alerts, ev, res, aj = _bundle()
    chains, _ = ch.build_chains(res["incidents"], res["incident_alerts"], alerts, ev, NET)
    inc = files.assemble(res["incidents"].row(0, named=True), chains[0])
    (tmp_path / "incidents").mkdir()
    (tmp_path / "incidents" / "9.json").write_text("{}", encoding="utf-8")
    files.write(tmp_path, [inc], files.index_rows([inc], "t"), aj, {"chain/_stats.json": {"stage": "chain"}})
    assert sorted(p.name for p in (tmp_path / "incidents").iterdir()) == ["1.json"]
    assert not list(tmp_path.rglob("*.tmp")) and not (tmp_path / "incidents.old").exists()
    assert json.loads((tmp_path / "chain" / "_stats.json").read_text(encoding="utf-8")) == {"stage": "chain"}


# ── CLI ──────────────────────────────────────────────────────────────────────

def _run_folder(tmp_path):
    xs, alerts, ev, res, aj = _bundle()
    alerts.write_parquet(tmp_path / "alerts.parquet")
    ev.write_parquet(tmp_path / "alert_evidence.parquet")
    (tmp_path / "alerts.json").write_text(json.dumps(aj), encoding="utf-8")
    assert correlate_main(["--run", str(tmp_path)]) == 0


def test_cli_builds_and_prints(tmp_path, capsys):
    _run_folder(tmp_path)
    assert chain_main(["--run", str(tmp_path)]) == 0
    for name in ("chains.json", "incident_lines.parquet", "index.json", "incidents/1.json"):
        assert (tmp_path / name).exists(), name
    st = json.loads((tmp_path / "chain" / "_stats.json").read_text(encoding="utf-8"))
    assert st["stage"] == "chain" and st["steps"] == 3 and isinstance(st["wall_secs"], float)
    aj = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert {a["incident_number"] for a in aj} == {1}
    inc = json.loads((tmp_path / "incidents" / "1.json").read_text(encoding="utf-8"))
    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert C.validate_bundle(inc, index, aj) == []
    capsys.readouterr()
    assert chain_main(["--run", str(tmp_path), "1"]) == 0
    out = capsys.readouterr().out
    assert inc["chain_text"] in out and " 1. " in out and "reach next:" in out
    assert chain_main(["--run", str(tmp_path), "7"]) == 1


def test_cli_missing_inputs(tmp_path, capsys):
    assert chain_main(["--run", str(tmp_path)]) == 1
    assert "detect" in capsys.readouterr().err


def test_cli_contract_error_writes_nothing(tmp_path, monkeypatch, capsys):
    _run_folder(tmp_path)
    before = (tmp_path / "alerts.json").read_bytes()
    monkeypatch.setattr(files, "check", lambda *a, **k: ["boom"])
    assert chain_main(["--run", str(tmp_path)]) == 1
    assert "boom" in capsys.readouterr().err
    assert not (tmp_path / "incidents").exists() and not (tmp_path / "chains.json").exists()
    assert (tmp_path / "alerts.json").read_bytes() == before


# ── real run ─────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not (REAL_RUN / "incidents.parquet").exists(), reason="real run not built")
def test_real_run_chains():
    inc = pl.read_parquet(REAL_RUN / "incidents.parquet")
    mem = pl.read_parquet(REAL_RUN / "incident_alerts.parquet")
    alerts = pl.read_parquet(REAL_RUN / "alerts.parquet")
    ev = pl.read_parquet(REAL_RUN / "alert_evidence.parquet")
    chains, lines = ch.build_chains(inc, mem, alerts, ev, NET)
    src = dict(alerts.select("alert_id", "src_ip").iter_rows())
    layer = dict(alerts.select("alert_id", "layer").iter_rows())

    def chain_of(ip):
        c = [c for c in chains if any(src.get(s["alert_id"]) == ip and s["layer"] == "rule" for s in c["chain"])]
        assert len(c) == 1
        return c[0]

    def sup3(step):
        return [x["rule_id"][:3] for x in step["supporting"]]

    a = chain_of("32.127.48.11")
    assert [s["rule_id"][:3] for s in a["chain"]] == ["R02", "R16", "R20", "R12"]   # scan -> SQLi -> web shell -> data out
    assert a["chain_text"] == "1. Discovery → 2. Initial Access → 3. Persistence → 4. Exfiltration"
    assert [sup3(s) for s in a["chain"]] == [[], ["A09"], [], ["A10", "A11"]]
    b = chain_of("10.10.10.118")
    assert [s["rule_id"][:3] for s in b["chain"]] == ["R24", "R11", "R12"]          # malware -> beaconing -> exfil
    assert b["chain_text"] == "1. Execution → 2. Command and Control → 3. Exfiltration"
    assert [sup3(s) for s in b["chain"]] == [[], [], ["A10", "A04", "A08", "A04", "A08"]]
    # every anomaly member appears exactly once as supporting; every numbered step is a rule step
    by_inc = {}
    for iid, aid in mem.select("incident_id", "alert_id").iter_rows():
        by_inc.setdefault(iid, set()).add(aid)
    for c in chains:
        sup = [x["alert_id"] for s in c["chain"] for x in s["supporting"]]
        assert len(sup) == len(set(sup))
        assert set(sup) == {x for x in by_inc[c["incident_id"]] if layer[x] == "anomaly"}
        assert all(s["layer"] == "rule" for s in c["chain"])
    assert sum(len(c["chain"]) for c in chains) == 32
    assert sum(len(s["supporting"]) for c in chains for s in c["chain"]) == 24
    assert lines.height == 44622
    aj = json.loads((REAL_RUN / "alerts.json").read_text(encoding="utf-8"))
    out = files.alerts_with_incidents(aj, mem)
    by_id = {c["incident_id"]: c for c in chains}
    bundle = [files.assemble(r, by_id[r["incident_id"]]) for r in inc.iter_rows(named=True)]
    index = files.index_rows(bundle, "firex-10G")
    for i in bundle:
        assert C.validate_bundle(i, index, out) == []
        assert all(s["line_total"] >= 1 for s in i["chain"])
        assert {e["step"] for e in i["graph"]["edges"]} == {s["n"] for s in i["chain"]}   # every step drawn
        assert sum(bool(e.get("supporting")) for e in i["graph"]["edges"]) >= \
            sum(len(s["supporting"]) for s in i["chain"])                                # anomalies drawn too
