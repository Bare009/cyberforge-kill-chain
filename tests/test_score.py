"""Risk score parts, ranking and the score CLI (docs/build-plan.md P10, B-1)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from killchain import contracts as C
from killchain import db
from killchain.graph import chain as ch
from killchain.graph import incident_files as files
from killchain.graph import path as gp
from killchain.score import risk
from killchain.score.cli import main as score_main
from test_chain import al, evidence_for

NET = db.load_network()
ATTACKER = "32.127.48.11"
PORTAL = "10.10.20.20"
NEXT = {"reachable": [], "sentence": "No internal reach observed in the logs: test.", "likely_tactics": []}


def make_inc(xs, number=1, iid="inc-1", nxt=None, title="test incident"):
    """A contract-C incident from alert dicts (test_chain.al), built the way chain and reach build it."""
    steps = ch.build_steps(xs, evidence_for(xs), NET)
    sup = [x for s in steps for x in s["supporting"]]
    part = {"chain": steps, "chain_text": ch.chain_text(steps),
            "gaps": ch.gaps((s["stage_no"] for s in steps), (x["stage_no"] for x in sup)),
            "tactics": list(dict.fromkeys(s["tactic"] for s in steps)),
            "techniques": list(dict.fromkeys(s["technique"] for s in steps)),
            "graph": gp.path_graph(steps, {a["alert_id"]: a for a in xs}, NET)}
    ips = sorted({a[k] for a in xs for k in ("src_ip", "dst_ip") if a.get(k)})
    row = {"incident_number": number, "incident_id": iid, "title": title,
           "severity": max(a["severity"] for a in xs),
           "ts_start": min(a["ts_start"] for a in xs), "ts_end": max(a["ts_end"] for a in xs),
           "merged": {"alerts": len(xs), "events": sum(a["event_count"] for a in xs)},
           "entities": {"ips": ips, "hosts": [], "users": sorted({a["user"] for a in xs if a.get("user")}),
                        "domains": []},
           "layers": sorted({a.get("layer") or "rule" for a in xs})}
    return files.assemble(row, part, copy.deepcopy(nxt or NEXT))


def chain_a(prefix="a", start=0, src=ATTACKER, dst=PORTAL):
    return [al(f"{prefix}1", "R02-port-scan", start, src_ip=src, dst_ip=dst),
            al(f"{prefix}2", "R16-web-sql-injection", start + 16, tactic="initial-access", src_ip=src, dst_ip=dst),
            al(f"{prefix}3", "R12-transfer", start + 400, tactic="exfiltration", src_ip=src, dst_ip=dst)]


def weak(prefix="w", start=0):
    """One blocked port scan, severity 2, from the internet against a desktop."""
    return [al(f"{prefix}1", "R02-port-scan", start, src_ip="45.74.28.9", dst_ip="10.10.10.50", severity=2,
               success=False)]


def reach_row(host, kind="observed"):
    return {"host": host, "zone": gp.node_for(host, "ip", NET)["zone"], "hop": 1, "kind": kind,
            "via": [{"from": PORTAL, "edge": "allowed_flow", "count": 3, "lines": []}]}


def scored(inc, enrichment=None):
    return risk.apply_risk(inc, risk.risk_parts(inc, NET, enrichment))


# ── parts ────────────────────────────────────────────────────────────────────

def test_parts_values_and_details():
    inc = scored(make_inc(chain_a()))
    p = inc["risk_parts"]
    assert list(p) == list(files.RISK_WEIGHTS)
    assert (p["severity"]["value"], p["severity"]["detail"]) == (0.8, "highest alert severity 4 of 5")
    assert (p["stage"]["value"], p["stage"]["detail"]) == (0.9286, "furthest stage Exfiltration (13 of 14)")
    assert (p["breadth"]["value"], p["breadth"]["detail"]) == (0.5, "3 distinct tactics (full marks at 6)")
    assert (p["success"]["value"], p["success"]["detail"]) == (1.0, "step 1 got through")
    assert (p["asset"]["value"], p["asset"]["detail"]) == (0.75, f"portal ({PORTAL}) (dmz, importance 0.75)")
    assert (p["reach"]["value"], p["reach"]["detail"]) == (0.0, "no important host reachable next")
    assert p["threat_intel"]["value"] == 0.0
    for k, x in p.items():
        assert x["weight"] == files.RISK_WEIGHTS[k]
        assert x["points"] == round(x["value"] * x["weight"] * 100, 2)
    assert inc["risk_score"] == round(sum(x["points"] for x in p.values()), 1) == 69.8
    assert inc["risk_band"] == "high"
    assert C.validate_incident(inc) == []


def test_blocked_and_single_step():
    inc = scored(make_inc(weak()))
    p = inc["risk_parts"]
    assert p["success"]["detail"] == "every step was blocked" and p["success"]["value"] == 0
    assert p["breadth"]["detail"] == "1 distinct tactic (full marks at 6)"
    assert p["asset"]["value"] == 0.25 and p["asset"]["detail"].startswith("10.10.10.50 (desktop")


@pytest.mark.parametrize("score,band", [(75.0, "critical"), (74.9, "high"), (50.0, "high"), (49.9, "medium"),
                                        (25.0, "medium"), (24.9, "low"), (0, "low")])
def test_bands(score, band):
    assert risk.band(score) == band


def test_breadth_capped():
    tactics = ["reconnaissance", "initial-access", "execution", "persistence", "credential-access", "discovery",
               "lateral-movement", "command-and-control"]
    xs = [al(f"t{i}", f"R{i:02d}-x", i * 10, tactic=t, src_ip=ATTACKER, dst_ip=PORTAL) for i, t in enumerate(tactics)]
    p = scored(make_inc(xs))["risk_parts"]["breadth"]
    assert p["value"] == 1.0 and p["detail"] == "8 distinct tactics (full marks at 6)"


def test_reach_part():
    servers = ["10.10.20.31", "10.10.20.32"]
    rows = [reach_row(h) for h in servers] + [reach_row(h, "inferred") for h in ("10.10.20.33", "10.10.20.34")]
    rows += [reach_row(f"10.10.10.{i}") for i in range(5)]
    p = scored(make_inc(chain_a(), nxt={**NEXT, "reachable": rows}))["risk_parts"]["reach"]
    assert p["value"] == 1.0
    assert p["detail"] == "2 observed and 2 inferred important hosts reachable next (server, DMZ, management)"
    p = scored(make_inc(chain_a(), nxt={**NEXT, "reachable": [reach_row("10.10.99.1")]}))["risk_parts"]["reach"]
    assert p["value"] == 0.3333 and p["points"] == 3.33
    desk = [reach_row(f"10.10.10.{i}") for i in range(5)]
    p = scored(make_inc(chain_a(), nxt={**NEXT, "reachable": desk}))["risk_parts"]["reach"]
    assert p["value"] == 0 and p["detail"] == "no important host reachable next"


def test_asset_ignores_reach_external_accounts_domains():
    inc = make_inc(weak())                                   # desktop 10.10.10.50, importance 0.25
    inc["graph"]["nodes"] += [{**gp.node_for("10.10.99.1", "ip", NET), "reach": "observed"},
                              gp.node_for("8.8.8.8", "ip", NET), gp.node_for("root", "user", NET),
                              gp.node_for("evil.example", "domain", NET)]
    assert scored(inc)["risk_parts"]["asset"]["value"] == 0.25
    inc["graph"]["nodes"].append(gp.node_for("10.10.99.1", "ip", NET))       # the firewall, touched
    p = scored(inc)["risk_parts"]["asset"]
    assert p["value"] == 1.0 and "10.10.99.1" in p["detail"] and "mgmt" in p["detail"]


def test_asset_none():
    xs = [al("n1", "R02-port-scan", 0, src_ip=ATTACKER, dst_ip="8.8.8.8")]
    p = scored(make_inc(xs))["risk_parts"]["asset"]
    assert p["value"] == 0 and p["detail"] == "no internal host or firewall touched"


def test_supporting_anomalies_do_not_raise_stage_breadth_success():
    base = weak()
    plain = scored(make_inc(base))["risk_parts"]
    xs = base + [al("x1", "A10-lopsided", 1, tactic="impact", layer="anomaly", src_ip="45.74.28.9",
                    dst_ip="10.10.10.50", success=True)]
    inc = scored(make_inc(xs))
    assert inc["chain"][0]["supporting"] and len(inc["chain"]) == 1
    for k in ("stage", "breadth", "success"):
        assert inc["risk_parts"][k] == plain[k]


def test_anomaly_only_incident_uses_its_numbered_steps():
    xs = [al("y1", "A01-rare", 0, tactic="discovery", layer="anomaly", src_ip=ATTACKER, dst_ip=PORTAL),
          al("y2", "A10-lopsided", 30, tactic="exfiltration", layer="anomaly", src_ip=ATTACKER, dst_ip=PORTAL)]
    inc = scored(make_inc(xs))
    assert [s["layer"] for s in inc["chain"]] == ["anomaly", "anomaly"]
    assert inc["risk_parts"]["stage"]["value"] == 0.9286 and inc["risk_parts"]["breadth"]["value"] == 0.3333


def test_threat_intel_part():
    inc = make_inc(chain_a())
    p = scored(inc)["risk_parts"]["threat_intel"]
    assert p["value"] == 0 and p["detail"] == risk.NO_TI_FILE
    doc = {"offline": False, "entities": {
        ATTACKER: {"verdict": "suspicious", "reputation": 0.6, "incidents": [7]},      # number is stale: ignored
        "8.8.8.8": {"verdict": "known-malicious", "reputation": 0.95, "incidents": [1]},  # not in this incident
    }}
    p = scored(inc, doc)["risk_parts"]["threat_intel"]
    assert p["value"] == 0.6 and p["points"] == 3.0
    assert p["detail"] == f"highest reputation 0.60 ({ATTACKER}, suspicious)"
    p = scored(inc, {**doc, "offline": True})["risk_parts"]["threat_intel"]
    assert p["detail"].endswith(risk.OFFLINE_NOTE)
    p = scored(inc, {"entities": {"8.8.8.8": doc["entities"]["8.8.8.8"]}})["risk_parts"]["threat_intel"]
    assert p["value"] == 0 and p["detail"] == "no entity of this incident has a reputation score"
    unknown = {"entities": {ATTACKER: {"verdict": "unknown", "reputation": 0.0}}}        # nobody outside answered
    p = scored(inc, unknown)["risk_parts"]["threat_intel"]
    assert p["value"] == 0 and p["detail"] == "no entity of this incident has a reputation score"
    clean = {"entities": {ATTACKER: {"verdict": "no-reports", "reputation": 0.0}}}
    assert scored(inc, clean)["risk_parts"]["threat_intel"]["detail"] == \
        f"highest reputation 0.00 ({ATTACKER}, no-reports)"
    assert C.validate_incident(inc) == []


def test_rank_orders_and_breaks_ties():
    a = scored(make_inc(chain_a(), number=1, iid="b"))
    w = scored(make_inc(weak(start=-60), number=2, iid="w"))
    tie_late = scored(make_inc(chain_a("c", start=60), number=3, iid="a"))
    tie_same = scored(make_inc(chain_a("d"), number=4, iid="a0"))
    ranked, mapping = risk.rank([w, tie_late, a, tie_same])
    assert [i["incident_id"] for i in ranked] == ["a0", "b", "a", "w"]       # same start: incident_id decides
    assert [i["incident_number"] for i in ranked] == [1, 2, 3, 4]
    assert mapping == {4: 1, 1: 2, 3: 3, 2: 4}
    again, m2 = risk.rank(copy.deepcopy(ranked))
    assert again == ranked and m2 == {1: 1, 2: 2, 3: 3, 4: 4}


# ── CLI ──────────────────────────────────────────────────────────────────────

def alerts_json(xs, number):
    return [{**{k: v for k, v in a.items() if k != "src_count"}, "ts_start": ch.iso_z(a["ts_start"]),
             "ts_end": ch.iso_z(a["ts_end"]), "incident_number": number} for a in xs]


def write_bundle(run: Path, nxt=None):
    """Two incidents: #1 is a weak blocked scan, #2 chain A with reach (scores higher); one alert in none."""
    w = make_inc(weak(start=-60), number=1, iid="weak", nxt=nxt, title="weak scan")
    s = make_inc(chain_a(), number=2, iid="strong", nxt=nxt or {**NEXT, "reachable": [reach_row("10.10.20.31")]},
                 title="chain A")
    extra = {**alerts_json(weak("z", start=900), None)[0], "alert_id": "lonely"}
    alerts = alerts_json(weak(start=-60), 1) + alerts_json(chain_a(), 2) + [extra]
    incs = [w, s]
    index = files.index_rows(incs, run.name)
    assert files.check(incs, index, alerts) == []
    files.write(run, incs, index, alerts)
    return run


def rd(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def bundle_bytes(run: Path):
    out = {p.name: p.read_bytes() for p in (run / "incidents").iterdir()}
    for n in ("index.json", "alerts.json"):
        out[n] = (run / n).read_bytes()
    return out


def test_cli_scores_and_renumbers(tmp_path, capsys):
    run = write_bundle(tmp_path / "r")
    assert score_main(["--run", str(run)]) == 0
    first, second = rd(run / "incidents" / "1.json"), rd(run / "incidents" / "2.json")
    assert (first["incident_id"], second["incident_id"]) == ("strong", "weak")
    assert first["risk_score"] > second["risk_score"] and first["risk_parts"]["reach"]["value"] == 0.3333
    alerts = rd(run / "alerts.json")
    num = {a["alert_id"]: a["incident_number"] for a in alerts}
    assert num["a1"] == 1 and num["w1"] == 2 and num["lonely"] is None
    sc = rd(run / "score.json")
    assert {(x["incident_id"], x["number_before"], x["incident_number"]) for x in sc["incidents"]} == \
        {("strong", 2, 1), ("weak", 1, 2)}
    assert sc["threat_intel_source"] is None
    st = rd(run / "score" / "_stats.json")
    assert st["stage"] == "score" and st["incidents"] == 2 and st["contract_errors"] == 0
    index = rd(run / "index.json")
    assert [r["incident_id"] for r in index["incidents"]] == ["strong", "weak"]
    for inc in (first, second):
        assert C.validate_bundle(inc, index, alerts) == []
    out = capsys.readouterr().out
    assert "#1 " in out and "chain A" in out
    before = bundle_bytes(run)
    assert score_main(["--run", str(run)]) == 0
    assert bundle_bytes(run) == before
    capsys.readouterr()
    assert score_main(["--run", str(run), "1"]) == 0
    out = capsys.readouterr().out
    assert "Threat intel" in out and risk.NO_TI_FILE in out and "total" in out


def test_cli_reads_enrichment(tmp_path):
    run = write_bundle(tmp_path / "r")
    (run / "enrichment.json").write_text(json.dumps({"offline": True, "entities": {
        ATTACKER: {"verdict": "suspicious", "reputation": 0.4, "incidents": [2]}}}), encoding="utf-8")
    assert score_main(["--run", str(run)]) == 0
    p = rd(run / "incidents" / "1.json")["risk_parts"]["threat_intel"]
    assert p["value"] == 0.4 and p["detail"].endswith(risk.OFFLINE_NOTE)
    assert rd(run / "score.json")["threat_intel_source"] == "enrichment.json"


def test_cli_needs_reach(tmp_path, capsys):
    run = write_bundle(tmp_path / "r", nxt=dict(files.NEXT_PLACEHOLDER))
    before = bundle_bytes(run)
    assert score_main(["--run", str(run)]) == 1
    assert "reach" in capsys.readouterr().err
    assert bundle_bytes(run) == before and not (run / "score.json").exists()


def test_cli_missing_index(tmp_path, capsys):
    assert score_main(["--run", str(tmp_path)]) == 1
    assert "index.json" in capsys.readouterr().err
