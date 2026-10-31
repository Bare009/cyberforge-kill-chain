"""Correlation: entity rows, hub cap, link weights, time rule, union-find, promotion and anomaly handling."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import pytest

from killchain import db
from killchain.correlate import engine as ce
from killchain.correlate import entities as en
from killchain.correlate.cli import main as correlate_main

ROOT = Path(__file__).resolve().parents[1]
REAL_RUN = ROOT / "data" / "runs" / "firex-10G"
T0 = datetime(2026, 10, 28, 20, 0, tzinfo=timezone.utc)
NET = db.load_network()
SET = en.load_settings()

DEFAULTS = {"layer": "rule", "title": "t", "technique": "T1046", "tactic": "discovery", "stage_no": 9,
            "severity": 4, "confidence": 0.85, "promote": False, "src_ip": None, "dst_ip": None, "host": None,
            "user": None, "domain": None, "event_count": 1}
SCHEMA = {"alert_id": pl.Utf8, "rule_id": pl.Utf8, "layer": pl.Utf8, "title": pl.Utf8, "technique": pl.Utf8,
          "tactic": pl.Utf8, "stage_no": pl.Int64, "severity": pl.Int64, "confidence": pl.Float64,
          "promote": pl.Boolean, "ts_start": pl.Datetime("us", "UTC"), "ts_end": pl.Datetime("us", "UTC"),
          "src_ip": pl.Utf8, "dst_ip": pl.Utf8, "host": pl.Utf8, "user": pl.Utf8, "domain": pl.Utf8,
          "event_count": pl.Int64}


def make_alerts(rows):
    """rows: dicts with alert_id, rule_id, start (minutes after T0), optional minutes (length) and any alert column.
    Returns (alerts, evidence); each alert gets one evidence line of its own."""
    out = []
    for r in rows:
        d = {**DEFAULTS, **{k: v for k, v in r.items() if k not in ("start", "minutes")}}
        d["ts_start"] = T0 + timedelta(minutes=r["start"])
        d["ts_end"] = d["ts_start"] + timedelta(minutes=r.get("minutes", 5))
        out.append(d)
    alerts = pl.DataFrame(out, schema=SCHEMA)
    ev = pl.DataFrame([{"alert_id": d["alert_id"], "source": "x.log", "line": i + 1} for i, d in enumerate(out)],
                      schema={"alert_id": pl.Utf8, "source": pl.Utf8, "line": pl.Int64})
    return alerts, ev


def run(rows, settings=SET):
    a, ev = make_alerts(rows)
    return ce.correlate(a, ev, NET, settings)


def groups(res):
    """Sorted list of sorted member alert-id lists."""
    m = res["incident_alerts"]
    return sorted(sorted(g["alert_id"].to_list()) for _, g in m.group_by("incident_id"))


# ── entities and hubs ────────────────────────────────────────────────────────

def test_classify_ip():
    assert en.classify_ip("10.10.10.118", NET) == (True, "desktop", "user-desktop")
    assert en.classify_ip("32.127.48.11", NET) == (False, "internet", "internet")
    assert en.classify_ip("71.54.76.0/24", NET) == (False, "internet", "internet")
    assert en.classify_ip("10.10.20.20", NET)[1:] == ("dmz", "web-portal")
    assert en.classify_ip(None, NET) == (None, "unknown", None)
    assert en.classify_ip("not-an-ip", NET) == (None, "unknown", None)


def test_entity_rows_normalise():
    a, _ = make_alerts([{"alert_id": "a", "rule_id": "R", "start": 0, "src_ip": "10.10.10.118",
                         "user": "Keerat.Ghughal", "domain": "Portal.Corp.Local"}])
    rows = en.entity_rows(a, NET)
    assert set(rows["kind"]) == {"ip", "user", "domain"}
    u = rows.filter(pl.col("kind") == "user").row(0, named=True)
    assert u["value"] == "keerat.ghughal" and u["display"] == "Keerat.Ghughal"
    ip = rows.filter(pl.col("kind") == "ip").row(0, named=True)
    assert ip["role"] == "src" and ip["internal"] is True and ip["zone"] == "desktop"


def test_fixed_hubs():
    a, _ = make_alerts([{"alert_id": "a", "rule_id": "R", "start": 0, "src_ip": "1.2.3.4"}])
    hubs = en.find_hubs(en.entity_rows(a, NET), NET, SET)
    assert {("ip", "10.10.20.20"), ("ip", "10.10.99.1"), ("ip", "203.0.113.5"), ("user", "admin"),
            ("domain", "portal.corp.local")} <= hubs
    assert ("ip", "1.2.3.4") not in hubs


def test_dynamic_hub_needs_share_and_sources():
    # 10.10.20.50 is in 4 of 10 alerts (40 %) but always with the same one source: not a hub
    rows = [{"alert_id": f"a{i}", "rule_id": "R", "start": i, "src_ip": "10.10.10.5", "dst_ip": "10.10.20.50"}
            for i in range(4)]
    rows += [{"alert_id": f"b{i}", "rule_id": "R", "start": i, "src_ip": f"9.9.9.{i}"} for i in range(6)]
    a, _ = make_alerts(rows)
    assert ("ip", "10.10.20.50") not in en.find_hubs(en.entity_rows(a, NET), NET, SET)
    # the same share with 6 different sources: a hub
    rows = [{"alert_id": f"a{i}", "rule_id": "R", "start": i, "src_ip": f"10.10.10.{i + 1}", "dst_ip": "10.10.20.50"}
            for i in range(6)]
    rows += [{"alert_id": f"b{i}", "rule_id": "R", "start": i, "src_ip": f"9.9.9.{i}"} for i in range(9)]
    a, _ = make_alerts(rows)
    assert ("ip", "10.10.20.50") in en.find_hubs(en.entity_rows(a, NET), NET, SET)


# ── union-find and time rule ─────────────────────────────────────────────────

def test_union_find():
    uf = ce.UnionFind(["a", "b", "c", "d", "e"])
    uf.union("a", "b")
    uf.union("c", "d")
    uf.union("b", "d")
    assert uf.groups() == [["a", "b", "c", "d"], ["e"]]
    assert uf.find("d") == uf.find("a")


def _al(start_min, minutes, stage):
    s = T0 + timedelta(minutes=start_min)
    return {"ts_start": s, "ts_end": s + timedelta(minutes=minutes), "stage_no": stage}


def test_time_rule():
    early = _al(0, 10, 5)
    assert ce.time_ok(early, _al(10 + 119, 5, 1), False, SET)              # 1 h 59 gap, any stage
    assert not ce.time_ok(early, _al(10 + 121, 5, 13), False, SET)         # > 2 h, no strong share
    assert ce.time_ok(early, _al(10 + 7 * 60, 5, 13), True, SET)           # widened: later stage, strong
    assert not ce.time_ok(early, _al(10 + 7 * 60, 5, 3), True, SET)        # widened needs stage not lower
    assert not ce.time_ok(early, _al(10 + 73 * 60, 5, 13), True, SET)      # beyond 72 h
    assert ce.time_ok(_al(0, 600, 9), _al(30, 5, 3), False, SET)           # overlap counts as gap 0


# ── links and components ─────────────────────────────────────────────────────

CHAIN_A = [
    {"alert_id": "a1", "rule_id": "R02", "start": 0, "minutes": 2, "stage_no": 9, "src_ip": "32.127.48.11",
     "dst_ip": "10.10.20.20"},
    {"alert_id": "a2", "rule_id": "R16", "start": 16, "stage_no": 3, "tactic": "initial-access",
     "src_ip": "32.127.48.11", "dst_ip": "10.10.20.20", "domain": "portal.corp.local"},
    {"alert_id": "a3", "rule_id": "R20", "start": 50, "minutes": 20, "stage_no": 5, "tactic": "persistence",
     "src_ip": "32.127.48.11", "dst_ip": "10.10.20.20"},
    {"alert_id": "a4", "rule_id": "R12", "start": 70 + 7 * 60, "stage_no": 13, "tactic": "exfiltration",
     "src_ip": "32.127.48.11", "dst_ip": "10.10.20.20"},
]


def test_chain_a_shape_is_one_incident():
    res = run(CHAIN_A)
    assert groups(res) == [["a1", "a2", "a3", "a4"]]
    steps = res["incident_alerts"].sort("step_n")
    assert steps["alert_id"].to_list() == ["a1", "a2", "a3", "a4"] and steps["step_n"].to_list() == [1, 2, 3, 4]
    inc = res["incidents"].row(0, named=True)
    assert inc["merged"] == {"alerts": 4, "events": 4} and inc["promoted_by"] == "rules>=2"
    assert "32.127.48.11" in inc["entities"]["ips"] and "10.10.20.20" in inc["entities"]["ips"]   # hubs listed
    assert inc["title"] == "Discovery to Exfiltration by 32.127.48.11"


def test_long_gap_to_lower_stage_splits():
    rows = [CHAIN_A[2], {**CHAIN_A[3], "stage_no": 3, "tactic": "initial-access"}]
    assert groups(run(rows)) == [["a3"], ["a4"]]


def test_fixed_hub_does_not_link():
    rows = [{"alert_id": "x", "rule_id": "R17", "start": 0, "src_ip": "1.1.1.1", "dst_ip": "10.10.20.20"},
            {"alert_id": "y", "rule_id": "R18", "start": 10, "src_ip": "2.2.2.2", "dst_ip": "10.10.20.20"}]
    assert groups(run(rows)) == [["x"], ["y"]]


def test_internal_target_alone_does_not_link_but_user_plus_target_does():
    rows = [{"alert_id": "x", "rule_id": "R1", "start": 0, "src_ip": "1.1.1.1", "dst_ip": "10.10.20.14"},
            {"alert_id": "y", "rule_id": "R2", "start": 30, "src_ip": "2.2.2.2", "dst_ip": "10.10.20.14"}]
    assert groups(run(rows)) == [["x"], ["y"]]
    rows = [dict(r, user="bob") for r in rows]
    a, _ = make_alerts(rows)
    pw = ce.pair_weights(en.entity_rows(a, NET), en.find_hubs(en.entity_rows(a, NET), NET, SET), SET)
    assert pw[("x", "y")]["weight"] == pytest.approx(1.3)
    assert groups(run(rows)) == [["x", "y"]]


def test_internal_source_of_both_links():
    rows = [{"alert_id": "x", "rule_id": "R24", "start": 0, "src_ip": "10.10.10.118", "dst_ip": "7.154.5.35"},
            {"alert_id": "y", "rule_id": "R09", "start": 30, "src_ip": "10.10.10.118", "dst_ip": "10.10.20.5"}]
    assert groups(run(rows)) == [["x", "y"]]


# ── promotion ────────────────────────────────────────────────────────────────

def test_promotion_bar():
    weak = {"alert_id": "w", "rule_id": "R1", "start": 0, "severity": 3, "src_ip": "1.1.1.1"}
    res = run([weak])
    assert res["incidents"].height == 0 and res["stats"]["below_bar"] == 1
    res = run([dict(weak, promote=True)])
    assert res["incidents"]["promoted_by"].to_list() == ["promote rule"]
    res = run([weak, dict(weak, alert_id="w2", rule_id="R2", start=10)])
    assert res["incidents"]["promoted_by"].to_list() == ["rules>=2"]
    res = run([dict(weak, severity=4, confidence=0.7)])
    assert res["incidents"]["promoted_by"].to_list() == ["single severe alert"]
    res = run([dict(weak, severity=4, confidence=0.69)])
    assert res["incidents"].height == 0


def test_anomaly_cannot_promote_weak_rule_component():
    rows = [{"alert_id": "w", "rule_id": "R1", "start": 0, "severity": 3, "src_ip": "1.1.1.1"},
            {"alert_id": "n", "rule_id": "A04", "layer": "anomaly", "start": 5, "severity": 5, "confidence": 0.9,
             "src_ip": "1.1.1.1"}]
    res = run(rows)
    assert res["incidents"].height == 0 and res["unexplained"]["alert_id"].to_list() == ["n"]


# ── anomaly join and anomaly-only incidents ──────────────────────────────────

def test_anomaly_joins_only_the_stronger_component():
    rows = [{"alert_id": "r1", "rule_id": "R24", "start": 0, "src_ip": "10.10.10.118", "dst_ip": "7.154.5.35",
             "user": "bob"},
            {"alert_id": "r2", "rule_id": "R09", "start": 60, "src_ip": "10.10.10.200", "dst_ip": "10.10.10.118"},
            {"alert_id": "n1", "rule_id": "A04", "layer": "anomaly", "start": 20, "severity": 2, "confidence": 0.3,
             "src_ip": "10.10.10.118", "dst_ip": "10.10.20.5", "user": "bob"}]
    res = run(rows)
    assert groups(res) == [["n1", "r1"], ["r2"]]
    m = res["incident_alerts"].filter(pl.col("alert_id") == "n1").row(0, named=True)
    assert m["joined"] == "extra" and res["stats"]["anomaly_joined"] == 1


def test_anomaly_does_not_bridge_rule_components():
    rows = [{"alert_id": "r1", "rule_id": "R1", "start": 0, "src_ip": "10.10.10.118"},
            {"alert_id": "r2", "rule_id": "R2", "start": 30, "src_ip": "10.10.10.200", "user": "bob"},
            {"alert_id": "n1", "rule_id": "A04", "layer": "anomaly", "start": 15, "severity": 2, "confidence": 0.3,
             "src_ip": "10.10.10.118", "user": "bob"}]
    res = run(rows)
    assert groups(res) == [["n1", "r1"], ["r2"]]


def test_anomaly_only_two_detectors_is_an_incident():
    base = {"layer": "anomaly", "severity": 2, "confidence": 0.3, "src_ip": "10.10.10.63"}
    res = run([dict(base, alert_id="n1", rule_id="A04", start=0), dict(base, alert_id="n2", rule_id="A05", start=30)])
    assert groups(res) == [["n1", "n2"]]
    assert res["incidents"]["promoted_by"].to_list() == ["two anomaly detectors"]
    assert res["stats"]["anomaly_only_incidents"] == 1 and res["unexplained"].height == 0


def test_anomaly_single_or_same_detector_is_unexplained():
    base = {"layer": "anomaly", "severity": 2, "confidence": 0.3, "src_ip": "10.10.10.63"}
    res = run([dict(base, alert_id="n1", rule_id="A04", start=0)])
    assert res["incidents"].height == 0 and res["unexplained"]["alert_id"].to_list() == ["n1"]
    res = run([dict(base, alert_id="n1", rule_id="A04", start=0), dict(base, alert_id="n2", rule_id="A04", start=30)])
    u = res["unexplained"]
    assert res["incidents"].height == 0 and sorted(u["alert_id"]) == ["n1", "n2"] and u["group_id"].n_unique() == 1
    assert set(u["reason"]) == {"single anomaly detector"}
    # two detectors more than an hour apart are not enough
    res = run([dict(base, alert_id="n1", rule_id="A04", start=0, minutes=5),
               dict(base, alert_id="n2", rule_id="A05", start=90)])
    assert res["incidents"].height == 0


def test_incident_id_is_stable_under_shuffle():
    ids = set(run(CHAIN_A)["incidents"]["incident_id"])
    rows = list(CHAIN_A)
    random.Random(3).shuffle(rows)
    assert set(run(rows)["incidents"]["incident_id"]) == ids
    assert ids == {ce.short_hash(["a1", "a2", "a3", "a4"])}


def test_contract_fields():
    res = run(CHAIN_A + [{"alert_id": "z", "rule_id": "R03", "start": 0, "src_ip": "10.10.40.72",
                          "dst_ip": "154.35.54.115", "tactic": "command-and-control", "stage_no": 12}])
    assert ce.contract_errors(res, {"a1", "a2", "a3", "a4", "z"}) == []
    assert ce.contract_errors(res, {"a1"})                       # chain alerts must be known alerts
    assert res["incidents"]["incident_number"].to_list() == [1, 2]


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_cli_writes_outputs(tmp_path, capsys):
    a, ev = make_alerts(CHAIN_A + [{"alert_id": "n9", "rule_id": "A01", "layer": "anomaly", "start": 3000,
                                    "src_ip": "9.9.9.9", "severity": 2, "confidence": 0.4}])
    a.write_parquet(tmp_path / "alerts.parquet")
    ev.write_parquet(tmp_path / "alert_evidence.parquet")
    assert correlate_main(["--run", str(tmp_path)]) == 0
    assert pl.read_parquet(tmp_path / "incidents.parquet").height == 1
    assert pl.read_parquet(tmp_path / "incident_alerts.parquet").height == 4
    assert pl.read_parquet(tmp_path / "unexplained.parquet")["alert_id"].to_list() == ["n9"]
    st = json.loads((tmp_path / "correlate" / "_stats.json").read_text(encoding="utf-8"))
    assert st["stage"] == "correlate" and st["incidents"] == 1 and "wall_secs" in st
    assert "#1 " in capsys.readouterr().out


def test_cli_missing_inputs(tmp_path):
    assert correlate_main(["--run", str(tmp_path)]) == 1


# ── real run ─────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not (REAL_RUN / "alerts.parquet").exists(), reason="real run not built")
def test_real_run_chains():
    alerts = pl.read_parquet(REAL_RUN / "alerts.parquet")
    ev = pl.read_parquet(REAL_RUN / "alert_evidence.parquet", columns=["alert_id", "source", "line"])
    res = ce.correlate(alerts, ev, NET, SET)
    m = res["incident_alerts"].join(alerts.select("alert_id", "src_ip"), on="alert_id")

    def rules_of(ip):
        inc = m.filter((pl.col("src_ip") == ip) & (pl.col("layer") == "rule"))["incident_id"].unique()
        assert inc.len() == 1, f"{ip} split over {inc.len()} incidents"
        return sorted(m.filter((pl.col("incident_id") == inc[0]) & (pl.col("layer") == "rule"))["rule_id"])

    assert rules_of("32.127.48.11") == ["R02-port-scan", "R12-large-lopsided-transfer", "R16-web-sql-injection",
                                        "R20-web-shell"]
    assert rules_of("10.10.10.118") == ["R11-beaconing", "R12-large-lopsided-transfer",
                                        "R24-malware-detected-not-blocked"]
    assert rules_of("203.228.177.117") == ["R05-admin-login-odd-hour", "R15-rogue-admin"]
    assert rules_of("10.10.10.44") == ["R09-lateral-movement", "R13-insider-drift"]
    assert res["incidents"].height <= 35
    assert res["incidents"]["merged"].struct.field("alerts").max() <= 15
    assert ce.contract_errors(res, set(alerts["alert_id"])) == []
