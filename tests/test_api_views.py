"""Dashboard, Alerts, Unexplained and Rules endpoints (track B, P11 day 5)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from killchain.api import create_app

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


def rd(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def wr(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def run(tmp_path: Path) -> Path:
    """The sample plus one anomaly alert in no incident, detect stats and eval metrics."""
    r = tmp_path / "run"
    shutil.copytree(SAMPLE, r)
    alerts = rd(r / "alerts.json")
    lone = {**alerts[0], "alert_id": "lone0001", "rule_id": "A01-rare-event", "layer": "anomaly",
            "incident_number": None, "title": "Rare event", "severity": 2, "src_ip": "10.10.10.44",
            "dst_ip": "10.10.20.31", "ts_start": "2026-10-27T01:00:00.000000Z", "ts_end": "2026-10-27T01:05:00.000000Z"}
    wr(r / "alerts.json", alerts + [lone])
    wr(r / "unexplained.json", {"run": "sample-run", "alerts": [{**lone, "reason": "single anomaly detector",
                                                                  "group_id": "g1"}]})
    wr(r / "detect" / "_stats.json", {"stage": "detect", "per_rule": [
        {"rule_id": "A01-rare-event", "secs": 0.5, "evidence_lines": 3, "alerts": 1}]})
    wr(r / "metrics.json", {"per_rule": [{"rule_id": "A01-rare-event", "alerts": 1, "truth_lines": 0,
                                          "background_alerts": 1}]})
    return r


@pytest.fixture
def client(run, tmp_path):
    return TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True))


def test_dashboard_summary(client, run):
    d = client.get("/dashboard/summary").json()
    k = d["kpis"]
    assert k["incidents"] == 1 and k["alerts"] == len(rd(run / "alerts.json")) and k["unexplained"] == 1
    assert [b["band"] for b in d["incidents_by_band"]] == ["critical", "high", "medium", "low"]
    assert sum(b["incidents"] for b in d["incidents_by_band"]) == 1
    cov = {c["tactic"]: c for c in d["coverage"]}
    assert len(d["coverage"]) == 14 and [c["stage_no"] for c in d["coverage"]] == list(range(1, 15))
    inc = rd(run / "incidents" / "1.json")
    assert all(cov[t]["incidents"] == 1 for t in inc["tactics"])
    hours = d["alerts_per_hour"]
    assert hours and sum(h["alerts"] for h in hours) == k["alerts"]
    assert all(h["rule"] + h["anomaly"] + h["vendor"] == h["alerts"] for h in hours)
    assert d["top_attackers"][0]["value"] == "32.127.48.11" and d["top_attackers"][0]["incidents"] == [1]
    assert all(t["value"].startswith("10.") or t["value"].startswith("203.0.113") for t in d["top_targets"])
    assert d["worst_incidents"][0]["incident_number"] == 1
    assert d["threat_intel"]["providers"]["local"] == "ok"


def test_vendor_alerts_per_hour_and_filter(run, tmp_path):
    """Alerts another product raised (layer vendor) get their own hourly count and layer filter."""
    alerts = rd(run / "alerts.json")
    vend = {**alerts[0], "alert_id": "vend0001", "rule_id": "vendor:sentinelone:mimikatz", "layer": "vendor",
            "technique_source": "keyword", "incident_number": None, "title": "Mimikatz credential theft",
            "ts_start": "2026-10-27T01:10:00.000000Z", "ts_end": "2026-10-27T01:10:00.000000Z"}
    wr(run / "alerts.json", alerts + [vend])
    c = TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti2.sqlite", ti_offline=True))
    d = c.get("/dashboard/summary").json()
    hours = d["alerts_per_hour"]
    assert sum(h["vendor"] for h in hours) == 1 and d["alerts_by_layer"]["vendor"] == 1
    assert all(h["rule"] + h["anomaly"] + h["vendor"] == h["alerts"] for h in hours)
    body = c.get("/alerts?layer=vendor").json()
    assert [a["alert_id"] for a in body["alerts"]] == ["vend0001"] and body["alerts"][0]["technique_source"] == "keyword"
    m = c.get("/mitre/matrix", params={"source": "vendor"}).json()
    assert m["summary"]["alertsTotal"] == 1 and m["filters"]["sources"] == ["vendor"]
    assert c.get("/mitre/matrix", params={"source": "rule"}).json()["summary"]["alertsTotal"] == len(
        [a for a in alerts if a["layer"] == "rule"])
    assert c.get("/mitre/matrix", params={"source": "bogus"}).status_code == 422


def test_alerts_filters_and_counts(client, run):
    body = client.get("/alerts").json()
    assert body["total"] == body["counts"]["all"] == len(rd(run / "alerts.json"))
    assert body["counts"]["not_in_incident"] == 1 and body["counts"]["unexplained"] == 1
    starts = [a["ts_start"] for a in body["alerts"]]
    assert starts == sorted(starts, reverse=True)
    none = client.get("/alerts?incident=none").json()
    assert [a["alert_id"] for a in none["alerts"]] == ["lone0001"]
    assert client.get("/alerts?incident=1").json()["total"] == body["total"] - 1
    assert client.get("/alerts?incident=any").json()["total"] == body["total"] - 1
    assert client.get("/alerts?layer=anomaly").json()["total"] >= 1
    assert client.get("/alerts?entity=10.10.10.44").json()["total"] == 1
    assert client.get("/alerts?q=rare").json()["total"] == 1
    assert all(a["severity"] >= 4 for a in client.get("/alerts?severity=4").json()["alerts"])
    t = body["alerts"][0]["technique"].split(".")[0]
    assert all(a["technique"].startswith(t) for a in client.get(f"/alerts?technique={t}").json()["alerts"])
    page = client.get("/alerts?limit=1&offset=1").json()
    assert len(page["alerts"]) == 1 and page["alerts"][0]["alert_id"] == body["alerts"][1]["alert_id"]
    assert client.get("/alerts?incident=abc").status_code == 422
    sev = [a["severity"] for a in client.get("/alerts?sort=severity").json()["alerts"]]
    assert sev == sorted(sev, reverse=True)


def test_unexplained(client):
    body = client.get("/unexplained").json()
    assert body["total"] == 1 and body["alerts"][0]["reason"] == "single anomaly detector"


def test_unexplained_falls_back_to_anomalies_in_no_incident(run, tmp_path):
    (run / "unexplained.json").unlink()
    c = TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True))
    assert [a["alert_id"] for a in c.get("/unexplained").json()["alerts"]] == ["lone0001"]


def test_rules_list_and_detail(client, run):
    body = client.get("/rules").json()
    assert body["total"] > 10 and body["errors"] == [] and body["evaluated"] is True
    rows = {r["id"]: r for r in body["rules"]}
    alerts = rd(run / "alerts.json")
    a01 = rows["A01-rare-event"]
    assert a01["alerts"] == 1 and a01["incidents"] == [] and a01["layer"] == "anomaly"
    assert a01["run_secs"] == 0.5 and a01["background_alerts"] == 1 and a01["ran"] is True
    # the sample's own rule ids predate rules/: reported, not dropped
    sample_rules = {a["rule_id"] for a in rd(SAMPLE / "alerts.json")} - set(rows)
    assert {u["rule_id"] for u in body["unknown_rules"]} == sample_rules
    assert sum(r["alerts"] for r in body["rules"]) + sum(u["alerts"] for u in body["unknown_rules"]) == len(alerts)
    counts = [r["alerts"] for r in body["rules"]]
    assert counts == sorted(counts, reverse=True)
    assert all(r["path"].startswith("rules/") for r in body["rules"])
    one = client.get("/rules/A01-rare-event").json()
    assert "id: A01-rare-event" in one["yaml"] and [a["alert_id"] for a in one["recent_alerts"]] == ["lone0001"]
    assert client.get("/rules?layer=anomaly").json()["total"] < body["total"]
    assert client.get("/rules/no-such-rule").status_code == 404


def test_rules_folder_missing_is_reported(run, tmp_path, monkeypatch):
    monkeypatch.setenv("KILLCHAIN_RULES_DIR", str(tmp_path / "nowhere"))
    c = TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True))
    body = c.get("/rules").json()
    assert body["total"] == 0 and "rules folder not found" in body["errors"][0]
