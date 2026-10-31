"""MITRE endpoints over the sample run (track B, P11 day 2).

The sample has 4 alerts, all in incident 1:
  T1595.002 sev 3, T1190 sev 4, T1505.003 sev 4, T1048.002 sev 5;
first at 2026-10-28 20:21 UTC (01:51 IST on the 29th), last ends 2026-10-29 07:08:54 UTC.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from killchain.api import create_app
from killchain.api.mitre import MitreFilters, MitreStore, catalogue

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(SAMPLE))


def cell(matrix, technique_id):
    for t in matrix["tactics"]:
        for c in t["techniques"]:
            if c["id"] == technique_id:
                return t, c
    raise AssertionError(f"{technique_id} not in the matrix")


def test_catalogue(client):
    c = client.get("/mitre/catalogue").json()["catalogue"]
    assert c["tacticsTotal"] == 14 and c["techniquesTotal"] == 216 and c["subtechniquesTotal"] == 475
    assert "MITRE" in c["attribution"]


def test_matrix_summary(client):
    m = client.get("/mitre/matrix").json()
    s = m["summary"]
    assert s["alertsTotal"] == 4 and s["alertsMapped"] == 4 and s["alertsUnmapped"] == 0
    assert s["techniquesSeen"] == 4 and s["subtechniquesSeen"] == 3 and s["tacticsSeen"] == 4
    assert m["period"]["preset"] == "30d"
    # the window ends at the run's last alert, not today
    assert m["period"]["end"].startswith("2026-10-29T07:08:54")


def test_matrix_cells(client):
    m = client.get("/mitre/matrix").json()
    tactic, c = cell(m, "T1190")
    assert tactic["name"] == "Initial Access"
    assert c["alerts"] == 1 and c["maxSeverity"] == "HIGH" and c["severity"]["high"] == 1
    assert c["correlatedAlerts"] == 1 and c["openAlerts"] == 0   # every sample alert is in incident 1
    _, recon = cell(m, "T1595")
    assert recon["alerts"] == 1 and [s["id"] for s in recon["subtechniques"]] == ["T1595.002"]
    assert recon["url"] == "https://attack.mitre.org/techniques/T1595/"
    _, untouched = cell(m, "T1110")
    assert untouched["seen"] is False and untouched["alerts"] == 0


def test_every_column_lists_all_its_techniques(client):
    m = client.get("/mitre/matrix").json()
    cat = catalogue()
    for t in m["tactics"]:
        expected = sum(1 for p in cat["parents"] if t["id"] in p["tactics"])
        assert t["techniquesTotal"] == len(t["techniques"]) == expected


def test_top_techniques(client):
    top = client.get("/mitre/matrix").json()["topTechniques"]
    # one alert each; ties are broken by id
    assert [t["id"] for t in top] == ["T1048", "T1190", "T1505", "T1595"]
    assert top[0]["maxSeverity"] == "CRITICAL"


@pytest.mark.parametrize("params,total", [
    ({"severity": "critical"}, 1),
    ({"severity": ["high", "critical"]}, 3),
    ({"status": "open"}, 0),
    ({"status": "correlated"}, 4),
    ({"source": "anomaly"}, 0),
    ({"source": "rule"}, 4),
    ({"preset": "24h"}, 4),
    ({"start": "2026-10-28T00:00:00Z", "end": "2026-10-29T00:00:00Z"}, 3),
    ({"start": "2026-10-29T00:00:00Z", "end": "2026-10-30T00:00:00Z"}, 1),
])
def test_matrix_filters(client, params, total):
    r = client.get("/mitre/matrix", params=params)
    assert r.status_code == 200, r.text
    assert r.json()["summary"]["alertsTotal"] == total


@pytest.mark.parametrize("params", [
    {"preset": "1y"},
    {"start": "2026-10-28T00:00:00Z"},
    {"start": "2026-10-29T00:00:00Z", "end": "2026-10-28T00:00:00Z"},
    {"severity": "huge"},
])
def test_matrix_rejects_bad_filters(client, params):
    r = client.get("/mitre/matrix", params=params)
    assert r.status_code == 422 and r.json()["detail"]


def test_technique_detail_parent_includes_subs(client):
    d = client.get("/mitre/techniques/T1595").json()
    assert d["technique"]["name"] == "Active Scanning"
    assert d["technique"]["tactics"] == [{"id": "TA0043", "name": "Reconnaissance"}]
    s = d["summary"]
    assert s["alerts"] == 1 and s["correlatedAlerts"] == 1 and s["alertsOnTechniqueItself"] == 0
    assert s["maxSeverity"] == "MEDIUM"
    assert [x["id"] for x in d["subtechniques"]] == ["T1595.002"]
    assert d["bySource"] == [{"source": "fw-recon-port-sweep", "alerts": 1}]
    assert d["byAsset"] == [{"asset": "10.10.20.20", "alerts": 1}]
    assert d["byStatus"] == [{"status": "in an incident", "alerts": 1}]
    a = d["recentAlerts"][0]
    assert a["incidentNumber"] == 1 and a["status"] == "correlated" and a["subtechniqueId"] == "T1595.002"


def test_technique_trend_is_by_ist_day(client):
    d = client.get("/mitre/techniques/T1595", params={"preset": "7d"}).json()
    days = {p["date"]: p["alerts"] for p in d["trend"]}
    # 20:21 UTC on the 28th is 01:51 IST on the 29th
    assert days["2026-10-29"] == 1 and days.get("2026-10-28", 0) == 0
    assert len(d["trend"]) == 8          # 7 days back from 29 Oct 12:38 IST touches 8 IST dates


def test_sub_technique_detail(client):
    d = client.get("/mitre/techniques/t1505.003").json()     # case-insensitive
    assert d["technique"]["id"] == "T1505.003" and d["technique"]["parent"] == "T1505"
    assert d["summary"]["alerts"] == 1 and d["summary"]["alertsOnTechniqueItself"] == 1


@pytest.mark.parametrize("tid", ["T9999", "nonsense"])
def test_technique_detail_unknown(client, tid):
    r = client.get(f"/mitre/techniques/{tid}")
    assert r.status_code == 404 and r.json()["detail"]


def test_unmapped_and_unknown_techniques():
    base = {
        "alert_id": "x", "rule_id": "r", "layer": "anomaly", "title": "t", "summary": "s",
        "technique_name": None, "tactic": "discovery", "severity": 2, "confidence": 0.3,
        "ts_start": "2026-10-28T10:00:00Z", "ts_end": "2026-10-28T10:05:00Z",
        "src_ip": None, "dst_ip": None, "host": None, "incident_number": None,
    }
    store = MitreStore([
        {**base, "alert_id": "a", "technique": "unknown"},
        {**base, "alert_id": "b", "technique": "T9999"},
        {**base, "alert_id": "c", "technique": "T1046"},
    ])
    s = store.matrix(MitreFilters())
    assert s["summary"]["alertsTotal"] == 3
    assert s["summary"]["alertsUnmapped"] == 1 and s["summary"]["alertsUnknownTechnique"] == 1
    assert s["summary"]["alertsMapped"] == 1
    assert s["unknownTechniques"] == [{"id": "T9999", "alerts": 1}]
    assert cell(s, "T1046")[1]["openAlerts"] == 1


def test_empty_run():
    m = MitreStore([]).matrix(MitreFilters())
    assert m["summary"]["alertsTotal"] == 0 and m["topTechniques"] == []
    assert all(not c["seen"] for t in m["tactics"] for c in t["techniques"])


def test_concurrent_requests(client):
    """FastAPI runs sync endpoints on a thread pool; each request uses its own DuckDB cursor."""
    def hit(i):
        path = "/mitre/matrix" if i % 2 else "/mitre/techniques/T1190"
        return client.get(path).status_code
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert set(pool.map(hit, range(80))) == {200}
