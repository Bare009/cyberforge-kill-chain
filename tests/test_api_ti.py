"""Threat-intel endpoints and the merge of enrichment.json into incidents (track B, P9/P11 day 4).

OTX is replaced by a mock transport; nothing reaches the network.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from killchain.api import create_app
from killchain.contracts import validate_bundle
from killchain.enrich.cache import TiCache
from killchain.enrich.engine import enrich_run

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


def general(count=0, families=()):
    pulses = [{"id": f"p{i}", "name": f"Pulse {i}", "tags": ["c2"], "malware_families": list(families)}
              for i in range(count)]
    return {"pulse_info": {"count": count, "pulses": pulses}, "validation": [], "country_name": "Netherlands"}


class Recorder:
    def __init__(self, answers=None):
        self.answers = answers or {}
        self.paths = []

    def __call__(self, request):
        self.paths.append(request.url.path)
        for k, v in self.answers.items():
            if k in request.url.path:
                return httpx.Response(200, json=v)
        return httpx.Response(200, json=general())

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")


def enriched_run(tmp_path: Path, answers=None) -> Path:
    """A copy of the sample run with enrichment.json made by the engine (mocked OTX)."""
    run = tmp_path / "run"
    shutil.copytree(SAMPLE, run)
    incidents = {1: json.loads((run / "incidents" / "1.json").read_text(encoding="utf-8"))}
    alerts = json.loads((run / "alerts.json").read_text(encoding="utf-8"))
    cache = TiCache(tmp_path / "build-cache.sqlite")
    doc = enrich_run(incidents, alerts, cache, otx_client=Recorder(answers).client())
    cache.close()
    (run / "enrichment.json").write_text(json.dumps(doc), encoding="utf-8")
    return run


def app_for(run: Path, tmp_path: Path, recorder=None, offline=False):
    return TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "api-cache.sqlite",
                                 ti_offline=offline, ti_client=(recorder or Recorder()).client()))


def test_without_enrichment_file_uses_incident_data(key, tmp_path):
    run = tmp_path / "plain"
    shutil.copytree(SAMPLE, run)
    (run / "enrichment.json").unlink(missing_ok=True)
    c = app_for(run, tmp_path)
    s = c.get("/ti/status").json()
    assert s["source"] == "incident data" and s["providers"] == {"local": "ok", "otx": "ok"}
    rows = c.get("/ti/indicators").json()
    assert rows["total"] == 1 and rows["indicators"][0]["value"] == "32.127.48.11"


def test_enrichment_is_merged_into_incidents(key, tmp_path):
    run = enriched_run(tmp_path, {"32.127.48.11": general(2, ["Mirai"])})
    c = app_for(run, tmp_path)
    inc = c.get("/incidents/1").json()
    assert set(inc["enrichment"]) == {"32.127.48.11", "10.10.20.20", "10.10.20.31", "portal.corp.local"}
    assert inc["enrichment"]["32.127.48.11"]["verdict"] == "suspicious"          # 2 pulses: score 0.4
    assert inc["enrichment"]["10.10.20.20"]["verdict"] == "unknown"
    assert inc["chain"][0]["enrichment_flags"] == ["OTX: 2 pulses (Mirai)"]
    assert c.get("/incidents").json()["incidents"][0]["ti_verdict"] == "suspicious"
    assert c.get("/health").json()["contract_errors"] == 0
    # the merged incident still matches contract C, and detection fields are untouched
    original = json.loads((SAMPLE / "incidents" / "1.json").read_text(encoding="utf-8"))
    alerts = json.loads((SAMPLE / "alerts.json").read_text(encoding="utf-8"))
    index = c.get("/incidents").json()
    assert validate_bundle(inc, {"incidents": index["incidents"]}, alerts) == []
    for k in ("risk_score", "risk_parts", "techniques", "merged", "graph", "next"):
        assert inc[k] == original[k]
    assert [s["action"] for s in inc["chain"]] == [s["action"] for s in original["chain"]]


def test_indicator_list_and_filters(key, tmp_path):
    run = enriched_run(tmp_path, {"32.127.48.11": general(1)})
    c = app_for(run, tmp_path)
    body = c.get("/ti/indicators").json()
    assert body["source"] == "enrichment.json" and body["total"] == 4
    first = body["indicators"][0]
    assert first["value"] == "32.127.48.11" and first["verdict"] == "suspicious" and first["flagged_by"] == ["otx"]
    assert first["pulses"] == 1 and first["incidents"][0]["incident_number"] == 1 and first["sendable"] is True
    assert c.get("/ti/indicators", params={"verdict": "unknown"}).json()["total"] == 3
    assert c.get("/ti/indicators", params={"kind": "domain"}).json()["indicators"][0]["value"] == "portal.corp.local"
    assert c.get("/ti/indicators", params={"sendable": "true"}).json()["total"] == 1
    assert c.get("/ti/indicators", params={"q": "internal domain"}).json()["total"] == 1


def test_indicator_detail(key, tmp_path):
    run = enriched_run(tmp_path)
    c = app_for(run, tmp_path)
    d = c.get("/ti/indicators/32.127.48.11").json()
    names = [p["provider"] for p in d["providers"]]
    assert names == ["local", "otx"]
    otx = d["providers"][1]
    assert otx["detail"]["otx_url"] == "https://otx.alienvault.com/indicator/ip/32.127.48.11"
    assert c.get("/ti/indicators/9.9.9.9").status_code == 404


def test_lookup_public_value_asks_otx_once_then_cache(key, tmp_path):
    rec = Recorder({"8.8.4.4": general(3)})
    c = app_for(SAMPLE, tmp_path, rec)
    r = c.post("/ti/lookup", json={"value": " 8.8.4.4 "})
    assert r.status_code == 200
    body = r.json()
    assert body["value"] == "8.8.4.4" and body["verdict"] == "suspicious" and body["in_run"] is False
    assert rec.paths == ["/api/v1/indicators/IPv4/8.8.4.4/general"]
    c.post("/ti/lookup", json={"value": "8.8.4.4"})
    assert len(rec.paths) == 1                                               # second time from the cache


@pytest.mark.parametrize("value", ["10.10.20.20", "203.0.113.5", "portal.corp.local", "http://10.10.20.20/a.php"])
def test_lookup_never_sends_private_values(key, tmp_path, value):
    rec = Recorder()
    body = app_for(SAMPLE, tmp_path, rec).post("/ti/lookup", json={"value": value}).json()
    assert rec.paths == [] and body["verdict"] == "unknown" and body["not_sent_because"]


def test_lookup_of_a_run_value_keeps_its_incidents(key, tmp_path):
    body = app_for(SAMPLE, tmp_path).post("/ti/lookup", json={"value": "32.127.48.11"}).json()
    assert body["in_run"] is True and body["incidents"][0]["incident_number"] == 1


@pytest.mark.parametrize("value,status", [("admin", 422), ("", 422), ("x" * 3000, 422)])
def test_lookup_rejects_bad_values(key, tmp_path, value, status):
    assert app_for(SAMPLE, tmp_path).post("/ti/lookup", json={"value": value}).status_code == status


def test_lookup_offline_makes_no_request(key, tmp_path):
    rec = Recorder()
    c = app_for(SAMPLE, tmp_path, rec, offline=True)
    body = c.post("/ti/lookup", json={"value": "8.8.4.4"}).json()
    assert rec.paths == [] and body["verdict"] == "unknown"
    assert c.get("/ti/status").json()["providers"]["otx"] == "offline"


def test_lookup_is_rate_limited(key, tmp_path):
    c = app_for(SAMPLE, tmp_path)
    c.app.state.ti.per_minute = 2
    codes = [c.post("/ti/lookup", json={"value": f"8.8.8.{i}"}).status_code for i in range(3)]
    assert codes == [200, 200, 429]
    r = c.post("/ti/lookup", json={"value": "8.8.8.9"})
    assert "Retry-After" in r.headers and "limit" in r.json()["detail"]


def test_health_reports_threat_intel(key, tmp_path):
    h = app_for(SAMPLE, tmp_path).get("/health").json()
    assert h["threat_intel"]["providers"] == {"local": "ok", "otx": "ok"}


def test_no_key_means_otx_is_skipped(monkeypatch, tmp_path):
    monkeypatch.setenv("OTX_API_KEY", "")
    rec = Recorder()
    c = app_for(SAMPLE, tmp_path, rec)
    assert c.get("/ti/status").json()["providers"]["otx"] == "no key"
    assert c.post("/ti/lookup", json={"value": "8.8.4.4"}).json()["verdict"] == "unknown" and rec.paths == []
