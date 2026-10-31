"""API over the committed sample run (track B, P11)."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from killchain.api import create_app
from killchain.api.bundle import BundleError, resolve_run_dir

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(SAMPLE))


def test_resolve_sample_by_name(monkeypatch):
    monkeypatch.delenv("KILLCHAIN_RUN", raising=False)
    assert resolve_run_dir("sample-run") == SAMPLE.resolve()
    assert resolve_run_dir() == SAMPLE.resolve()
    with pytest.raises(BundleError):
        resolve_run_dir("no-such-run")


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    h = r.json()
    assert h["status"] == "ok" and h["contract_errors"] == 0
    assert h["run"] == "sample-run" and h["sample"] is True
    assert h["counts"] == {"incidents": 1, "alerts": 4, "events": 940}


def test_list(client):
    body = client.get("/incidents").json()
    assert body["total"] == 1 and body["incidents"][0]["incident_number"] == 1
    assert body["incidents"][0]["merged"] == {"alerts": 4, "events": 940}


@pytest.mark.parametrize("params,total", [
    ({"technique": "T1190"}, 1),
    ({"technique": "t1048"}, 1),          # parent of T1048.002, case-insensitive
    ({"technique": "T1110"}, 0),
    ({"tactic": "initial-access"}, 1),
    ({"tactic": "Initial Access"}, 1),
    ({"tactic": "impact"}, 0),
    ({"severity": 5}, 1),
    ({"entity": "32.127.48.11"}, 1),
    ({"entity": "1.2.3.4"}, 0),
    ({"q": "PORTAL"}, 1),
    ({"q": "32.127"}, 1),
    ({"q": "ransomware"}, 0),
])
def test_list_filters(client, params, total):
    assert client.get("/incidents", params=params).json()["total"] == total


def test_list_paging(client):
    body = client.get("/incidents", params={"offset": 1}).json()
    assert body["total"] == 1 and body["incidents"] == []
    assert client.get("/incidents", params={"limit": 0}).status_code == 422


def test_incident_by_number_and_hash(client):
    by_n = client.get("/incidents/1").json()
    by_hash = client.get(f"/incidents/{by_n['incident_id']}").json()
    assert by_n == by_hash
    assert [s["n"] for s in by_n["chain"]] == [1, 2, 3, 4]


@pytest.mark.parametrize("path", ["/incidents/99", "/incidents/nope", "/incidents/99/path"])
def test_unknown_incident(client, path):
    r = client.get(path)
    assert r.status_code == 404 and "not found" in r.json()["detail"]


def test_path(client):
    p = client.get("/incidents/1/path").json()
    assert set(p) >= {"chain", "chain_text", "gaps", "graph", "next"}
    assert [s["n"] for s in p["chain"]] == [1, 2, 3, 4]
    node_ids = {n["id"] for n in p["graph"]["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in p["graph"]["edges"])
    assert isinstance(p["next"]["sentence"], str)


def test_cors_for_dev_server(client):
    r = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
    r = client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_path_is_fast(client):
    """Plan target: p95 of GET /incidents/{n}/path under 500 ms. In process it should be ~1 ms."""
    times = []
    for _ in range(200):
        t0 = time.perf_counter()
        assert client.get("/incidents/1/path").status_code == 200
        times.append(time.perf_counter() - t0)
    p95 = sorted(times)[int(len(times) * 0.95)]
    assert p95 < 0.05, f"p95 {p95 * 1000:.1f} ms"


def test_broken_incident_is_served_as_degraded(tmp_path):
    run = tmp_path / "broken-run"
    shutil.copytree(SAMPLE, run)
    inc_file = run / "incidents" / "1.json"
    inc = json.loads(inc_file.read_text(encoding="utf-8"))
    inc["risk_score"] = 12.0          # no longer the sum of risk_parts
    inc_file.write_text(json.dumps(inc), encoding="utf-8")
    h = TestClient(create_app(run)).get("/health").json()
    assert h["status"] == "degraded" and h["contract_errors"] >= 1


def test_missing_index_fails_loudly(tmp_path):
    with pytest.raises(BundleError, match="index.json"):
        create_app(tmp_path)
