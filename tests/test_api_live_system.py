"""Live watcher and stream, /metrics and /system (track B, day 6)."""

from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timezone
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


def bump(p: Path) -> None:
    """Make sure the file's mtime moves even on coarse clocks."""
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))


@pytest.fixture
def run(tmp_path):
    r = tmp_path / "run"
    shutil.copytree(SAMPLE, r)
    return r


@pytest.fixture
def client(run, tmp_path):
    return TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True,
                                 llm_cache=tmp_path / "llm.sqlite"))


def change_title_and_add_alert(run: Path) -> None:
    inc = rd(run / "incidents" / "1.json")
    inc["title"] = "Updated by live mode"
    wr(run / "incidents" / "1.json", inc)
    idx = rd(run / "index.json")
    idx["incidents"][0]["title"] = "Updated by live mode"
    wr(run / "index.json", idx)
    alerts = rd(run / "alerts.json")
    alerts.append({**alerts[0], "alert_id": "live0001", "rule_id": "A01-rare-event", "layer": "anomaly",
                   "incident_number": None, "title": "New rare event"})
    wr(run / "alerts.json", alerts)
    bump(run / "index.json")
    bump(run / "alerts.json")


# ---------------------------------------------------------------- watcher

def test_watcher_waits_for_files_to_settle_then_reloads(client, run):
    w = client.app.state.live
    assert w.poll() is None                                   # nothing changed
    change_title_and_add_alert(run)
    assert w.poll() == "pending"                              # changed: wait one more check
    assert client.get("/incidents/1").json()["title"] != "Updated by live mode"
    assert w.poll() == "reloaded"
    assert client.get("/incidents/1").json()["title"] == "Updated by live mode"
    assert client.get("/alerts?q=New rare").json()["total"] == 1     # every endpoint sees the new bundle
    ev = client.get("/live/status").json()["events"][0]
    assert ev["type"] == "bundle" and ev["changed_incidents"] == [1] and ev["new_incidents"] == []
    assert [a["alert_id"] for a in ev["new_alerts"]] == ["live0001"] and ev["counts"]["new_alerts"] == 1
    assert w.poll() is None and w.reloads == 1


def test_watcher_keeps_serving_when_a_reload_fails(client, run):
    w = client.app.state.live
    (run / "index.json").write_text("{ half written", encoding="utf-8")
    bump(run / "index.json")
    w.poll()
    assert w.poll() == "error" and w.last_error
    assert client.get("/incidents/1").status_code == 200       # the old bundle is still served
    shutil.copy(SAMPLE / "index.json", run / "index.json")
    bump(run / "index.json")
    w.poll()
    assert w.poll() == "reloaded" and w.last_error is None


def test_live_process_status(client, run):
    w = client.app.state.live
    s = client.get("/live/status").json()
    assert s["process_state"] == "not started" and s["process"] is None and "killchain live" in s["how_to_start"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    wr(run / "live" / "status.json", {"state": "running", "source": "firex-10G.log", "offset": 1000, "size": 5000,
                                      "lines_per_sec": 120.5, "updated_at": now})
    assert w.poll() == "status"
    s = client.get("/live/status").json()
    assert s["process_state"] == "running" and s["process"]["lines_per_sec"] == 120.5
    assert s["events"][0]["type"] == "status" and s["events"][0]["previous"] == "not started"
    wr(run / "live" / "status.json", {"state": "running", "updated_at": "2020-01-01T00:00:00Z"})
    bump(run / "live" / "status.json")
    w.poll()
    assert client.get("/live/status").json()["process_state"] == "stale"


def test_stream_sends_hello_then_changes(client, run):
    w = client.app.state.live
    change_title_and_add_alert(run)
    w.poll()
    w.poll()
    with client.stream("GET", "/live/stream?since=0&limit=2") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        body = "".join(r.iter_text())
    events = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
    assert [e["type"] for e in events] == ["hello", "bundle"]
    assert events[1]["changed_incidents"] == [1] and "id: 1\nevent: bundle" in body
    # by default only events after the current version are sent
    with client.stream("GET", "/live/stream?limit=1") as r:
        only = [json.loads(line[6:]) for line in "".join(r.iter_text()).splitlines() if line.startswith("data: ")]
    assert [e["type"] for e in only] == ["hello"] and only[0]["version"] == 1


def test_watcher_thread_picks_up_changes(run, tmp_path):
    app = create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True,
                     llm_cache=tmp_path / "llm.sqlite", watch=True, watch_interval=0.1)
    try:
        change_title_and_add_alert(run)
        deadline = time.time() + 5
        while time.time() < deadline and app.state.live.reloads == 0:
            time.sleep(0.05)
        assert app.state.live.reloads == 1 and app.state.live.watching
    finally:
        app.state.live.stop()


# ---------------------------------------------------------------- metrics and system

def test_metrics_absent_then_present(client, run):
    body = client.get("/metrics").json()
    assert body["available"] is False and "eval score" in body["hint"]
    wr(run / "metrics.json", {"truth": "silver (truth.parquet)",
                              "metrics": {"detection_recall": 0.95, "processing_secs": 157.0, "open_time_p95_ms": None},
                              "grades": {"detection_recall": "great", "processing_secs": "great", "open_time_p95_ms": "n/a"},
                              "detail": {"truth_lines": 100}, "per_incident": [], "per_class": [], "paths": [],
                              "per_rule": [{"rule_id": "A01-rare-event", "alerts": 1, "layer": "anomaly",
                                            "truth_lines": 0, "background_alerts": 1}]})
    w = client.app.state.live
    w.poll()
    assert w.poll() == "reloaded"                               # metrics.json is watched too
    body = client.get("/metrics").json()
    assert body["available"] and body["metrics"]["detection_recall"] == 0.95 and body["truth"].startswith("silver")
    t = body["targets"]["detection_recall"]
    assert (t["good"], t["great"], t["higher_is_better"], t["label"]) == (0.7, 0.9, True, "Detection recall")
    assert body["targets"]["false_alarm_share"]["higher_is_better"] is False and len(body["targets"]) == 7
    assert client.get("/rules").json()["evaluated"] is True


def test_system(client, run, tmp_path):
    s = client.get("/system").json()
    assert s["run"] == "sample-run" and s["sample"] is True and s["contract_error_count"] == 0
    assert s["evidence"]["logs"] == [{"source": "firex-10G.log", "available": False}]
    assert s["evidence"]["origin"] == "evidence_sample.json"
    assert s["threat_intel"]["providers"]["local"] == "ok" and "budget" in s["llm"]
    names = {f["name"] for f in s["files"]}
    assert {"index.json", "alerts.json", "incidents/"} <= names
    assert s["api"]["reloads"] == 0 and s["api"]["versions"]["duckdb"] and s["rule_test_sandbox"] is False
    (tmp_path / "firex-10G.log").write_text("x\n", encoding="utf-8")
    assert client.get("/system").json()["evidence"]["logs"][0]["available"] is True
