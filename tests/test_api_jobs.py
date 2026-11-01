"""Analyse a new log from the UI: chunked uploads, runs, run switching and pipeline jobs (killchain/api/jobs.py)."""
from __future__ import annotations

import json
import shutil
import time
from collections import namedtuple
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from killchain.api import create_app
from killchain.api import jobs as jobs_mod
from test_run import attack_lines

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    (data / "runs").mkdir(parents=True)
    for name in ("first", "second"):
        shutil.copytree(SAMPLE, data / "runs" / name)
        for f in ("index.json", "run_summary.json"):          # the copies carry their own run names
            p = data / "runs" / name / f
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["run"] = name
            p.write_text(json.dumps(doc), encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    monkeypatch.setenv("KILLCHAIN_DATA_DIR", str(data))
    monkeypatch.delenv("KILLCHAIN_UPLOADS", raising=False)
    app = create_app(data / "runs" / "first", raw_dir=raw, ti_cache=tmp_path / "ti.sqlite", ti_offline=True,
                     llm_cache=tmp_path / "llm.sqlite")
    return TestClient(app), app, data, raw


def put(client, name, body: bytes, offset: int, total: int):
    return client.post(f"/uploads/{name}", params={"offset": offset, "total": total}, content=body,
                       headers={"Content-Type": "application/octet-stream"})


def test_chunked_upload_resumes_and_lands_in_the_raw_folder(env):
    client, _, _, raw = env
    blob = b"".join(f"line {i}\n".encode() for i in range(5000))
    total = len(blob)
    assert client.get("/uploads/new.log").json() == {"name": "new.log", "received": 0, "size": None, "complete": False}
    r = put(client, "new.log", blob[:10000], 0, total)
    assert r.status_code == 200 and r.json()["received"] == 10000 and not r.json()["complete"]
    assert (raw / ".incoming" / "new.log.part").stat().st_size == 10000
    # a chunk at the wrong offset is refused with where the server is
    r = put(client, "new.log", blob[5000:15000], 5000, total)
    assert r.status_code == 409 and r.json()["received"] == 10000
    assert client.get("/uploads/new.log").json()["received"] == 10000
    # the partial upload is listed, the file is not yet
    listing = client.get("/uploads").json()
    assert listing["partial"] == [{"name": "new.log", "received": 10000}] and listing["files"] == []
    r = put(client, "new.log", blob[10000:], 10000, total)
    assert r.status_code == 200 and r.json() == {"name": "new.log", "received": total, "size": total, "complete": True}
    assert (raw / "new.log").read_bytes() == blob and not (raw / ".incoming" / "new.log.part").exists()
    listing = client.get("/uploads").json()
    assert [f["name"] for f in listing["files"]] == ["new.log"] and listing["files"][0]["size"] == total
    assert listing["partial"] == [] and listing["enabled"] is True and listing["defaults"]["workers"] >= 1
    # the same file again: nothing to send; a different file of that name: refused
    r = put(client, "new.log", blob[:100], 0, total)
    assert r.status_code == 200 and r.json()["already"] is True
    r = put(client, "new.log", blob[:100], 0, total + 1)
    assert r.status_code == 409 and "different file" in r.json()["detail"]


def test_upload_refusals(env, monkeypatch):
    client, _, _, raw = env
    for bad in (".hidden", "x.part", "a b.log", "-x.log"):
        assert put(client, bad, b"x", 0, 1).status_code == 400, bad
    assert put(client, "ok.log", b"abcdef", 0, 3).status_code == 400              # past the total size
    assert client.get("/uploads/ok.log").json()["received"] == 0                    # nothing kept
    Usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(jobs_mod.shutil, "disk_usage", lambda p: Usage(10, 10, 1000))
    r = put(client, "big.log", b"x" * 10, 0, 50 * 2**30)
    assert r.status_code == 507 and "not enough disk space" in r.json()["detail"]
    monkeypatch.setenv("KILLCHAIN_UPLOADS", "0")
    assert put(client, "ok.log", b"abc", 0, 3).status_code == 403
    assert client.post("/jobs", json={"file": "ok.log"}).status_code == 403
    assert client.get("/jobs/current").json()["enabled"] is False


def test_discard_drops_only_a_partial_upload(env):
    client, _, _, raw = env
    put(client, "p.log", b"abc", 0, 10)
    assert client.post("/uploads/p.log/discard").json()["received"] == 0
    (raw / "whole.log").write_bytes(b"abc")
    assert client.post("/uploads/whole.log/discard").json()["complete"] is True
    assert (raw / "whole.log").exists()


def test_runs_list_and_select(env):
    client, app, data, _ = env
    runs = client.get("/runs").json()
    names = [r["name"] for r in runs["runs"]]
    assert runs["runs"][0]["active"] is True and {"first", "second"} <= set(names)
    assert all(not r["active"] for r in runs["runs"][1:])
    old_live = app.state.live
    old_version = old_live.version
    r = client.post("/runs/select", json={"run": "second"})
    assert r.status_code == 200 and r.json()["active"] == "second"
    assert client.get("/health").json()["run"] == "second"
    assert Path(app.state.bundle.run_dir) == data / "runs" / "second"
    assert app.state.evidence is not None and app.state.live is not old_live
    # the old watcher told its streams, and the new one carries on its event ids
    assert old_live.closed and old_live.events[-1]["type"] == "run" and old_live.events[-1]["run"] == "second"
    assert app.state.live.version == old_live.version == old_version + 1
    assert [r["name"] for r in client.get("/runs").json()["runs"] if r["active"]] == ["second"]
    for bad in ("nope", "..", "../first", ".hidden"):
        assert client.post("/runs/select", json={"run": bad}).status_code == 404, bad


def test_job_refusals(env):
    client, _, _, raw = env
    assert client.post("/jobs", json={"file": "missing.log"}).status_code == 404
    (raw / "a.log").write_text("x\n", encoding="utf-8")
    assert client.post("/jobs", json={"file": "a.log", "run": "first"}).status_code == 409     # being served
    r = client.post("/jobs", json={"file": "a.log", "run": "second"})
    assert r.status_code == 409 and "already exists" in r.json()["detail"]
    assert client.post("/jobs", json={"file": "a.log", "run": "bad/name"}).status_code == 400
    assert client.post("/jobs/current/cancel").status_code == 409
    assert client.get("/jobs/current").json() == {"enabled": True, "job": None}


def wait_for_job(client, timeout=300):
    t0 = time.time()
    while time.time() - t0 < timeout:
        job = client.get("/jobs/current").json()["job"]
        if job["state"] != "running":
            return job
        time.sleep(0.5)
    raise AssertionError("job did not finish")


def test_job_runs_the_pipeline_and_switches_to_the_new_run(env):
    client, app, data, raw = env
    (raw / "attack.log").write_text("\n".join(attack_lines()) + "\n", encoding="utf-8")
    r = client.post("/jobs", json={"file": "attack.log", "offline": True, "no_llm": True, "workers": 1,
                                   "upload_secs": 1.5})
    assert r.status_code == 202
    job = r.json()
    assert job["state"] == "running" and job["run"] == "attack" and job["file_bytes"] == (raw / "attack.log").stat().st_size
    assert [s["name"] for s in job["stages"]] == jobs_mod.STAGES
    # only one job at a time
    assert client.post("/jobs", json={"file": "attack.log", "run": "again", "offline": True}).status_code == 409
    job = wait_for_job(client)
    assert job["state"] in ("ok", "ok_with_warnings"), job
    assert job["switched"] is True and job["error"] is None and job["upload_secs"] == 1.5
    st = {s["name"]: s["status"] for s in job["stages"]}
    assert st["narrate"] == "skipped" and all(st[s] in ("ok", "degraded") for s in jobs_mod.STAGES if s != "narrate")
    assert all(s["wall_secs"] is not None for s in job["stages"] if s["status"] == "ok")
    assert job["parse"]["phase"] == "done" and job["parse"]["pct"] == 100.0
    health = client.get("/health").json()
    assert health["run"] == "attack" and health["counts"]["incidents"] == job["result"]["incidents"] > 0
    assert job["result"]["alerts"] == health["counts"]["alerts"] and job["result"]["wall_secs"] > 0
    # saved for after a restart, and the file now lists its run
    saved = json.loads((data / "jobs" / "last.json").read_text(encoding="utf-8"))
    assert saved["id"] == job["id"] and saved["state"] == job["state"]
    assert client.get("/uploads").json()["files"][0]["runs"] == ["attack"]
    runs = client.get("/runs").json()
    assert runs["active"] == "attack" and runs["runs"][0]["name"] == "attack"
    assert runs["runs"][0]["input"] == "attack.log"


def test_cancel_stops_the_job(env):
    client, app, _, raw = env
    (raw / "attack.log").write_text("\n".join(attack_lines() * 20) + "\n", encoding="utf-8")
    assert client.post("/jobs", json={"file": "attack.log", "offline": True, "no_llm": True, "workers": 1}).status_code == 202
    time.sleep(1.0)
    assert client.post("/jobs/current/cancel").status_code == 200
    job = wait_for_job(client, timeout=60)
    assert job["state"] == "cancelled" and job["switched"] is False
    assert client.get("/health").json()["run"] == "first"
    assert not any(s["status"] in ("running", "pending") for s in job["stages"])
