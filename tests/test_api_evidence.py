"""Evidence lines and entity lookups (track B, P11 day 3)."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient

from killchain.api import create_app
from killchain.api.entities import guess_kind

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample-run"
REAL_LOG = ROOT / "data" / "raw" / "firex-10G.log"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """The sample run with an empty raw folder: lines are listed, raw text is not."""
    return TestClient(create_app(SAMPLE, raw_dir=tmp_path_factory.mktemp("no-raw")))


def copy_sample(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    shutil.copytree(SAMPLE, run)
    return run


def fake_log(raw: Path, n_lines: int = 5) -> list:
    """A small log; returns (line_no, byte_offset, text) for each line."""
    raw.mkdir(parents=True, exist_ok=True)
    out, offset, buf = [], 0, b""
    for i in range(1, n_lines + 1):
        text = f'date=2026-10-29 time=01:51:{i:02d} srcip=32.127.48.11 dstip=10.10.20.20 dstport={1000 + i}'
        out.append((i, offset, text))
        b = (text + "\n").encode()
        buf += b
        offset += len(b)
    (raw / "fake.log").write_bytes(buf)
    return out


# ── /incidents/{id}/events ───────────────────────────────────────────────────

def test_events_from_sample_without_raw(client):
    r = client.get("/incidents/1/events")
    assert r.status_code == 200
    body = r.json()
    assert body["origin"] == "evidence_sample.json"
    assert body["total"] == 80 and len(body["lines"]) == 50 and body["limit"] == 50
    assert body["raw_available"] is False and all(ln["raw"] is None for ln in body["lines"])
    assert body["steps"] == [{"step": n, "lines": 20} for n in (1, 2, 3, 4)]
    first = body["lines"][0]
    assert first["step"] == 1 and first["line"] == 3210274 and first["byte_offset"] == 1694144963
    assert first["ts_ist"] == "2026-10-29 01:51:23"
    times = [ln["ts"] for ln in body["lines"]]
    assert times == sorted(times)


def test_events_one_step_and_paging(client):
    body = client.get("/incidents/1/events", params={"step": 2, "limit": 15}).json()
    assert body["total"] == 20 and len(body["lines"]) == 15
    assert {ln["step"] for ln in body["lines"]} == {2} and {ln["technique"] for ln in body["lines"]} == {"T1190"}
    rest = client.get("/incidents/1/events", params={"step": 2, "limit": 15, "offset": 15}).json()
    assert len(rest["lines"]) == 5
    assert not {ln["line"] for ln in body["lines"]} & {ln["line"] for ln in rest["lines"]}


@pytest.mark.parametrize("path,params,status", [
    ("/incidents/1/events", {"step": 9}, 404),
    ("/incidents/99/events", {}, 404),
    ("/incidents/1/events", {"limit": 500}, 422),
    ("/incidents/1/events", {"step": 0}, 422),
])
def test_events_errors(client, path, params, status):
    assert client.get(path, params=params).status_code == status


def test_events_read_raw_text(tmp_path):
    run = copy_sample(tmp_path)
    lines = fake_log(tmp_path / "raw")
    inc = json.loads((run / "incidents" / "1.json").read_text(encoding="utf-8"))
    alert_id = inc["chain"][0]["alert_id"]
    rows = [{"alert_id": alert_id, "source": "fake.log", "line": ln, "byte_offset": off,
             "ts": f"2026-10-28T20:21:{ln:02d}.000000Z", "technique": "T1595.002", "role": "window"}
            for ln, off, _ in lines]
    (run / "evidence_sample.json").write_text(json.dumps(rows), encoding="utf-8")
    body = TestClient(create_app(run, raw_dir=tmp_path / "raw")).get("/incidents/1/events", params={"step": 1}).json()
    assert body["raw_available"] is True and body["total"] == 5
    assert [ln["raw"] for ln in body["lines"]] == [t for _, _, t in lines]


def test_unsafe_sources_are_never_opened(tmp_path):
    run = copy_sample(tmp_path)
    (tmp_path / "secret.txt").write_text("do not read", encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    alert_id = json.loads((run / "incidents" / "1.json").read_text(encoding="utf-8"))["chain"][0]["alert_id"]
    bad = ["../secret.txt", str(tmp_path / "secret.txt"), "..", "sub/../../secret.txt"]
    rows = [{"alert_id": alert_id, "source": s, "line": i, "byte_offset": 0,
             "ts": "2026-10-28T20:21:23.000000Z", "technique": "T1595.002", "role": "window"}
            for i, s in enumerate(bad, 1)]
    (run / "evidence_sample.json").write_text(json.dumps(rows), encoding="utf-8")
    body = TestClient(create_app(run, raw_dir=raw)).get("/incidents/1/events").json()
    assert body["total"] == 4 and body["raw_available"] is False
    assert all(ln["raw"] is None for ln in body["lines"])


def test_events_from_parquet(tmp_path):
    """A pipeline run has alert_evidence.parquet with UTC timestamps, as the detection engine writes it."""
    run = copy_sample(tmp_path)
    (run / "evidence_sample.json").unlink()
    lines = fake_log(tmp_path / "raw", 3)
    alert_id = json.loads((run / "incidents" / "1.json").read_text(encoding="utf-8"))["chain"][3]["alert_id"]
    table = pa.table({
        "alert_id": [alert_id] * 3, "source": ["fake.log"] * 3,
        "line": [ln for ln, _, _ in lines], "byte_offset": [off for _, off, _ in lines],
        "ts": pa.array([datetime(2026, 10, 29, 4, 39, s, tzinfo=timezone.utc) for s in (9, 10, 11)],
                       type=pa.timestamp("us", tz="UTC")),
        "technique": ["T1048.002"] * 3, "role": ["window"] * 3,
    })
    pq.write_table(table, run / "alert_evidence.parquet")
    body = TestClient(create_app(run, raw_dir=tmp_path / "raw")).get("/incidents/1/events").json()
    assert body["origin"] == "alert_evidence.parquet" and body["total"] == 3
    first = body["lines"][0]
    assert first["step"] == 4 and first["ts"] == "2026-10-29T04:39:09.000000Z"
    assert first["ts_ist"] == "2026-10-29 10:09:09" and first["raw"] == lines[0][2]
    assert body["steps"] == [{"step": 1, "lines": 0}, {"step": 2, "lines": 0}, {"step": 3, "lines": 0},
                             {"step": 4, "lines": 3}]


def test_events_fall_back_to_line_samples(tmp_path):
    run = copy_sample(tmp_path)
    (run / "evidence_sample.json").unlink()
    body = TestClient(create_app(run, raw_dir=tmp_path)).get("/incidents/1/events").json()
    assert body["origin"] == "incident line samples" and body["total"] == 80


@pytest.mark.skipif(not REAL_LOG.exists(), reason="raw log not available")
def test_events_from_the_real_log():
    """The sample's offsets point at the attacker's lines in firex-10G.log."""
    body = TestClient(create_app(SAMPLE)).get("/incidents/1/events", params={"step": 2, "limit": 5}).json()
    assert body["raw_available"] is True
    for ln in body["lines"]:
        assert "srcip=32.127.48.11 " in ln["raw"] and "dstip=10.10.20.20 " in ln["raw"], ln["raw"][:200]


# ── /entities/{value} ────────────────────────────────────────────────────────

def test_entity_attacker(client):
    e = client.get("/entities/32.127.48.11").json()
    assert e["kind"] == "external_ip" and e["zone"] == "internet"
    assert e["incidents"] == [{
        "incident_number": 1, "title": "Web attack chain from 32.127.48.11 against the portal",
        "risk_score": 76.5, "risk_band": "critical", "ts_start_ist": "2026-10-29 01:51:23",
        "tactics": ["reconnaissance", "initial-access", "persistence", "exfiltration"],
        "roles": ["source"], "steps": [1, 2, 3, 4],
    }]
    assert e["alerts_total"] == 4 and all(a["as"] == ["src_ip"] and a["incident_number"] == 1 for a in e["alerts"])
    assert e["enrichment"]["verdict"] == "no-reports"


def test_entity_target_and_reach_only(client):
    portal = client.get("/entities/10.10.20.20").json()
    assert portal["label"] == "portal (10.10.20.20)" and portal["incidents"][0]["roles"] == ["target"]
    nxt = client.get("/entities/10.10.20.31").json()
    assert nxt["incidents"][0]["roles"] == ["reachable next"] and nxt["incidents"][0]["steps"] == []
    assert nxt["alerts"] == []


def test_entity_domain(client):
    d = client.get("/entities/portal.corp.local").json()
    assert d["kind"] == "domain" and d["incidents"][0]["roles"] == ["domain"]


def test_entity_unknown(client):
    r = client.get("/entities/1.2.3.4")
    assert r.status_code == 404 and "does not appear" in r.json()["detail"]


@pytest.mark.parametrize("value,kind", [
    ("10.10.20.20", "ip"), ("2001:db8::1", "ip"), ("portal.corp.local", "domain"), ("Deepika.Khan", "domain"),
    ("svc_backup30", "account"),
])
def test_guess_kind(value, kind):
    assert guess_kind(value) == kind
