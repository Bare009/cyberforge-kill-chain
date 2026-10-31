"""SIEM connections (killchain/connectors, ported from AI-SOC): store, registry, webhook auth,
sink (dedupe, raw lines to live.log), API pull and the SSRF guard. Everything runs in a temp
KILLCHAIN_DATA_DIR; the real data folder is never touched."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from killchain.connectors import auth, credentials, registry, sink, vendors
from killchain.connectors.config import CollectorSettings
from killchain.connectors.poller import Poller
from killchain.connectors.pull_clients import PullError, validate_target_url
from killchain.connectors.routes import router as settings_router
from killchain.connectors.store import ConnectorStore, get_store
from killchain.connectors.webhook import router as ingest_router

KEY = Fernet.generate_key().decode()
SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"

FGT1 = ('date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" devname="FGT60FTK00000000" '
        'devid="FGT60FTK00000000" logid="1501054600" type="utm" subtype="dns" level="information" vd="root" '
        'srcip=10.10.40.156 srcport=37918 dstip=11.113.232.73 dstport=53 action="pass" policyid=20')
FGT2 = ('date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" devname="FGT60FTK00000000" '
        'devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
        'srcip=10.10.40.225 srcport=50951 dstip=71.38.6.121 dstport=443 action="accept" policyid=4')


@pytest.fixture()
def data(tmp_path, monkeypatch):
    d = tmp_path / "data"
    monkeypatch.setenv("KILLCHAIN_DATA_DIR", str(d))
    monkeypatch.delenv("INGEST_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("COLLECTOR_ALLOW_HTTP", raising=False)
    monkeypatch.delenv("COLLECTOR_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.delenv("KILLCHAIN_SYSLOG", raising=False)
    monkeypatch.setenv("CONNECTOR_CREDENTIALS_KEY", KEY)
    auth.invalidate_cache()
    return d


@pytest.fixture()
def client(data):
    app = FastAPI()
    app.include_router(settings_router)
    app.include_router(ingest_router)
    return TestClient(app)


def _create_webhook(client, auth_mode="bearer", name="Edge FW", vendor="fortigate"):
    r = client.post("/settings/siem-integrations",
                    json={"vendor": vendor, "name": name, "transport": "webhook", "auth_mode": auth_mode})
    assert r.status_code == 201, r.text
    return r.json()


def _sig(secret: str, body: bytes) -> str:
    key = hashlib.sha256(secret.encode()).hexdigest().encode()
    return "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()


# ── store ────────────────────────────────────────────────────────────────────

def test_store_crud_round_trip(tmp_path):
    path = tmp_path / "c.json"
    st = ConnectorStore(path)
    now = datetime.now(timezone.utc)
    st.insert_one({"connector_id": "abc123", "vendor": "custom", "name": "A", "created_at": now,
                   "pull_state": {"next_run_at": None}})
    st.insert_one({"connector_id": "def456", "vendor": "custom", "name": "B"})
    with pytest.raises(ValueError):
        st.insert_one({"connector_id": "abc123"})
    assert st.find_one({"connector_id": "abc123"})["created_at"] == now
    assert st.update_one({"connector_id": "abc123"},
                         {"$set": {"pull_state.cursor.watermark": "w", "enabled": False},
                          "$inc": {"alerts_received": 3}})
    assert not st.update_one({"connector_id": "nope"}, {"$set": {"x": 1}})
    assert st.find_one({"name": "B", "connector_id": {"$ne": "def456"}}) is None
    assert [d["name"] for d in st.find({"pull_state.next_run_at": None})] == ["A", "B"]   # missing == None
    assert [d["name"] for d in st.find({"created_at": {"$lte": now}})] == ["A"]

    again = ConnectorStore(path)                      # re-read from disk
    doc = again.find_one({"connector_id": "abc123"})
    assert doc["pull_state"]["cursor"] == {"watermark": "w"}
    assert doc["alerts_received"] == 3 and doc["enabled"] is False
    assert isinstance(doc["created_at"], datetime)
    assert again.delete_one({"connector_id": "abc123"}) == 1
    assert again.delete_one({"connector_id": "abc123"}) == 0
    assert [d["connector_id"] for d in ConnectorStore(path).find()] == ["def456"]
    assert not list(tmp_path.glob("*.tmp"))


# ── registry and routes ──────────────────────────────────────────────────────

def test_vendor_catalog_offers_only_supported_modes(client):
    body = client.get("/settings/siem-vendors").json()
    by_id = {v["id"]: v for v in body["vendors"]}
    assert {"wazuh", "sentinelone", "sumologic", "alienvault", "cybolt", "custom", "fortigate"} <= set(by_id)
    for v in by_id.values():
        assert "mtls" not in v["authModes"]
        assert set(v["transports"]) <= {"webhook", "api_pull"}       # syslog off by default
    assert by_id["sentinelone"]["pull"]["client"] == "sentinelone"
    assert body["endpoints"]["baseUrl"] == "http://testserver"
    assert body["endpoints"]["credentialsKeyConfigured"] is True


def test_create_webhook_returns_secret_once(client):
    out = _create_webhook(client)
    cid = out["connectorId"]
    assert out["secret"].startswith("soar_") and out["secretHint"].startswith("soar_")
    assert out["webhookUrl"] == f"http://testserver/ingest/webhook/{cid}"
    assert out["authMode"] == "bearer" and out["enabled"] is True
    rows = client.get("/settings/siem-integrations").json()["integrations"]
    assert len(rows) == 1
    row = rows[0]
    assert "secret" not in row and "secret_hash" not in json.dumps(row)
    assert out["secret"] not in json.dumps(row)
    assert row["registered"] is True and row["alertsReceived"] == 0
    assert row["linesForwarded"] == 0 and row["notAnalysable"] == 0
    # validation errors are 400 with a message
    r = client.post("/settings/siem-integrations", json={"vendor": "fortigate", "name": "Edge FW"})
    assert r.status_code == 400 and "already exists" in r.json()["detail"]
    r = client.post("/settings/siem-integrations",
                    json={"vendor": "wazuh", "name": "x", "auth_mode": "mtls"})
    assert r.status_code == 400


def test_rotate_patch_delete(client):
    out = _create_webhook(client)
    cid, old = out["connectorId"], out["secret"]
    rot = client.post(f"/settings/siem-integrations/{cid}/rotate-secret").json()
    assert rot["secret"] != old
    assert client.get(f"/ingest/webhook/{cid}/ping", headers={"Authorization": f"Bearer {old}"}).status_code == 401
    assert client.get(f"/ingest/webhook/{cid}/ping",
                      headers={"Authorization": f"Bearer {rot['secret']}"}).status_code == 200
    r = client.patch(f"/settings/siem-integrations/{cid}", json={"name": "Renamed"})
    assert r.status_code == 200 and r.json()["name"] == "Renamed"
    assert client.get(f"/settings/siem-integrations/{cid}/agents").json() == {"agents": []}
    assert client.delete(f"/settings/siem-integrations/{cid}").status_code == 204
    assert client.delete(f"/settings/siem-integrations/{cid}").status_code == 404
    assert client.get("/settings/siem-integrations").json()["integrations"] == []


# ── webhook auth ─────────────────────────────────────────────────────────────

def test_webhook_bearer_token_and_disabled(client):
    out = _create_webhook(client)
    cid, secret = out["connectorId"], out["secret"]
    url = f"/ingest/webhook/{cid}"
    r = client.post(url, json={"message": FGT1}, headers={"Authorization": f"Bearer {secret}"})
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1 and r.json()["status"] == "accepted"
    assert client.post(url, json={"message": FGT2}, headers={"X-SOAR-Token": secret}).status_code == 202
    assert client.post(url, json={"a": 1}, headers={"Authorization": "Bearer soar_wrong"}).status_code == 401
    assert client.post(url, json={"a": 1}).status_code == 401
    assert client.post("/ingest/webhook/unknown-id", json={"a": 1},
                       headers={"Authorization": f"Bearer {secret}"}).status_code == 401
    assert client.post(url, content=b"{not json", headers={"Authorization": f"Bearer {secret}"}).status_code == 400
    ping = client.get(f"{url}/ping", headers={"Authorization": f"Bearer {secret}"})
    assert ping.status_code == 200 and ping.json()["vendor"] == "fortigate"

    assert client.patch(f"/settings/siem-integrations/{cid}", json={"enabled": False}).status_code == 200
    r = client.post(url, json={"message": FGT1}, headers={"Authorization": f"Bearer {secret}"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or missing connector credentials."


def test_webhook_hmac(client):
    out = _create_webhook(client, auth_mode="hmac", name="Signed")
    cid, secret = out["connectorId"], out["secret"]
    body = json.dumps({"full_log": FGT1}).encode()
    url = f"/ingest/webhook/{cid}"
    ok = client.post(url, content=body, headers={"X-SOAR-Signature": _sig(secret, body),
                                                 "Content-Type": "application/json"})
    assert ok.status_code == 202, ok.text
    bad = client.post(url, content=body, headers={"X-SOAR-Signature": _sig("soar_other", body)})
    assert bad.status_code == 401
    tampered = client.post(url, content=body + b" ", headers={"X-SOAR-Signature": _sig(secret, body)})
    assert tampered.status_code == 401
    # bearer is not accepted on an hmac connector
    assert client.post(url, content=body, headers={"Authorization": f"Bearer {secret}"}).status_code == 401


def test_webhook_size_caps(client):
    out = _create_webhook(client)
    h = {"Authorization": f"Bearer {out['secret']}"}
    url = f"/ingest/webhook/{out['connectorId']}"
    r = client.post(url, json=[{"id": i} for i in range(501)], headers=h)
    assert r.status_code == 413
    r = client.post(url, content=b"[" + b" " * (8 * 1024 * 1024) + b"]", headers=h)
    assert r.status_code == 413


# ── sink ─────────────────────────────────────────────────────────────────────

def test_split_batch_shapes():
    assert sink.split_batch({"a": 1}) == [{"a": 1}]
    assert sink.split_batch([{"a": 1}, "line", 3, ""]) == [{"a": 1}, "line"]
    assert sink.split_batch({"events": [{"a": 1}, {"b": 2}]}) == [{"a": 1}, {"b": 2}]
    assert sink.split_batch({"records": ["l1", "l2"]}) == ["l1", "l2"]
    assert sink.split_batch({"data": "scalar", "x": 1}) == [{"data": "scalar", "x": 1}]
    assert sink.split_batch("one line") == ["one line"]
    with pytest.raises(sink.BatchShapeError):
        sink.split_batch(42)
    with pytest.raises(sink.BatchShapeError) as e:
        sink.split_batch([{"i": i} for i in range(501)])
    assert e.value.too_large


def test_extract_raw_lines():
    assert sink.extract_raw_lines(FGT1) == [FGT1]
    assert sink.extract_raw_lines({"full_log": FGT1, "message": "x"}) == [FGT1]
    assert sink.extract_raw_lines({"event": {"original": FGT2}}) == [FGT2]
    assert sink.extract_raw_lines({"event.original": FGT2}) == [FGT2]
    assert sink.extract_raw_lines({"message": f"{FGT1}\r\n\n{FGT2}\n"}) == [FGT1, FGT2]
    assert sink.extract_raw_lines({"message": "  ", "severity": 3}) == []
    assert sink.extract_raw_lines({"full_log": 5}) == []


def test_raw_lines_to_live_log_dedupe_and_counts(client, data):
    out = _create_webhook(client)
    cid = out["connectorId"]
    h = {"Authorization": f"Bearer {out['secret']}"}
    batch = {"alerts": [{"id": "a1", "full_log": FGT1}, {"id": "a2", "_raw": FGT2},
                        {"id": "a3", "rule": {"level": 10}, "agent": "x"}]}
    r = client.post(f"/ingest/webhook/{cid}", json=batch, headers=h).json()
    assert (r["accepted"], r["lines_forwarded"], r["not_analysable"], r["duplicates"]) == (3, 2, 1, 0)
    assert r["alert_ids"] == ["a1", "a2", "a3"]

    live = data / "ingest" / "live.log"
    assert live.read_text(encoding="utf-8") == f"{FGT1}\n{FGT2}\n"
    recs = (data / "ingest" / cid / "records.ndjson").read_text(encoding="utf-8").splitlines()
    assert len(recs) == 3
    first = json.loads(recs[0])
    assert first["full_log"] == FGT1
    assert first["_ingestion_meta"]["connector_id"] == cid
    assert first["_ingestion_meta"]["tenant_id"] == "default"
    assert first["_ingestion_meta"]["transport"] == "webhook"

    # re-send: a1..a3 are duplicates; a plain string has no id, so it is always new
    r = client.post(f"/ingest/webhook/{cid}", json=[{"id": "a1", "full_log": FGT1}, FGT2], headers=h).json()
    assert (r["accepted"], r["duplicates"], r["lines_forwarded"]) == (1, 1, 1)
    assert live.read_text(encoding="utf-8").splitlines() == [FGT1, FGT2, FGT2]

    row = client.get("/settings/siem-integrations").json()["integrations"][0]
    assert row["alertsReceived"] == 4
    assert row["linesForwarded"] == 3 and row["notAnalysable"] == 1 and row["duplicates"] == 1
    assert row["lastSeenAt"] and row["observedStatus"] == "active" and row["totalAlerts"] == 4

    # dedupe survives a restart (seen ids are on disk)
    fresh = sink.Sink(data / "ingest", live)
    res = fresh.ingest_many([{"id": "a2", "_raw": FGT2}], source="fortigate", source_hint=None,
                            connector={"connector_id": cid})
    assert res.duplicates == 1 and res.accepted == 0


def test_lifespan_creates_empty_live_log_and_stops_poller(data, monkeypatch):
    monkeypatch.delenv("KILLCHAIN_CONNECTORS", raising=False)       # default: poller on
    from killchain.api import create_app

    from killchain.connectors import poller as poller_mod

    events = []
    real_run = poller_mod.Poller.run

    async def run(self, stop):
        events.append("start")
        await real_run(self, stop)
        events.append("stop")

    monkeypatch.setattr(poller_mod.Poller, "run", run)
    app = create_app(SAMPLE)
    with TestClient(app) as c:
        assert (data / "ingest" / "live.log").read_bytes() == b""
        assert c.get("/settings/siem-vendors").status_code == 200
        assert c.get("/settings/siem-integrations").json() == {"integrations": []}
        assert events == ["start"]
    assert events == ["start", "stop"]          # shutdown stopped the poller cleanly


# ── credentials ──────────────────────────────────────────────────────────────

def test_credentials_key_file_fallback(data, monkeypatch):
    monkeypatch.delenv("CONNECTOR_CREDENTIALS_KEY")
    tok = credentials.encrypt({"token": "abc"})
    keyfile = data / "connectors" / ".credentials_key"
    assert keyfile.exists()
    key = keyfile.read_text().strip()
    assert credentials.decrypt(tok) == {"token": "abc"}
    credentials.encrypt({"x": "y"})
    assert keyfile.read_text().strip() == key              # generated once
    monkeypatch.setenv("CONNECTOR_CREDENTIALS_KEY", KEY)
    with pytest.raises(credentials.CredentialError):
        credentials.decrypt(tok)                           # different key


# ── API pull ─────────────────────────────────────────────────────────────────

def _create_pull(client, url="https://93.184.216.34/api/alerts"):
    r = client.post("/settings/siem-integrations", json={
        "vendor": "custom", "name": "REST", "transport": "api_pull",
        "pull": {"config": {"url": url, "items_path": "data", "id_field": "id",
                            "timestamp_field": "ts", "auth_type": "bearer"},
                 "interval_seconds": 300},
        "credentials": {"token": "vendor-token-123456"},
    })
    assert r.status_code == 201, r.text
    return r.json()


def test_generic_rest_pull_advances_watermark(client, data):
    out = _create_pull(client)
    cid = out["connectorId"]
    assert out["secret"] is None and out["webhookUrl"] is None
    assert out["pull"]["client"] == "generic_rest"
    assert "vendor-token" not in json.dumps(out)
    assert out["pull"]["credentialHint"] == "token ••••3456"

    seen = []
    # newer than the initial watermark (now - 60 min lookback)
    t1 = (datetime.now(timezone.utc) - timedelta(minutes=30)).replace(microsecond=0)
    t2 = t1 + timedelta(minutes=5)
    z = lambda t: t.isoformat().replace("+00:00", "Z")   # noqa: E731
    items = [{"id": "x1", "ts": z(t1), "message": FGT1},
             {"id": "x2", "ts": z(t2), "sev": 5}]

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"data": items})

    store = get_store()

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            p = Poller(store, CollectorSettings(), sink=sink.get_sink(), http=http)
            first = await p.run_connector(store.find_one({"connector_id": cid}))
            second = await p.run_connector(store.find_one({"connector_id": cid}))
            return first, second

    first, second = asyncio.run(go())
    assert first["fetched"] == 2 and first["queued"] == 2 and first["complete"] is True
    assert second["queued"] == 0 and second["duplicates"] == 2
    assert seen[0].headers["Authorization"] == "Bearer vendor-token-123456"
    assert "since=" in str(seen[0].url) and "limit=100" in str(seen[0].url)
    assert seen[1].url.params["since"] == z(t2)          # second poll starts at the newest item

    doc = store.find_one({"connector_id": cid})
    assert doc["pull_state"]["cursor"]["watermark"] == z(t2)
    assert doc["alerts_received"] == 2 and doc["lines_forwarded"] == 1 and doc["not_analysable"] == 1
    assert doc["pull_state"]["lease_owner"] is None
    assert (data / "ingest" / "live.log").read_text(encoding="utf-8") == FGT1 + "\n"
    row = client.get("/settings/siem-integrations").json()["integrations"][0]
    assert row["pullState"]["watermark"] == z(t2)
    assert row["pullState"]["lastRun"]["queued"] == 0 and row["pullState"]["lastError"] is None
    nxt = datetime.fromisoformat(row["pullState"]["nextRunAt"])
    assert nxt > datetime.now(timezone.utc) + timedelta(seconds=200)


def test_pull_auth_failure_is_recorded(client):
    cid = _create_pull(client)["connectorId"]
    store = get_store()

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401))) as http:
            return await Poller(store, CollectorSettings(), http=http).run_connector(
                store.find_one({"connector_id": cid}))

    asyncio.run(go())
    st = client.get("/settings/siem-integrations").json()["integrations"][0]["pullState"]
    assert st["lastError"]["kind"] == "auth" and st["consecutiveFailures"] == 1


def test_ssrf_guard_blocks_link_local_and_private(monkeypatch):
    with pytest.raises(PullError) as e:
        asyncio.run(validate_target_url("https://169.254.169.254/latest/meta-data"))
    assert e.value.kind == "config"
    with pytest.raises(PullError):
        asyncio.run(validate_target_url("https://10.0.0.5/api", allow_private=False))
    with pytest.raises(PullError):
        asyncio.run(validate_target_url("http://93.184.216.34/api", allow_http=False))
    with pytest.raises(PullError):
        asyncio.run(validate_target_url("https://user:pw@93.184.216.34/api"))
    asyncio.run(validate_target_url("https://10.0.0.5/api", allow_private=True))
    asyncio.run(validate_target_url("https://93.184.216.34/api"))


def test_pull_against_link_local_target_fails_without_request(client):
    cid = _create_pull(client, url="https://169.254.169.254/latest")["connectorId"]
    store = get_store()
    calls = []

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as http:
            return await Poller(store, CollectorSettings(), http=http).run_connector(
                store.find_one({"connector_id": cid}))

    asyncio.run(go())
    assert calls == []
    assert store.find_one({"connector_id": cid})["pull_state"]["last_error"]["kind"] == "config"


def test_poll_now_sets_next_run(client):
    cid = _create_pull(client)["connectorId"]
    store = get_store()
    later = datetime.now(timezone.utc) + timedelta(hours=1)
    store.update_one({"connector_id": cid}, {"$set": {"pull_state.next_run_at": later}})
    p = Poller(store, CollectorSettings())
    assert p._due_connectors() == []
    r = client.post(f"/settings/siem-integrations/{cid}/poll-now")
    assert r.status_code == 200
    assert datetime.fromisoformat(r.json()["pullState"]["nextRunAt"]) <= datetime.now(timezone.utc)
    assert [d["connector_id"] for d in p._due_connectors()] == [cid]
    # webhook connectors cannot be polled
    wh = _create_webhook(client)
    assert client.post(f"/settings/siem-integrations/{wh['connectorId']}/poll-now").status_code == 400


# ── syslog (optional, KILLCHAIN_SYSLOG=1) ────────────────────────────────────

def test_syslog_transport_hidden_unless_enabled(client, monkeypatch):
    r = client.post("/settings/siem-integrations", json={
        "vendor": "fortigate", "name": "FW syslog", "transport": "syslog", "allowed_sources": ["127.0.0.1"]})
    assert r.status_code == 400
    monkeypatch.setenv("KILLCHAIN_SYSLOG", "1")
    fg = {v["id"]: v for v in client.get("/settings/siem-vendors").json()["vendors"]}["fortigate"]
    assert "syslog" in fg["transports"]
    r = client.post("/settings/siem-integrations", json={
        "vendor": "fortigate", "name": "FW syslog", "transport": "syslog", "allowed_sources": ["127.0.0.1"]})
    assert r.status_code == 201, r.text
    assert r.json()["authMode"] == "source_ip" and r.json()["syslog"]["allowedSources"] == ["127.0.0.1/32"]
    r = client.post("/settings/siem-integrations", json={
        "vendor": "custom", "name": "Other", "transport": "syslog", "allowed_sources": ["127.0.0.1/32"]})
    assert r.status_code == 400 and "already assigned" in r.json()["detail"]


def test_syslog_tcp_framing():
    from killchain.connectors.syslog_server import extract_frame

    buf = bytearray(b"12 <189>abc def\n<190>next")
    assert extract_frame(buf, 1000) == (b"<189>abc def", 15)
    assert extract_frame(bytearray(b"<190>partial"), 1000) is None
    assert extract_frame(bytearray(b"<1>a\r\n"), 1000) == (b"<1>a", 6)


def test_syslog_udp_and_tcp_reach_live_log(client, data, monkeypatch):
    monkeypatch.setenv("KILLCHAIN_SYSLOG", "1")
    monkeypatch.setenv("SYSLOG_BIND", "127.0.0.1")
    monkeypatch.setenv("SYSLOG_UDP_PORT", "0")      # ephemeral ports
    monkeypatch.setenv("SYSLOG_TCP_PORT", "0")
    from killchain.connectors.syslog_server import SyslogServer, unmatched_sources

    cid = client.post("/settings/siem-integrations", json={
        "vendor": "fortigate", "name": "FW", "transport": "syslog",
        "allowed_sources": ["127.0.0.1"]}).json()["connectorId"]

    async def go():
        srv = SyslogServer(get_store(), CollectorSettings(), sink.get_sink())
        tasks = await srv.start()
        loop = asyncio.get_running_loop()
        udp, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol,
                                                     remote_addr=srv.bound["udp"])
        udp.sendto(b"<189>" + FGT1.encode())
        udp.close()
        _, w = await asyncio.open_connection(*srv.bound["tcp"])
        w.write(b"<189>" + FGT2.encode() + b"\n")
        await w.drain()
        w.close()
        srv.accept_datagram(b"<189>" + FGT1.encode(), "10.9.9.9")       # no connector: dropped
        for _ in range(100):
            if srv.queue.empty() and (data / "ingest" / "live.log").exists() and \
                    len((data / "ingest" / "live.log").read_text().splitlines()) >= 2:
                break
            await asyncio.sleep(0.05)
        await srv.queue.join()
        await srv.close(tasks)

    asyncio.run(go())
    lines = (data / "ingest" / "live.log").read_text(encoding="utf-8").splitlines()
    assert sorted(lines) == sorted([FGT1, FGT2])
    row = client.get("/settings/siem-integrations").json()["integrations"][0]
    assert row["alertsReceived"] == 2 and row["linesForwarded"] == 2
    assert row["syslog"]["lastSenderIp"] == "127.0.0.1"
    assert "10.9.9.9" in [s["address"] for s in unmatched_sources()]
