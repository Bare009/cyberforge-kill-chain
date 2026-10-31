"""Threat-intel engine (track B, P9): never-send rules, OTX parsing, cache, offline, retries.

No test reaches the network: OTX answers come from an httpx.MockTransport that
also records every request, so the tests can prove what was (not) sent.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from killchain.enrich.cache import TiCache
from killchain.enrich.engine import Engine, enrich_run, step_flags, verdict_of
from killchain.enrich.indicators import classify, collect
from killchain.enrich.providers.local import domain_traits, label_entropy
from killchain.enrich.providers.otx import OTXProvider, parse_general

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


def load_sample():
    inc = json.loads((SAMPLE / "incidents" / "1.json").read_text(encoding="utf-8"))
    alerts = json.loads((SAMPLE / "alerts.json").read_text(encoding="utf-8"))
    return {1: inc}, alerts


def otx_general(count=0, validation=(), tags=(), families=(), country="United States of America", asn="AS7018"):
    pulses = [{"id": f"p{i}", "name": f"Pulse {i}", "tags": list(tags), "malware_families": list(families),
               "adversary": "", "created": "2026-10-01T00:00:00", "modified": "2026-10-02T00:00:00"}
              for i in range(min(count, 10))]
    return {"pulse_info": {"count": count, "pulses": pulses,
                           "related": {"alienvault": {"adversary": [], "malware_families": []}}},
            "validation": [{"source": "whitelist", "message": m} for m in validation],
            "country_name": country, "asn": asn}


class FakeOTX:
    """Records requests; answers from a {path suffix: (status, json, headers)} map, default 'no pulses'."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        for key, ans in self.answers.items():
            if key in path:
                if isinstance(ans, list):          # a sequence of answers for retries
                    ans = ans.pop(0) if len(ans) > 1 else ans[0]
                status, body, headers = (ans + (None, None))[:3] if isinstance(ans, tuple) else (200, ans, None)
                return httpx.Response(status, json=body, headers=headers or {})
        return httpx.Response(200, json=otx_general())

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    def sent_values(self):
        return [r.url.path for r in self.requests]


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "")


@pytest.fixture
def cache(tmp_path):
    c = TiCache(tmp_path / "ti.sqlite")
    yield c
    c.close()


def otx(cache, fake, **kw):
    cfg = {"enabled": True, "key_env": "OTX_API_KEY", "base_url": "https://otx.test/api/v1", "ttl_hours": 6,
           "min_interval_s": 0, "daily_cap": kw.pop("daily_cap", 0), "pulses_for_full_score": 5}
    return OTXProvider(cfg, cache, client=fake.client(), sleep=lambda s: None, **kw)


# ── never-send rules ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,kind,sendable", [
    ("32.127.48.11", "ip", True),
    ("8.8.8.8", "ip", True),
    ("10.10.20.20", "ip", False),
    ("192.168.1.5", "ip", False),
    ("172.20.0.1", "ip", False),
    ("127.0.0.1", "ip", False),
    ("169.254.1.1", "ip", False),
    ("203.0.113.5", "ip", False),         # the firewall's own public address (documentation range)
    ("192.0.2.88", "ip", False),
    ("198.51.100.23", "ip", False),
    ("100.64.0.1", "ip", False),          # carrier-grade NAT, not global
    ("2001:db8::1", "ip", False),
    ("portal.corp.local", "domain", False),
    ("fileserver.lan", "domain", False),
    ("kjhsdf.duckdns.org", "domain", True),
    ("doqotobitum.com", "domain", True),
    ("http://hoguyusebavox.info/pkg/invoice_2026.pdf.exe", "url", True),
    ("http://10.10.20.20/uploads/img_0931.php", "url", False),
    ("https://portal.corp.local/login", "url", False),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash", True),
])
def test_classify(value, kind, sendable):
    ind = classify(value)
    assert ind is not None and ind.kind == kind and ind.sendable is sendable
    if not sendable:
        assert ind.reason


@pytest.mark.parametrize("value", ["admin", "Deepika.Khan_x", "", "javascript:alert(1)", "not a domain", "a" * 3000])
def test_classify_rejects_non_indicators(value):
    assert classify(value) is None


def test_zones_come_from_network_yaml():
    assert classify("10.10.20.20").zone == "dmz"
    assert classify("10.10.99.1").zone == "mgmt"
    assert classify("10.10.40.7").zone == "iot"
    assert classify("203.0.113.5").zone == "public"
    assert classify("32.127.48.11").zone == "internet"


def test_collect_from_sample():
    incidents, alerts = load_sample()
    found = collect(incidents, alerts)
    assert set(found) == {"32.127.48.11", "10.10.20.20", "10.10.20.31", "portal.corp.local"}
    assert found["32.127.48.11"].steps == {1: {1, 2, 3, 4}}
    assert [v for v, i in found.items() if i.sendable] == ["32.127.48.11"]


def test_private_values_are_never_sent(key, cache):
    """Every private, reserved, internal or own value: the OTX client must receive no request for it."""
    fake = FakeOTX()
    values = ["10.10.20.20", "203.0.113.5", "192.0.2.88", "portal.corp.local", "http://10.10.20.20/x.php",
              "127.0.0.1", "32.127.48.11"]
    inds = {v: classify(v) for v in values}
    for v, i in inds.items():
        i.add_place(1)
    engine = Engine([otx(cache, fake)], cache)
    out, stats = engine.run({i.value: i for i in inds.values()})
    assert fake.sent_values() == ["/api/v1/indicators/IPv4/32.127.48.11/general"]
    assert stats.lookups == 1 and stats.skipped_private == 6
    assert out["203.0.113.5"]["verdict"] == "unknown" and out["203.0.113.5"]["providers"] == []
    for r in fake.requests:
        assert r.headers["X-OTX-API-KEY"] == "test-key"


# ── OTX parsing ──────────────────────────────────────────────────────────────

def test_parse_no_pulses():
    r = parse_general(classify("32.127.48.11"), otx_general())
    assert r["available"] and not r["malicious"] and r["score"] == 0
    assert r["detail"]["pulse_count"] == 0 and r["detail"]["country"] == "United States of America"
    assert r["detail"]["otx_url"] == "https://otx.alienvault.com/indicator/ip/32.127.48.11"


def test_parse_pulses_score_and_families():
    r = parse_general(classify("198.79.124.52"), otx_general(3, tags=["c2", "Cobalt Strike"],
                                                             families=[{"display_name": "Cobalt Strike"}]))
    assert r["malicious"] and r["score"] == 0.6
    assert r["detail"]["malware_families"] == ["Cobalt Strike"]
    assert r["detail"]["tags"][:2] == ["c2", "cobalt strike"]
    assert "3 pulses" in r["tags"]
    assert len(r["detail"]["pulses"]) == 3 and r["detail"]["pulses"][0]["url"] == "https://otx.alienvault.com/pulse/p0"


def test_parse_allow_listed_is_not_flagged_even_with_pulses():
    """Measured: OTX lists example.com in 18 pulses but also allow-lists it."""
    r = parse_general(classify("example.com"), otx_general(18, validation=["Whitelisted domain example.com"]))
    assert r["score"] == 0 and not r["malicious"] and "allow-listed" in r["tags"]
    assert r["detail"]["validation"] == ["Whitelisted domain example.com"]


def test_parse_empty_answer_is_no_reports():
    r = parse_general(classify("1.2.3.4"), {})
    assert r["available"] and r["detail"]["pulse_count"] == 0


@pytest.mark.parametrize("value,path", [
    ("32.127.48.11", "/indicators/IPv4/32.127.48.11/general"),
    ("2606:4700::1111", "/indicators/IPv6/2606:4700::1111/general"),
    ("doqotobitum.com", "/indicators/domain/doqotobitum.com/general"),
    ("kjhsdf.duckdns.org", "/indicators/hostname/kjhsdf.duckdns.org/general"),
    ("d41d8cd98f00b204e9800998ecf8427e", "/indicators/file/d41d8cd98f00b204e9800998ecf8427e/general"),
])
def test_otx_paths(key, cache, value, path):
    fake = FakeOTX()
    otx(cache, fake).lookup(classify(value))
    assert fake.requests[0].url.path == "/api/v1" + path


def test_otx_url_is_encoded(key, cache):
    fake = FakeOTX()
    otx(cache, fake).lookup(classify("http://hoguyusebavox.info/pkg/a.pdf.exe"))
    assert "/indicators/url/http%3A%2F%2Fhoguyusebavox.info%2Fpkg%2Fa.pdf.exe/general" in str(fake.requests[0].url)


def test_otx_404_means_unknown_to_otx(key, cache):
    fake = FakeOTX({"32.127.48.11": (404, {"detail": "not found"})})
    r = otx(cache, fake).lookup(classify("32.127.48.11"))
    assert r["available"] and r["detail"]["pulse_count"] == 0


def test_otx_bad_key_is_reported_not_retried(key, cache):
    fake = FakeOTX({"IPv4": (403, {"detail": "auth"})})
    r = otx(cache, fake).lookup(classify("32.127.48.11"))
    assert not r["available"] and "rejected the API key" in r["error"] and len(fake.requests) == 1


def test_otx_retries_on_429_and_5xx(key, cache):
    fake = FakeOTX({"IPv4": [(429, {}, {"retry-after": "1"}), (502, {}), (200, otx_general(1))]})
    r = otx(cache, fake).lookup(classify("32.127.48.11"))
    assert r["available"] and r["detail"]["pulse_count"] == 1 and len(fake.requests) == 3


def test_otx_gives_up_after_retries(key, cache):
    fake = FakeOTX({"IPv4": (503, {})})
    r = otx(cache, fake, retries=2).lookup(classify("32.127.48.11"))
    assert not r["available"] and r["error"] == "HTTP 503" and len(fake.requests) == 3


def test_otx_timeout_is_a_failure_not_a_crash(key, cache):
    def boom(request):
        raise httpx.ReadTimeout("slow", request=request)
    p = otx(cache, FakeOTX())
    p._client = httpx.Client(transport=httpx.MockTransport(boom))
    r = p.lookup(classify("32.127.48.11"))
    assert not r["available"] and r["error"] == "timeout"


def test_otx_daily_cap(key, cache):
    fake = FakeOTX()
    p = otx(cache, fake, daily_cap=2)
    for v in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        last = p.lookup(classify(v))
    assert len(fake.requests) == 2 and "daily cap" in last["error"]


def test_otx_without_key_is_skipped(no_key, cache):
    fake = FakeOTX()
    p = otx(cache, fake)
    assert p.ready() == (False, "no key")
    ind = classify("32.127.48.11")
    ind.add_place(1)
    out, stats = Engine([p], cache).run({ind.value: ind})
    assert fake.requests == [] and stats.providers == {"otx": "no key"} and out[ind.value]["verdict"] == "unknown"


# ── engine: cache, offline, verdicts ─────────────────────────────────────────

def test_second_run_makes_no_network_calls(key, cache):
    incidents, alerts = load_sample()
    fake = FakeOTX()
    first = enrich_run(incidents, alerts, cache, otx_client=fake.client())
    assert len(fake.requests) == 1 and first["summary"]["lookups"] == 1
    fake2 = FakeOTX()
    second = enrich_run(incidents, alerts, cache, otx_client=fake2.client())
    assert fake2.requests == [] and second["summary"]["cache_hits"] == 1 and second["summary"]["lookups"] == 0
    assert second["entities"]["32.127.48.11"]["verdict"] == "no-reports"


def test_offline_uses_cache_and_local_only(key, cache):
    incidents, alerts = load_sample()
    fake = FakeOTX()
    doc = enrich_run(incidents, alerts, cache, offline=True, otx_client=fake.client())
    assert fake.requests == [] and doc["providers"] == {"local": "ok", "otx": "offline"}
    assert doc["entities"]["32.127.48.11"]["verdict"] == "unknown"           # nothing cached yet
    enrich_run(incidents, alerts, cache, otx_client=FakeOTX().client())      # fill the cache
    doc = enrich_run(incidents, alerts, cache, offline=True, otx_client=fake.client())
    assert fake.requests == [] and doc["entities"]["32.127.48.11"]["verdict"] == "no-reports"


def test_failed_answers_are_not_cached(key, cache):
    incidents, alerts = load_sample()
    enrich_run(incidents, alerts, cache, otx_client=FakeOTX({"IPv4": (500, {})}).client())
    fake = FakeOTX()
    doc = enrich_run(incidents, alerts, cache, otx_client=fake.client())
    assert len(fake.requests) == 1 and doc["summary"]["failures"] == 0


def test_enrichment_document(key, cache):
    incidents, alerts = load_sample()
    fake = FakeOTX({"32.127.48.11": otx_general(4, tags=["scanner"], families=["Mirai"])})
    doc = enrich_run(incidents, alerts, cache, otx_client=fake.client())
    e = doc["entities"]["32.127.48.11"]
    assert e["verdict"] == "known-malicious" and e["reputation"] == 0.8        # 4 pulses / 5 = 0.8
    assert e["incidents"] == [1] and e["sendable"] is True
    assert doc["steps"] == {"1": {str(n): ["OTX: 4 pulses (Mirai)"] for n in (1, 2, 3, 4)}}
    local = next(p for p in e["providers"] if p["provider"] == "local")
    assert local["detail"]["alerts"] == 4 and local["detail"]["rules"] == sorted(local["detail"]["rules"])
    portal = doc["entities"]["portal.corp.local"]
    assert portal["verdict"] == "unknown" and "internal domain" in portal["tags"]
    assert doc["summary"]["verdicts"]["unknown"] == 3


@pytest.mark.parametrize("scores,flagged,expect", [
    ([], False, "unknown"),
    ([0.0], False, "no-reports"),
    ([0.2], True, "suspicious"),
    ([0.4], False, "suspicious"),
    ([0.8], True, "known-malicious"),
])
def test_verdict_thresholds(scores, flagged, expect):
    provs = [{"provider": "otx", "available": True, "score": s, "malicious": flagged} for s in scores]
    provs.append({"provider": "local", "available": True, "score": None, "malicious": False})
    assert verdict_of(provs)[0] == expect


def test_step_flags():
    provs = [
        {"provider": "otx", "available": True, "detail": {"pulse_count": 1, "malware_families": [], "tags": ["c2"]}},
        {"provider": "local", "available": True, "tags": ["external", "dynamic-DNS domain", "unusual TLD .top"]},
    ]
    assert step_flags(provs) == ["OTX: 1 pulse (c2)", "dynamic-DNS domain", "unusual TLD .top"]


# ── local context ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("domain,ddns,unusual,random_like", [
    ("kjhsdf.duckdns.org", "duckdns.org", False, False),
    ("vusaqawofor.top", None, True, False),
    ("kmvatgftbypkn6ul4j30kvpzfmncpcfososlbvu4.doqotobitum.com", None, False, True),
    ("x7k2m9qz4w.example.net", None, False, True),
    ("microsoft.com", None, False, False),
    ("update.microsoft.com", None, False, False),
])
def test_domain_traits(domain, ddns, unusual, random_like):
    t = domain_traits(domain)
    assert t["dynamic_dns"] == ddns and t["unusual_tld"] == unusual and t["random_looking"] == random_like


def test_label_entropy():
    assert label_entropy("aaaa") == 0 and label_entropy("ab") == 1.0
