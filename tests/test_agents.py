"""P10b part 1: LLM client, fact sheet, narrator guard and report.json (track B).

The LLM is a mock OpenAI-compatible server (httpx MockTransport), so the real SDK, its
headers and its error classes are exercised; nothing reaches the network.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import httpx
import pytest

import killchain.agents.__main__ as agents_cli
from killchain.agents.facts import allowed_values, fact_sheet, required_values
from killchain.agents.llm import LLMClient, LLMError, LLMStore, RateLimiter, estimate_tokens, parse_duration
from killchain.agents.narrator import check, messages_for, narrate
from killchain.agents.settings import Endpoint, Limits, endpoints
from killchain.bundle.build import run_bundle
from killchain.contracts import validate_incident

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"
CFG = {"timeout_s": 5, "temperature": 0, "margin": 1.0, "max_wait_s": 20, "auth_cooldown_s": 600,
       "narrator": {"max_tokens": 700, "prompt_version": 1}}


def rd(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def inc():
    return rd(SAMPLE / "incidents" / "1.json")


def good_answer(inc, **over):
    steps = [{"n": s["n"], "text": f"{s['src']} {s['action']} against {s['dst']}.",
              "evidence_lines": [s["line_sample"][0]["line"]]} for s in inc["chain"]]
    obj = {"summary": f"{inc['chain'][0]['src']} attacked {inc['chain'][0]['dst']} and moved data out. It got through.",
           "steps": steps, "next": "Hosts near the portal may be next.",
           "triage": {"verdict": "looks_real", "confidence": 0.9, "reasons": ["four linked steps", "data moved out"]}}
    obj.update(over)
    return obj


def ep(provider="primary", model="big", rpm=30, rpd=1000, tpm=100000, tpd=1000000):
    return Endpoint(provider, f"https://{provider}.example/v1", "test-key", model, "large", Limits(rpm, rpd, tpm, tpd))


class FakeLLM:
    """OpenAI chat completions. `script` items: dict (an answer object), str (raw content),
    or (status, headers) for an error. Per base host, consumed in order; the last repeats."""

    def __init__(self, scripts):
        self.scripts = {k: list(v) for k, v in scripts.items()}
        self.calls = []

    def __call__(self, request: httpx.Request):
        host = request.url.host.split(".")[0]
        body = json.loads(request.content)
        self.calls.append((host, body))
        script = self.scripts[host]
        item = script.pop(0) if len(script) > 1 else script[0]
        if isinstance(item, tuple):
            status, headers = item
            return httpx.Response(status, headers=headers, json={"error": {"message": "nope", "type": "x"}})
        content = item if isinstance(item, str) else json.dumps(item)
        return httpx.Response(200, headers={"x-ratelimit-remaining-tokens": "5000"}, json={
            "id": "c1", "object": "chat.completion", "created": 0, "model": body["model"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 900, "completion_tokens": 300, "total_tokens": 1200}})

    def http(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def client_for(fake, tmp_path, chain=None, sleeps=None):
    sleeps = sleeps if sleeps is not None else []
    return LLMClient(chain or [ep()], LLMStore(tmp_path / "llm.sqlite"), cfg=CFG, http_client=fake.http(),
                     sleep=sleeps.append)


# ---------------------------------------------------------------- fact sheet

def test_fact_sheet_has_no_raw_lines_and_is_small(inc):
    sheet = fact_sheet(inc)
    blob = json.dumps(sheet)
    assert "date=" not in blob and "devname" not in blob                 # no raw log text
    assert [s["n"] for s in sheet["chain"]] == [s["n"] for s in inc["chain"]]
    assert all(len(s["evidence_lines"]) <= 3 for s in sheet["chain"])
    assert estimate_tokens(messages_for(sheet)) < 1600


def test_required_and_allowed_values(inc):
    need = required_values(inc)
    assert need["steps"] == [1, 2, 3, 4] and "32.127.48.11" in need["ips"] and "10.10.20.20" in need["ips"]
    allowed = allowed_values(inc)
    assert {"T1190", "T1505.003"} <= allowed["techniques"]
    assert inc["chain"][0]["line_sample"][0]["line"] in allowed["lines"]


# ---------------------------------------------------------------- guard

def test_guard_accepts_a_faithful_answer(inc):
    assert check(good_answer(inc), inc) == []


@pytest.mark.parametrize("change, problem", [
    (lambda o, i: o.update(summary=o["summary"] + " 8.8.8.8 helped."), "mentions IP 8.8.8.8"),
    (lambda o, i: o["steps"].pop(), "steps must be numbered exactly"),
    (lambda o, i: o["steps"][0]["evidence_lines"].append(1), "cites lines [1]"),
    (lambda o, i: o["steps"][0].update(evidence_lines=[i["chain"][1]["line_sample"][0]["line"]]), "not that step's evidence_lines"),
    (lambda o, i: o.update(next="They may use T1486 next."), "mentions technique T1486"),
    (lambda o, i: o.update(next="See evil-c2.example for details."), "mentions domain evil-c2.example"),
    (lambda o, i: o.update(next="The account svc_backup30 may be used."), "mentions account svc_backup30"),
    (lambda o, i: o.update(summary="Something happened.", steps=[{**s, "text": "A step."} for s in o["steps"]]),
     "leaves out chain IP 32.127.48.11"),
    (lambda o, i: o.update(triage={"verdict": "maybe", "confidence": 2, "reasons": []}), "triage.verdict"),
    (lambda o, i: o.update(next="Read line 9999999 for proof."), "cites line 9999999"),
])
def test_guard_rejects(inc, change, problem):
    obj = good_answer(inc)
    change(obj, inc)
    errs = check(obj, inc, known_accounts={"svc_backup30", "admin"})
    assert any(problem in e for e in errs), errs


def test_guard_allows_common_account_words_and_log_names(inc):
    obj = good_answer(inc, next="An admin login may follow; see firex-10G.log line " +
                      str(inc["chain"][0]["line_sample"][0]["line"]) + ".")
    assert check(obj, inc, known_accounts={"admin"}) == []


# ---------------------------------------------------------------- narrator

def test_narrate_accepts_and_renders(inc, tmp_path):
    fake = FakeLLM({"primary": [good_answer(inc)]})
    o = narrate(inc, client_for(fake, tmp_path))
    assert o.failure is None and o.entry["source"] == "ai" and o.entry["attempts"] == 1
    md = o.entry["markdown"]
    assert "### Summary" in md and "### Triage opinion" in md and "**Looks real** (confidence 0.90)" in md
    first = inc["chain"][0]["line_sample"][0]["line"]
    assert f"*Evidence: line {first}.*" in md
    assert o.entry["triage"] == {"verdict": "looks_real", "confidence": 0.9, "reasons": ["four linked steps", "data moved out"]}
    sent = fake.calls[0][1]
    assert sent["temperature"] == 0 and sent["response_format"] == {"type": "json_object"} and sent["max_tokens"] == 700
    assert "date=" not in sent["messages"][1]["content"]


def test_narrate_retries_once_with_the_problems(inc, tmp_path):
    bad = good_answer(inc, summary="1.2.3.4 did it. Then more.")
    fake = FakeLLM({"primary": [bad, good_answer(inc)]})
    o = narrate(inc, client_for(fake, tmp_path))
    assert o.entry and o.entry["attempts"] == 2
    retry_msgs = fake.calls[1][1]["messages"]
    assert retry_msgs[-1]["role"] == "user" and "mentions IP 1.2.3.4" in retry_msgs[-1]["content"]


def test_narrate_keeps_template_after_two_bad_answers(inc, tmp_path):
    fake = FakeLLM({"primary": [good_answer(inc, steps=[])]})
    o = narrate(inc, client_for(fake, tmp_path))
    assert o.entry is None and "rejected twice" in o.failure and len(fake.calls) == 2


def test_narrate_rejects_non_json(inc, tmp_path):
    fake = FakeLLM({"primary": ["Sure! Here is the report: ..."]})
    o = narrate(inc, client_for(fake, tmp_path))
    assert o.entry is None and "not valid JSON" in o.failure


def test_second_run_comes_from_the_cache(inc, tmp_path):
    fake = FakeLLM({"primary": [good_answer(inc)]})
    narrate(inc, client_for(fake, tmp_path))
    o = narrate(inc, client_for(fake, tmp_path))
    assert len(fake.calls) == 1 and o.entry["cached"] is True


# ---------------------------------------------------------------- client: fallback and limits

def test_auth_error_falls_back_and_pauses_the_provider(inc, tmp_path):
    fake = FakeLLM({"primary": [(401, {})], "fallback": [good_answer(inc)]})
    c = client_for(fake, tmp_path, chain=[ep("primary"), ep("fallback", "small")])
    r = c.chat(messages_for(fact_sheet(inc)))
    assert r.endpoint == "fallback:small" and any("key refused" in n for n in r.notes)
    c.chat([{"role": "user", "content": "another"}])
    assert [h for h, _ in fake.calls] == ["primary", "fallback", "fallback"]   # primary skipped the 2nd time
    assert c.budget()[0]["paused"] is True


def test_429_waits_for_retry_after_then_retries(inc, tmp_path):
    sleeps = []
    fake = FakeLLM({"primary": [(429, {"retry-after": "1.5"}), good_answer(inc)]})
    r = client_for(fake, tmp_path, sleeps=sleeps).chat([{"role": "user", "content": "x"}])
    assert sleeps == [1.5] and r.endpoint == "primary:big" and len(fake.calls) == 2


def test_long_429_moves_to_the_next_model(inc, tmp_path):
    sleeps = []
    fake = FakeLLM({"primary": [(429, {"retry-after": "120"})], "fallback": [good_answer(inc)]})
    c = client_for(fake, tmp_path, chain=[ep("primary"), ep("fallback", "small")], sleeps=sleeps)
    assert c.chat([{"role": "user", "content": "x"}]).endpoint == "fallback:small" and sleeps == []


def test_server_error_is_retried_once_then_gives_up(tmp_path):
    fake = FakeLLM({"primary": [(503, {})]})
    with pytest.raises(LLMError, match="InternalServerError"):
        client_for(fake, tmp_path).chat([{"role": "user", "content": "x"}])
    assert len(fake.calls) == 2


def test_daily_budget_skips_the_model(inc, tmp_path):
    store = LLMStore(tmp_path / "llm.sqlite")
    small = ep("primary", "big", tpd=2000)
    store.add_usage(small.name, 1, 1900)
    fake = FakeLLM({"primary": [good_answer(inc)], "fallback": [good_answer(inc)]})
    c = LLMClient([small, ep("fallback", "small")], store, cfg=CFG, http_client=fake.http(), sleep=lambda s: None)
    r = c.chat([{"role": "user", "content": "x"}], max_tokens=300)
    assert r.endpoint == "fallback:small" and "daily budget used up" in r.notes[0]


def test_minute_buckets_and_headers(tmp_path):
    now = [1000.0]
    lim = RateLimiter(LLMStore(tmp_path / "l.sqlite"), margin=1.0, clock=lambda: now[0])
    e = ep(rpm=2, tpm=1000)
    assert lim.wait_needed(e, 400) == 0
    lim.record(e, 400)
    now[0] += 10
    lim.record(e, 400)
    assert lim.wait_needed(e, 100) == pytest.approx(50)          # 2 requests in the last minute
    now[0] += 55                                                  # first one left the window
    assert lim.wait_needed(e, 100) == 0
    assert lim.wait_needed(e, 5000) is None                       # bigger than a whole minute
    lim.apply_headers(e, {"x-ratelimit-remaining-tokens": "0", "x-ratelimit-reset-tokens": "7.5s"})
    assert lim.wait_needed(e, 10) == pytest.approx(7.5)


def test_parse_duration():
    assert parse_duration("12") == 12 and parse_duration("7.66s") == pytest.approx(7.66)
    assert parse_duration("2m59.56s") == pytest.approx(179.56) and parse_duration("250ms") == pytest.approx(0.25)
    assert parse_duration("1h2m3s") == 3723 and parse_duration(None) is None and parse_duration("soon") is None


def test_endpoints_from_env(monkeypatch):
    for k in ("PRIMARY", "FALLBACK"):
        for f in ("BASE_URL", "API_KEY", "MODEL_LARGE", "MODEL_SMALL"):
            monkeypatch.setenv(f"LLM_{k}_{f}", "")
    monkeypatch.setenv("LLM_PRIMARY_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("LLM_PRIMARY_API_KEY", "k")
    monkeypatch.setenv("LLM_PRIMARY_MODEL_LARGE", "llama-3.3-70b-versatile")
    monkeypatch.setenv("LLM_PRIMARY_MODEL_SMALL", "llama-3.1-8b-instant")
    monkeypatch.setenv("LLM_MAX_REQUESTS_PER_MINUTE", "20")
    chain = endpoints("large")
    assert [e.name for e in chain] == ["primary:llama-3.3-70b-versatile", "primary:llama-3.1-8b-instant"]
    assert chain[0].limits.tokens_per_day == 100000 and chain[0].limits.requests_per_minute == 20
    assert "k" not in repr(chain[0])
    assert [e.name for e in endpoints("small")] == ["primary:llama-3.1-8b-instant"]


# ---------------------------------------------------------------- CLI and bundle

@pytest.fixture
def run(tmp_path, monkeypatch):
    r = tmp_path / "runs" / "demo"
    shutil.copytree(SAMPLE, r)
    for k in ("PRIMARY", "FALLBACK"):
        for f in ("BASE_URL", "API_KEY", "MODEL_LARGE", "MODEL_SMALL"):
            monkeypatch.setenv(f"LLM_{k}_{f}", "")
    monkeypatch.setenv("LLM_PRIMARY_BASE_URL", "https://primary.example/v1")
    monkeypatch.setenv("LLM_PRIMARY_API_KEY", "test-key")
    monkeypatch.setenv("LLM_PRIMARY_MODEL_LARGE", "big")
    monkeypatch.setenv("LLM_ENABLED", "false")
    return r


def test_cli_is_off_by_default(run, tmp_path):
    assert agents_cli.main(["narrate", "--run", str(run), "--cache", str(tmp_path / "c.sqlite")]) == 0
    assert not (run / "report.json").exists()


def test_cli_writes_report_json_then_bundle_merges_it(run, tmp_path, monkeypatch, inc):
    fake = FakeLLM({"primary": [good_answer(inc)]})
    monkeypatch.setattr(agents_cli, "HTTP_CLIENT", fake.http())
    args = ["narrate", "--run", str(run), "--llm", "--cache", str(tmp_path / "c.sqlite")]
    assert agents_cli.main(args) == 0
    doc = rd(run / "report.json")
    entry = doc["incidents"][inc["incident_id"]]
    assert entry["source"] == "ai" and entry["model"] == "primary:big" and doc["usage"]["calls"] == 1
    assert doc["budget"][0]["tokens"] == 1200 and doc["failures"] == {}

    assert agents_cli.main(args) == 0                         # unchanged facts: kept, no call
    assert len(fake.calls) == 1

    template = rd(run / "incidents" / "1.json")["report"]["markdown"]
    assert run_bundle(run).errors == []
    out = rd(run / "incidents" / "1.json")
    assert out["report_source"] == "ai" and out["report"]["template_markdown"] == template
    assert out["report"]["triage"]["verdict"] == "looks_real" and validate_incident(out) == []
    assert rd(run / "index.json")["incidents"][0]["triage_verdict"] == "looks_real"

    (run / "report.json").unlink()                            # reports withdrawn: the template comes back
    run_bundle(run)
    back = rd(run / "incidents" / "1.json")
    assert back["report_source"] == "template" and back["report"]["markdown"] == template


def test_cli_records_failures_and_keeps_template(run, tmp_path, monkeypatch, inc):
    fake = FakeLLM({"primary": [good_answer(inc, steps=[])]})
    monkeypatch.setattr(agents_cli, "HTTP_CLIENT", fake.http())
    assert agents_cli.main(["narrate", "--run", str(run), "--llm", "--cache", str(tmp_path / "c.sqlite")]) == 0
    doc = rd(run / "report.json")
    assert doc["incidents"] == {} and "rejected twice" in doc["failures"][inc["incident_id"]]["reason"]
    run_bundle(run)
    assert rd(run / "incidents" / "1.json")["report_source"] == "template"


# ---------------------------------------------------------------- API: report endpoint and LLM status

def test_report_endpoint_and_health(run, tmp_path, monkeypatch, inc):
    from fastapi.testclient import TestClient

    from killchain.api import create_app

    fake = FakeLLM({"primary": [good_answer(inc)]})
    monkeypatch.setattr(agents_cli, "HTTP_CLIENT", fake.http())
    cache = tmp_path / "c.sqlite"
    agents_cli.main(["narrate", "--run", str(run), "--llm", "--cache", str(cache)])
    run_bundle(run)
    c = TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True, llm_cache=cache))

    ai = c.get("/incidents/1/report").json()
    assert ai["source"] == "ai" and ai["available"] == ["ai", "template"] and ai["model"] == "primary:big"
    assert ai["triage"]["verdict"] == "looks_real" and ai["markdown"].startswith("### Summary")
    tpl = c.get("/incidents/1/report?source=template").json()
    assert tpl["source"] == "template" and tpl["triage"] is None and "### Summary" not in tpl["markdown"]
    assert c.get("/incidents/1/report?source=other").status_code == 422

    llm = c.get("/health").json()["llm"]
    assert llm["configured"] == ["primary:big"] and llm["ai_reports"] == 1 and llm["template_reports"] == 0
    assert llm["budget"][0]["tokens"] == 1200 and llm["budget"][0]["tokens_per_day"] > 0
    assert "test-key" not in json.dumps(llm)


def test_report_endpoint_without_ai(tmp_path):
    from fastapi.testclient import TestClient

    from killchain.api import create_app

    c = TestClient(create_app(SAMPLE, raw_dir=tmp_path, ti_cache=tmp_path / "ti.sqlite", ti_offline=True,
                              llm_cache=tmp_path / "none.sqlite"))
    body = c.get("/incidents/1/report").json()
    assert body["source"] == "template" and body["available"] == ["template"]
    assert c.get("/incidents/1/report?source=ai").status_code == 404
