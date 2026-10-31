"""P10b part 2: incident Q&A, rule writer (draft, test, save) and the on-demand limits (track B).

The LLM is the mock server from test_agents.py. Rule tests run on a tiny prepared run made
from test_detect.py's synthetic log, never on the real logs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from killchain import db
from killchain.api import create_app

from test_agents import FakeLLM
from test_detect import RULES, build_lines

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample-run"

COUNT_RULE = {**RULES["count"], "id": "U01-admin-burst", "title": "Admin login burst",
              "attack": {"technique": "T1110.001", "tactic": "credential-access"}}


def rule_yaml(**over) -> str:
    return yaml.safe_dump({**COUNT_RULE, **over}, sort_keys=False)


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    """events.duckdb from the synthetic detect log (one admin brute-force burst)."""
    tmp = tmp_path_factory.mktemp("ondemand")
    (tmp / "t.log").write_text("\n".join(build_lines()) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, "-m", "killchain", "parse", str(tmp / "t.log"), "--out", str(tmp / "p"),
                    "--workers", "1", "--no-summary"], cwd=ROOT, check=True, capture_output=True)
    db.prepare_run(tmp / "p", tmp / "prepared")
    return tmp / "prepared" / db.PREPARED_NAME


@pytest.fixture
def env(tmp_path, monkeypatch, prepared):
    run = tmp_path / "run"
    shutil.copytree(SAMPLE, run)
    shutil.copy(prepared, run / db.PREPARED_NAME)
    rules = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", rules)
    monkeypatch.setenv("KILLCHAIN_RULES_DIR", str(rules))
    for k in ("PRIMARY", "FALLBACK"):
        for f in ("BASE_URL", "API_KEY", "MODEL_LARGE", "MODEL_SMALL"):
            monkeypatch.setenv(f"LLM_{k}_{f}", "")
    monkeypatch.setenv("LLM_PRIMARY_BASE_URL", "https://primary.example/v1")
    monkeypatch.setenv("LLM_PRIMARY_API_KEY", "test-key")
    monkeypatch.setenv("LLM_PRIMARY_MODEL_LARGE", "big")
    monkeypatch.setenv("LLM_PRIMARY_MODEL_SMALL", "small")
    return {"run": run, "rules": rules, "tmp": tmp_path}


def app(env, fake=None, per_minute=None):
    a = create_app(env["run"], raw_dir=env["tmp"], ti_cache=env["tmp"] / "ti.sqlite", ti_offline=True,
                   llm_cache=env["tmp"] / "llm.sqlite", llm_client=fake.http() if fake else None)
    if per_minute is not None:
        a.state.agents.per_minute = per_minute
    return TestClient(a)


def sample_lines():
    inc = json.loads((SAMPLE / "incidents" / "1.json").read_text(encoding="utf-8"))
    ev = json.loads((SAMPLE / "evidence_sample.json").read_text(encoding="utf-8"))
    return inc, ev


# ---------------------------------------------------------------- Q&A

def test_ask_answers_with_cited_lines_and_caches(env):
    inc, ev = sample_lines()
    line = inc["chain"][1]["line_sample"][0]["line"]
    fake = FakeLLM({"primary": [{"answer": f"The SQL injection started at line {line}.", "cited_lines": [line]}]})
    c = app(env, fake)
    r = c.post("/incidents/1/ask", json={"question": "When did the SQL injection start?"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rejected"] is False and body["model"] == "primary:small" and body["cited_lines"][0]["line"] == line
    assert body["cited_lines"][0]["step"] == 2 and 0 < body["lines_given"] <= 60
    sent = json.loads(fake.calls[0][1]["messages"][1]["content"])
    assert sent["question"] == "When did the SQL injection start?" and len(sent["evidence_lines"]) == body["lines_given"]
    again = c.post("/incidents/1/ask", json={"question": "When did the SQL injection start?"}).json()
    assert again["cached"] is True and len(fake.calls) == 1


def test_ask_rejects_foreign_lines_and_ips(env):
    inc, _ = sample_lines()
    line = inc["chain"][0]["line_sample"][0]["line"]
    bad = {"answer": "It began at line 1234567 from 8.8.4.4.", "cited_lines": [1234567]}
    fake = FakeLLM({"primary": [bad]})
    body = app(env, fake).post("/incidents/1/ask", json={"question": "Where did it start?"}).json()
    assert body["rejected"] is True and body["answer"] is None and len(fake.calls) == 2
    assert any("1234567" in p for p in body["problems"]) and any("8.8.4.4" in p for p in body["problems"])

    fixed = FakeLLM({"primary": [bad, {"answer": "It began with a port sweep.", "cited_lines": [line]}]})
    ok = app(env, fixed).post("/incidents/1/ask", json={"question": "Where did it start, really?"}).json()
    assert ok["rejected"] is False and ok["attempts"] == 2
    retry = fixed.calls[1][1]["messages"][-1]["content"]
    assert "not one of the evidence lines given" in retry


def test_ask_errors(env, monkeypatch):
    fake = FakeLLM({"primary": [{"answer": "x", "cited_lines": []}]})
    c = app(env, fake)
    assert c.post("/incidents/1/ask", json={"question": "?"}).status_code == 400
    assert c.post("/incidents/99/ask", json={"question": "What happened?"}).status_code == 404
    down = FakeLLM({"primary": [(503, {})]})
    r = app(env, down).post("/incidents/1/ask", json={"question": "What happened?"})
    assert r.status_code == 502 and "No model answered" in r.json()["detail"]
    monkeypatch.setenv("LLM_PRIMARY_API_KEY", "")
    r = app(env).post("/incidents/1/ask", json={"question": "What happened?"})
    assert r.status_code == 503 and "LLM_PRIMARY_API_KEY" in r.json()["detail"]


def test_on_demand_cap(env):
    fake = FakeLLM({"primary": [{"answer": "Nothing more is known.", "cited_lines": []}]})
    c = app(env, fake, per_minute=2)
    for q in ("First question?", "Second question?"):
        assert c.post("/incidents/1/ask", json={"question": q}).status_code == 200
    r = c.post("/incidents/1/ask", json={"question": "Third question?"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0 and "try again in" in r.json()["detail"]
    assert len(fake.calls) == 2


# ---------------------------------------------------------------- rule test and the sandbox

def test_rule_test_runs_on_the_run(env):
    body = app(env).post("/rules/test", json={"yaml": rule_yaml()}).json()
    assert body["valid"] and body["ran"] and body["alerts"] == 1 and body["evidence_lines"] == 120
    assert body["hits"][0]["rule_id"] == "U01-admin-burst" and body["rule"]["technique"] == "T1110.001"


@pytest.mark.parametrize("text, problem", [
    ("id: [unclosed", "not valid YAML"),
    ("- a list", "must be a YAML mapping"),
    (rule_yaml(id="../evil"), "id must start with a letter"),
    (rule_yaml(kind="bogus"), "kind 'bogus'"),
    (rule_yaml(where="no_such_column = 1"), "does not compile"),
])
def test_rule_test_reports_problems(env, text, problem):
    body = app(env).post("/rules/test", json={"yaml": text}).json()
    assert body["ran"] is False and any(problem in e for e in body["errors"]), body


def test_sandbox_blocks_file_access(env):
    text = rule_yaml(kind="sql", sql="SELECT 'x' AS alert_key, 'f' AS source, 1 AS line FROM read_csv('C:/Windows/win.ini')",
                     window=None, having=None, group_by=None, where=None)
    body = app(env).post("/rules/test", json={"yaml": text}).json()
    assert body["ran"] is False and any("Permission" in e or "disabled" in e for e in body["errors"]), body


def test_sandbox_stops_a_slow_rule(env):
    c = app(env)
    c.app.state.agents.sandbox.timeout_s = 0.5
    text = rule_yaml(kind="sql", where=None, window=None, having=None, group_by=None,
                     sql="SELECT 'k' AS alert_key, 'f' AS source, r.range AS line FROM range(50000000000) r "
                         "WHERE hash(r.range) = 0")
    body = c.post("/rules/test", json={"yaml": text}).json()
    assert body["ran"] is False and any("stopped" in e for e in body["errors"]), body


def test_rule_test_needs_prepared_events(env):
    (env["run"] / db.PREPARED_NAME).unlink()
    r = app(env).post("/rules/test", json={"yaml": rule_yaml()})
    assert r.status_code == 409 and "events.duckdb" in r.json()["detail"]


# ---------------------------------------------------------------- draft and save

def test_draft_writes_validates_and_tests(env):
    fake = FakeLLM({"primary": [{"yaml": rule_yaml(), "explanation": "Bursts of failed admin logins."}]})
    body = app(env, fake).post("/rules/draft", json={"description": "many failed admin logins from one source"}).json()
    assert body["problems"] == [] and body["test"]["alerts"] == 1 and body["model"] == "primary:big"
    sent = json.loads(fake.calls[0][1]["messages"][1]["content"])
    assert any(c.startswith("log_desc ") for c in sent["events_columns"]) and len(sent["example_rules"]) == 3
    assert not list(env["rules"].rglob("U01-admin-burst.yaml"))                    # nothing saved by a draft


def test_draft_retries_then_returns_problems(env):
    bad = {"yaml": rule_yaml(where="no_such_column = 1")}
    fixed = FakeLLM({"primary": [bad, {"yaml": rule_yaml()}]})
    ok = app(env, fixed).post("/rules/draft", json={"description": "failed admin logins burst"}).json()
    assert ok["attempts"] == 2 and ok["problems"] == [] and ok["test"]["ran"]
    assert "does not compile" in fixed.calls[1][1]["messages"][-1]["content"]

    still = FakeLLM({"primary": [bad]})
    body = app(env, still).post("/rules/draft", json={"description": "failed admin logins burst again"}).json()
    assert body["test"] is None and "does not compile" in body["problems"][0] and "no_such_column" in body["yaml"]


def test_draft_errors(env):
    fake = FakeLLM({"primary": [{"yaml": rule_yaml()}]})
    assert app(env, fake).post("/rules/draft", json={"description": "short"}).status_code == 400
    (env["run"] / db.PREPARED_NAME).unlink()
    assert app(env, fake).post("/rules/draft", json={"description": "failed admin logins burst"}).status_code == 409


def test_save_writes_once_and_shows_on_the_rules_page(env):
    c = app(env)
    r = c.post("/rules/save", json={"yaml": rule_yaml()})
    assert r.status_code == 201 and r.json()["path"].endswith("U01-admin-burst.yaml")
    saved = env["rules"] / "firewall" / "U01-admin-burst.yaml"
    assert yaml.safe_load(saved.read_text(encoding="utf-8"))["id"] == "U01-admin-burst"
    assert c.post("/rules/save", json={"yaml": rule_yaml()}).status_code == 409          # never overwrites
    assert c.post("/rules/save", json={"yaml": rule_yaml(id="R01-admin-bruteforce")}).status_code == 409
    assert c.post("/rules/save", json={"yaml": "id: [bad"}).status_code == 400
    assert "U01-admin-burst" in {x["id"] for x in c.get("/rules").json()["rules"]}
    anomaly = c.post("/rules/save", json={"yaml": rule_yaml(id="U02-anomaly", layer="anomaly")})
    assert anomaly.status_code == 201 and (env["rules"] / "anomaly" / "U02-anomaly.yaml").exists()
