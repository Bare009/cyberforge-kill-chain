"""On-demand agents (docs/build-plan.md P10b): incident Q&A and the rule writer.

POST /incidents/{id}/ask    {question}     answer citing evidence line numbers (small model)
POST /rules/draft           {description}  a YAML rule written by the large model, validated and test-run
POST /rules/test            {yaml}         validate and test-run a rule (no LLM)
POST /rules/save            {yaml}         save it under rules/ (only on a button press; never overwrites)

Q&A and drafts share a per-minute cap (config/llm.yaml `on_demand_per_minute`); past it
the API answers 429 with Retry-After. Without an LLM key they answer 503; when every
model fails, 502. Tests and saves need no LLM.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from killchain.agents.llm import LLMClient, LLMError, LLMStore
from killchain.agents.settings import endpoints, llm_config

router = APIRouter()


class AskBody(BaseModel):
    question: str = Field(..., max_length=2000)


class DraftBody(BaseModel):
    description: str = Field(..., max_length=4000)


class YamlBody(BaseModel):
    yaml: str = Field(..., max_length=40000)


class Agents:
    """LLM clients (created on first use), the shared cap and the rule-test sandbox for one app."""

    def __init__(self, run_dir, cache_path, http_client: Any = None):
        from killchain.agents.rulewriter import Sandbox

        cfg = llm_config()
        rw = cfg.get("rule_writer") or {}
        self.cache_path = cache_path
        self.http_client = http_client
        self.per_minute = int(cfg.get("on_demand_per_minute", 6))
        self.sandbox = Sandbox(run_dir, memory_limit=str(rw.get("test_memory_limit", "2GB")),
                               timeout_s=float(rw.get("test_timeout_s", 60)))
        self._clients: Dict[str, LLMClient] = {}
        self._store: Optional[LLMStore] = None
        self._lock = threading.Lock()
        self._calls: Deque[float] = deque()

    def client(self, size: str) -> LLMClient:
        with self._lock:
            if size not in self._clients:
                chain = endpoints(size)
                if not chain:
                    raise HTTPException(status_code=503, detail="No LLM is configured: add LLM_PRIMARY_API_KEY "
                                                                "(Groq) or LLM_FALLBACK_API_KEY to .env and restart the API.")
                if self._store is None:
                    self._store = LLMStore(self.cache_path)
                self._clients[size] = LLMClient(chain, self._store, http_client=self.http_client)
            return self._clients[size]

    def check_cap(self) -> None:
        now = time.monotonic()
        with self._lock:
            while self._calls and now - self._calls[0] >= 60:
                self._calls.popleft()
            if len(self._calls) >= self.per_minute:
                wait = int(60 - (now - self._calls[0])) + 1
                raise HTTPException(status_code=429, headers={"Retry-After": str(wait)},
                                    detail=f"Limit of {self.per_minute} questions and drafts a minute reached "
                                           f"(free-tier LLM budget); try again in {wait} s.")
            self._calls.append(now)


def _agents(request: Request) -> Agents:
    return request.app.state.agents


@router.post("/incidents/{ident}/ask", tags=["agents"])
def ask_incident(ident: str, body: AskBody, request: Request) -> Dict[str, Any]:
    """Answer a question about one incident from its facts and up to 60 evidence lines, citing line numbers."""
    from killchain.agents.qa import QuestionError, ask

    b = request.app.state.bundle
    n = b.resolve(ident)
    if n is None:
        raise HTTPException(status_code=404, detail=f"incident {ident} not found in run {b.run}")
    ag = _agents(request)
    client = ag.client("small")
    ag.check_cap()
    try:
        ans = ask(body.question, b.incidents[n], request.app.state.evidence, client)
    except QuestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=f"No model answered: {exc}") from exc
    out = ans.as_dict()
    out["incident_number"] = n
    out["rejected"] = not ans.ok
    if not ans.ok:
        out["problems"] = ans.problems[:5]
        out["note"] = ("The answer was not shown: it cited lines or addresses that are not in this incident's "
                       "evidence. Try asking more narrowly.")
    return out


@router.post("/rules/draft", tags=["rules"])
def draft_rule(body: DraftBody, request: Request) -> Dict[str, Any]:
    """Write a rule from a plain-English description, validate it and test it on this run. Nothing is saved."""
    from killchain.agents.rulewriter import RuleWriterError, draft

    ag = _agents(request)
    if not ag.sandbox.available:
        raise HTTPException(status_code=409, detail="This run has no prepared events.duckdb, so rules cannot be "
                                                    "tested on it.")
    client = ag.client("large")
    ag.check_cap()
    try:
        return draft(body.description, client, ag.sandbox).as_dict()
    except RuleWriterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=f"No model answered: {exc}") from exc


@router.post("/rules/test", tags=["rules"])
def test_rule(body: YamlBody, request: Request) -> Dict[str, Any]:
    """Validate a rule and run it on this run's events: alert count, evidence lines and the first 5 hits."""
    from killchain.agents.rulewriter import RuleWriterError, test

    ag = _agents(request)
    try:
        return test(body.yaml, ag.sandbox)
    except RuleWriterError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/rules/save", tags=["rules"], status_code=201)
def save_rule(body: YamlBody, request: Request, response: Response) -> Dict[str, Any]:
    """Save a valid rule as rules/<firewall|anomaly>/<id>.yaml. Never overwrites an existing rule."""
    from killchain.agents.rulewriter import RuleWriterError, save
    from .views import RuleStore

    try:
        out = save(body.yaml)
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuleWriterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    request.app.state.rules = RuleStore(request.app.state.bundle)        # the new rule shows on the Rules page
    return out
