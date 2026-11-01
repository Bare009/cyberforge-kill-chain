"""OpenAI-compatible LLM client for the agents (docs/build-plan.md P10b).

- Fallback chain: primary large -> primary small -> fallback large -> fallback small (from .env;
  Groq gpt-oss-120b / gpt-oss-20b, then NeevCloud); the caller falls back to the template
  report when every model fails.
- Reasoning models (config/llm.yaml `reasoning:`) get `reasoning_effort` and extra output tokens,
  since their hidden reasoning counts against max_tokens.
- Every answer is cached in data/cache/llm.sqlite by hash of model + prompt + settings,
  so a rerun only calls the LLM for prompts that changed.
- Per-model budget: requests and tokens per minute and per day (config/llm.yaml, with a
  margin), counted in the same SQLite file so the daily totals survive restarts; Groq's
  x-ratelimit-* headers tighten the minute buckets.
- A 429 waits for retry-after (when short) and is retried once; otherwise the next model.
  A 401/403 pauses that provider. Timeouts and 5xx are retried once after a short backoff.
- temperature 0, 30 s timeout, JSON output mode. Keys are never logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple

from .settings import CACHE_PATH, Endpoint, llm_config

log = logging.getLogger(__name__)

Messages = Sequence[Dict[str, str]]


class LLMError(Exception):
    """No model in the chain gave an answer."""


@dataclass
class LLMResult:
    content: str
    endpoint: str            # provider:model
    model: str
    provider: str
    cached: bool
    prompt_tokens: int = 0
    completion_tokens: int = 0
    notes: List[str] = field(default_factory=list)    # what happened on the way (skips, retries)

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def estimate_tokens(messages: Messages) -> int:
    """Rough token count (about 4 characters a token), used before a call for the budget."""
    return sum(len(m.get("content") or "") for m in messages) // 4 + 8 * len(messages)


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


_DURATION = re.compile(r"(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m(?!s))?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?$")


def parse_duration(text: Optional[str]) -> Optional[float]:
    """Seconds from "12", "1.5", "7.66s", "2m59.56s", "1h2m3s" or "250ms" (Groq header formats)."""
    if not text:
        return None
    t = text.strip()
    try:
        return float(t)
    except ValueError:
        pass
    m = _DURATION.match(t)
    if not m or not any(m.groups()):
        return None
    h, mi, s, ms = (float(x) if x else 0.0 for x in m.groups())
    return h * 3600 + mi * 60 + s + ms / 1000


class LLMStore:
    """SQLite: cached answers and daily usage per model."""

    def __init__(self, path: Path = CACHE_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS answers (key TEXT PRIMARY KEY, endpoint TEXT, created TEXT,
                content TEXT, prompt_tokens INT, completion_tokens INT);
            CREATE TABLE IF NOT EXISTS usage (day TEXT, endpoint TEXT, requests INT, tokens INT,
                PRIMARY KEY (day, endpoint));
        """)
        self._db.commit()

    def get(self, key: str) -> Optional[Tuple[str, int, int]]:
        with self._lock:
            row = self._db.execute("SELECT content, prompt_tokens, completion_tokens FROM answers WHERE key = ?",
                                   (key,)).fetchone()
        return (row[0], int(row[1] or 0), int(row[2] or 0)) if row else None

    def put(self, key: str, endpoint: str, content: str, prompt_tokens: int, completion_tokens: int) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO answers VALUES (?, ?, ?, ?, ?, ?)",
                             (key, endpoint, datetime.now(timezone.utc).isoformat(), content,
                              prompt_tokens, completion_tokens))
            self._db.commit()

    def add_usage(self, endpoint: str, requests: int, tokens: int, day: Optional[str] = None) -> None:
        d = day or today()
        with self._lock:
            self._db.execute("""INSERT INTO usage VALUES (?, ?, ?, ?) ON CONFLICT(day, endpoint)
                                DO UPDATE SET requests = requests + excluded.requests,
                                              tokens = tokens + excluded.tokens""", (d, endpoint, requests, tokens))
            self._db.commit()

    def usage(self, endpoint: str, day: Optional[str] = None) -> Tuple[int, int]:
        with self._lock:
            row = self._db.execute("SELECT requests, tokens FROM usage WHERE day = ? AND endpoint = ?",
                                   (day or today(), endpoint)).fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

    def close(self) -> None:
        with self._lock:
            self._db.close()


class RateLimiter:
    """Minute buckets in memory, day totals in the store; all limits scaled by the margin."""

    def __init__(self, store: LLMStore, margin: float = 0.9, clock: Callable[[], float] = time.monotonic):
        self.store, self.margin, self.clock = store, margin, clock
        self._recent: Dict[str, Deque[Tuple[float, int]]] = {}
        self._blocked_until: Dict[str, float] = {}

    def _window(self, ep: Endpoint) -> Deque[Tuple[float, int]]:
        q = self._recent.setdefault(ep.name, deque())
        now = self.clock()
        while q and now - q[0][0] >= 60:
            q.popleft()
        return q

    def wait_needed(self, ep: Endpoint, tokens: int) -> Optional[float]:
        """Seconds to wait before a call of about `tokens`; None when today's budget is spent."""
        lim, m = ep.limits, self.margin
        req_day, tok_day = self.store.usage(ep.name)
        if req_day + 1 > lim.requests_per_day * m or tok_day + tokens > lim.tokens_per_day * m:
            return None
        now = self.clock()
        wait = max(0.0, self._blocked_until.get(ep.name, 0.0) - now)
        q = self._window(ep)
        if len(q) + 1 > lim.requests_per_minute * m and q:
            wait = max(wait, 60 - (now - q[0][0]))
        used = sum(t for _, t in q)
        if used + tokens > lim.tokens_per_minute * m:
            if tokens > lim.tokens_per_minute * m:
                return None                      # one call bigger than the minute budget: never fits
            acc, need = used, used + tokens - lim.tokens_per_minute * m
            for t0, t in q:                       # wait until enough old calls leave the window
                acc -= t
                if used - acc >= need:
                    wait = max(wait, 60 - (now - t0))
                    break
        return wait

    def record(self, ep: Endpoint, tokens: int) -> None:
        self._window(ep).append((self.clock(), tokens))
        self.store.add_usage(ep.name, 1, tokens)

    def apply_headers(self, ep: Endpoint, headers: Any) -> None:
        """Groq's x-ratelimit-* headers: when a bucket is empty, block until it resets."""
        if headers is None:
            return
        for kind in ("requests", "tokens"):
            rem = headers.get(f"x-ratelimit-remaining-{kind}")
            reset = parse_duration(headers.get(f"x-ratelimit-reset-{kind}"))
            try:
                empty = rem is not None and float(rem) <= 0
            except ValueError:
                empty = False
            if empty and reset:
                self._blocked_until[ep.name] = max(self._blocked_until.get(ep.name, 0.0), self.clock() + reset)


class LLMClient:
    def __init__(self, chain: Sequence[Endpoint], store: Optional[LLMStore] = None, *,
                 cfg: Optional[Dict[str, Any]] = None, http_client: Any = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        self.chain = list(chain)
        self.cfg = cfg if cfg is not None else llm_config()
        self.store = store or LLMStore()
        self.limiter = RateLimiter(self.store, float(self.cfg.get("margin", 0.9)), clock)
        self.sleep, self.clock = sleep, clock
        self.http_client = http_client
        self._clients: Dict[str, Any] = {}
        self._cooldown: Dict[str, float] = {}

    # -- helpers
    def _client(self, ep: Endpoint):
        c = self._clients.get(ep.name)
        if c is None:
            from openai import OpenAI

            c = OpenAI(base_url=ep.base_url, api_key=ep.api_key, max_retries=0,
                       timeout=float(self.cfg.get("timeout_s", 30)), http_client=self.http_client)
            self._clients[ep.name] = c
        return c

    def cache_key(self, ep: Endpoint, messages: Messages, max_tokens: int, json_mode: bool) -> str:
        d: Dict[str, Any] = {"model": ep.model, "provider": ep.provider, "messages": list(messages),
                             "max_tokens": max_tokens, "json": json_mode,
                             "temperature": self.cfg.get("temperature", 0)}
        if ep.reasoning_effort or ep.reasoning_tokens:      # only then, so other models keep their keys
            d["reasoning"] = [ep.reasoning_effort, ep.reasoning_tokens]
        return hashlib.sha256(json.dumps(d, sort_keys=True).encode("utf-8")).hexdigest()

    def cached(self, messages: Messages, max_tokens: int, json_mode: bool = True) -> Optional[LLMResult]:
        for ep in self.chain:
            hit = self.store.get(self.cache_key(ep, messages, max_tokens, json_mode))
            if hit:
                return LLMResult(hit[0], ep.name, ep.model, ep.provider, True, hit[1], hit[2])
        return None

    # -- the call
    def chat(self, messages: Messages, *, max_tokens: int = 700, json_mode: bool = True,
             use_cache: bool = True) -> LLMResult:
        """One answer from the first model in the chain that gives one."""
        import openai

        if use_cache:
            hit = self.cached(messages, max_tokens, json_mode)
            if hit:
                return hit
        if not self.chain:
            raise LLMError("no LLM endpoint configured (LLM_PRIMARY_* / LLM_FALLBACK_* in .env)")
        max_wait = float(self.cfg.get("max_wait_s", 20))
        notes: List[str] = []
        for ep in self.chain:
            if self._cooldown.get(ep.provider, 0) > self.clock():
                notes.append(f"{ep.name}: skipped, key was refused recently")
                continue
            ep_max = max_tokens + ep.reasoning_tokens       # room for a reasoning model's hidden reasoning
            est = estimate_tokens(messages) + ep_max
            for attempt in range(2):
                wait = self.limiter.wait_needed(ep, est)
                if wait is None:
                    notes.append(f"{ep.name}: daily budget used up")
                    break
                if wait > max_wait:
                    notes.append(f"{ep.name}: minute budget full for {wait:.0f} s")
                    break
                if wait > 0:
                    self.sleep(wait)
                try:
                    kwargs: Dict[str, Any] = {"model": ep.model, "messages": list(messages), "max_tokens": ep_max,
                                              "temperature": self.cfg.get("temperature", 0)}
                    if json_mode:
                        kwargs["response_format"] = {"type": "json_object"}
                    if ep.reasoning_effort:
                        kwargs["reasoning_effort"] = ep.reasoning_effort
                    raw = self._client(ep).chat.completions.with_raw_response.create(**kwargs)
                    self.limiter.apply_headers(ep, raw.headers)
                    resp = raw.parse()
                    choice = resp.choices[0]
                    content = (choice.message.content or "").strip()
                    u = getattr(resp, "usage", None)
                    pt = int(getattr(u, "prompt_tokens", 0) or 0)
                    ct = int(getattr(u, "completion_tokens", 0) or 0)
                    self.limiter.record(ep, pt + ct or est)
                    if not content:
                        why = (" (hit max_tokens; raise extra_tokens for this model in config/llm.yaml)"
                               if getattr(choice, "finish_reason", None) == "length" else "")
                        notes.append(f"{ep.name}: empty answer{why}")
                        break
                    if getattr(choice, "finish_reason", None) == "length":
                        # cut off at max_tokens: not cached, so a retry asks again instead of getting this back;
                        # the callers' checks reject a half answer
                        notes.append(f"{ep.name}: answer cut off at max_tokens")
                    else:
                        self.store.put(self.cache_key(ep, messages, max_tokens, json_mode), ep.name, content, pt, ct)
                    return LLMResult(content, ep.name, ep.model, ep.provider, False, pt, ct, notes)
                except (openai.AuthenticationError, openai.PermissionDeniedError):
                    self._cooldown[ep.provider] = self.clock() + float(self.cfg.get("auth_cooldown_s", 600))
                    notes.append(f"{ep.name}: key refused; {ep.provider} paused")
                    break
                except openai.RateLimitError as exc:
                    self.limiter.record(ep, 0)
                    headers = getattr(getattr(exc, "response", None), "headers", None)
                    self.limiter.apply_headers(ep, headers)
                    ra = parse_duration(headers.get("retry-after")) if headers is not None else None
                    if attempt == 0 and ra is not None and ra <= max_wait:
                        notes.append(f"{ep.name}: 429, waiting {ra:.1f} s")
                        self.sleep(ra)
                        continue
                    notes.append(f"{ep.name}: 429 rate limited")
                    break
                except (openai.APITimeoutError, openai.APIConnectionError, openai.InternalServerError) as exc:
                    self.limiter.record(ep, 0)
                    if attempt == 0:
                        notes.append(f"{ep.name}: {type(exc).__name__}, retrying")
                        self.sleep(2.0)
                        continue
                    notes.append(f"{ep.name}: {type(exc).__name__}")
                    break
                except openai.APIStatusError as exc:
                    self.limiter.record(ep, 0)
                    notes.append(f"{ep.name}: HTTP {exc.status_code}")
                    break
        raise LLMError("; ".join(notes) or "no answer")

    # -- budget meter
    def budget(self) -> List[Dict[str, Any]]:
        out = []
        for ep in self.chain:
            req, tok = self.store.usage(ep.name)
            lim = ep.limits
            out.append({"endpoint": ep.name, "provider": ep.provider, "model": ep.model, "size": ep.size,
                        "day": today(), "requests": req, "tokens": tok,
                        "requests_per_day": lim.requests_per_day, "tokens_per_day": lim.tokens_per_day,
                        "tokens_left": max(0, lim.tokens_per_day - tok),
                        "paused": self._cooldown.get(ep.provider, 0) > self.clock()})
        return out
