"""Settings for the LLM agents: config/llm.yaml plus endpoints and keys from .env (never logged)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from killchain.enrich.settings import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
LLM_YAML = ROOT / "config" / "llm.yaml"
CACHE_PATH = ROOT / "data" / "cache" / "llm.sqlite"
PROMPTS = Path(__file__).resolve().parent / "prompts"


@dataclass(frozen=True)
class Limits:
    requests_per_minute: int
    requests_per_day: int
    tokens_per_minute: int
    tokens_per_day: int


@dataclass(frozen=True)
class Endpoint:
    """One model at one provider. `name` is how it shows in reports and the budget meter."""
    provider: str            # primary | fallback
    base_url: str
    api_key: str
    model: str
    size: str                # large | small
    limits: Limits
    # reasoning models (gpt-oss, ...): the effort sent with each call, and the output tokens added
    # to every job's max_tokens for the hidden reasoning, which counts against max_tokens
    reasoning_effort: Optional[str] = None
    reasoning_tokens: int = 0

    @property
    def name(self) -> str:
        return f"{self.provider}:{self.model}"

    def __repr__(self) -> str:   # never print the key
        return f"Endpoint({self.name})"


@lru_cache(maxsize=4)
def llm_config(path: str = str(LLM_YAML)) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def limits_for(model: str, cfg: Dict[str, Any]) -> Limits:
    d = {**(cfg.get("default") or {}), **((cfg.get("models") or {}).get(model) or {})}
    rpm = int(d.get("requests_per_minute", 20))
    cap = os.environ.get("LLM_MAX_REQUESTS_PER_MINUTE")
    if cap and cap.strip().isdigit():
        rpm = min(rpm, int(cap))
    return Limits(rpm, int(d.get("requests_per_day", 1000)), int(d.get("tokens_per_minute", 6000)),
                  int(d.get("tokens_per_day", 100000)))


def reasoning_for(model: str, cfg: Dict[str, Any]) -> Tuple[Optional[str], int]:
    """(effort, extra output tokens) from the first `reasoning:` entry whose `match` regex is found
    in the model name (case-insensitive); (None, 0) for a model that does not reason."""
    for r in cfg.get("reasoning") or []:
        if re.search(str(r.get("match") or "^$"), model, re.IGNORECASE):
            effort = r.get("effort")
            return (str(effort) if effort else None), int(r.get("extra_tokens") or 0)
    return None, 0


def endpoints(size: str = "large", cfg: Dict[str, Any] | None = None) -> List[Endpoint]:
    """The fallback chain for a job, from .env. Large jobs: primary large, primary small, fallback
    large, fallback small. Small jobs: primary small, fallback small. Endpoints without a key or
    model are left out."""
    load_dotenv()
    cfg = cfg if cfg is not None else llm_config()
    order = [("primary", "LARGE"), ("primary", "SMALL"), ("fallback", "LARGE"), ("fallback", "SMALL")]
    if size == "small":
        order = [("primary", "SMALL"), ("fallback", "SMALL")]
    out: List[Endpoint] = []
    seen = set()
    for provider, tier in order:
        p = provider.upper()
        url = (os.environ.get(f"LLM_{p}_BASE_URL") or "").strip()
        key = (os.environ.get(f"LLM_{p}_API_KEY") or "").strip()
        model = (os.environ.get(f"LLM_{p}_MODEL_{tier}") or "").strip()
        if not (url and key and model) or (provider, model) in seen:
            continue
        seen.add((provider, model))
        effort, extra = reasoning_for(model, cfg)
        out.append(Endpoint(provider, url, key, model, tier.lower(), limits_for(model, cfg), effort, extra))
    return out


def llm_enabled() -> bool:
    load_dotenv()
    return (os.environ.get("LLM_ENABLED") or "").strip().lower() in ("1", "true", "yes", "on")
