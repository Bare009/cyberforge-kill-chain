"""AlienVault OTX: pulses (community threat reports) that mention an indicator.

Request logic from AI-SOC backend/services/enrichment/providers/otx.py, with
httpx instead of aiohttp. One GET per indicator:
  /indicators/{IPv4|IPv6|domain|hostname|url|file}/{value}/general
with header X-OTX-API-KEY.

Scoring (docs/build-plan.md P9): score = min(pulses / 5, 1). OTX also returns
`validation`: allow-list hits such as "Whitelisted domain" or "Known False
Positive" (measured: 8.8.8.8, duckdns.org, example.com all carry them, and
example.com is in 18 pulses anyway). An allow-listed indicator scores 0 and is
not flagged, whatever its pulse count.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from ..cache import TiCache
from ..indicators import Indicator
from ..settings import provider_key
from .base import Provider, ProviderError, result

NAME = "otx"
WEB = "https://otx.alienvault.com/indicator"


def _section(ind: Indicator) -> Tuple[str, str]:
    """(API section, web section) for an indicator."""
    if ind.kind == "ip":
        return ("IPv6", "ip") if ipaddress.ip_address(ind.value).version == 6 else ("IPv4", "ip")
    if ind.kind == "domain":
        # OTX keeps registered domains and host names apart; a name with more than two labels is a host name.
        return ("hostname", "hostname") if ind.value.count(".") >= 2 else ("domain", "domain")
    if ind.kind == "url":
        return "url", "url"
    return "file", "file"


def _families(values: Any) -> List[str]:
    out = []
    for v in values or []:
        name = v.get("display_name") or v.get("id") if isinstance(v, dict) else v
        if isinstance(name, str) and name.strip():
            out.append(name.strip())
    return out


def parse_general(ind: Indicator, data: Dict[str, Any], pulses_for_full: int = 5) -> Dict[str, Any]:
    """Turn OTX's /general answer into a provider result."""
    pi = data.get("pulse_info") or {}
    pulses = [p for p in pi.get("pulses") or [] if isinstance(p, dict)]
    count = int(pi.get("count") or len(pulses))
    validation = [v for v in data.get("validation") or [] if isinstance(v, dict)]
    allow_listed = bool(validation)

    tags: Dict[str, int] = {}
    for p in pulses:
        for t in p.get("tags") or []:
            if isinstance(t, str) and t.strip():
                tags[t.strip().lower()] = tags.get(t.strip().lower(), 0) + 1
    families = list(dict.fromkeys(
        _families(f for p in pulses for f in p.get("malware_families") or [])
        + _families((pi.get("related") or {}).get("alienvault", {}).get("malware_families"))))
    adversaries = list(dict.fromkeys(
        [p["adversary"] for p in pulses if isinstance(p.get("adversary"), str) and p["adversary"].strip()]
        + [a for a in (pi.get("related") or {}).get("alienvault", {}).get("adversary") or [] if isinstance(a, str)]))

    score = 0.0 if allow_listed else min(count / max(1, pulses_for_full), 1.0)
    top_tags = [t for t, _ in sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))[:12]]
    out_tags = (["allow-listed"] if allow_listed else []) + ([f"{count} pulses"] if count else []) + top_tags[:6]
    _, web = _section(ind)
    detail = {
        "pulse_count": count,
        "pulses": [{"id": p.get("id"), "name": p.get("name"), "created": p.get("created"),
                    "modified": p.get("modified"), "tags": (p.get("tags") or [])[:6],
                    "url": f"https://otx.alienvault.com/pulse/{p['id']}" if p.get("id") else None}
                   for p in pulses[:5]],
        "tags": top_tags,
        "malware_families": families[:10],
        "adversaries": adversaries[:10],
        "allow_listed": allow_listed,
        "validation": [v.get("message") or v.get("name") for v in validation][:5],
        "country": data.get("country_name"),
        "country_code": data.get("country_code"),
        "asn": data.get("asn"),
        "otx_url": f"{WEB}/{web}/{quote(ind.value, safe='')}",
    }
    return result(NAME, available=True, malicious=(count > 0 and not allow_listed), score=score,
                  tags=out_tags, detail=detail)


class OTXProvider(Provider):
    name = NAME
    label = "AlienVault OTX"
    kinds = frozenset({"ip", "domain", "url", "hash"})
    network = True

    def __init__(self, cfg: Dict[str, Any], cache: TiCache, *, timeout_s: float = 5.0,
                 retries: int = 2, backoff_s: Optional[List[float]] = None,
                 client: Optional[httpx.Client] = None, sleep: Callable[[float], None] = time.sleep):
        self.cfg = cfg
        self.cache = cache
        self.key = provider_key(NAME, cfg)
        self.base = (cfg.get("base_url") or "https://otx.alienvault.com/api/v1").rstrip("/")
        self.retries = retries
        self.backoff = backoff_s or [1, 3]
        self.min_interval = float(cfg.get("min_interval_s") or 0)
        self.daily_cap = int(cfg.get("daily_cap") or 0)
        self.pulses_for_full = int(cfg.get("pulses_for_full_score") or 5)
        self._client = client or httpx.Client(timeout=timeout_s, headers={"User-Agent": "killchain/0.1"})
        self._sleep = sleep
        self._gate = threading.Lock()
        self._last = 0.0

    def ready(self) -> Tuple[bool, str]:
        if not self.cfg.get("enabled", True):
            return False, "disabled"
        if not self.key:
            return False, "no key"
        return True, "ok"

    def _wait_turn(self) -> None:
        with self._gate:
            gap = self.min_interval - (time.monotonic() - self._last)
            if gap > 0:
                self._sleep(gap)
            self._last = time.monotonic()

    def _get(self, path: str) -> Dict[str, Any]:
        for attempt in range(self.retries + 1):
            if self.daily_cap and self.cache.requests_today(NAME) >= self.daily_cap:
                raise ProviderError(f"daily cap of {self.daily_cap} requests reached")
            self._wait_turn()
            self.cache.count_request(NAME)
            try:
                r = self._client.get(self.base + path, headers={"X-OTX-API-KEY": self.key or ""})
            except httpx.TimeoutException:
                err = ProviderError("timeout", retry=True)
            except httpx.HTTPError as exc:
                err = ProviderError(f"network error: {type(exc).__name__}", retry=True)
            else:
                if r.status_code == 200:
                    return r.json()
                if r.status_code == 404:
                    return {}                                   # OTX does not know it
                if r.status_code in (401, 403):
                    raise ProviderError("OTX rejected the API key (HTTP %d)" % r.status_code)
                if r.status_code == 400:
                    raise ProviderError("OTX refused the indicator (HTTP 400)")
                retry = r.status_code == 429 or r.status_code >= 500
                err = ProviderError(f"HTTP {r.status_code}", retry=retry)
                if r.status_code == 429:
                    wait = r.headers.get("retry-after")
                    if wait and wait.isdigit() and attempt < self.retries:
                        self._sleep(min(float(wait), 30))
                        continue
            if not err.retry or attempt >= self.retries:
                raise err
            self._sleep(self.backoff[min(attempt, len(self.backoff) - 1)])
        raise ProviderError("gave up")                          # not reached

    def lookup(self, ind: Indicator) -> Dict[str, Any]:
        section, _ = _section(ind)
        value = quote(ind.value, safe="") if ind.kind == "url" else ind.value
        try:
            data = self._get(f"/indicators/{section}/{value}/general")
        except ProviderError as exc:
            return result(NAME, available=False, error=str(exc))
        return parse_general(ind, data, self.pulses_for_full)
