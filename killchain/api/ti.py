"""Threat intel over HTTP (P11 for P9): the run's indicators, one indicator, and on-demand lookups.

GET  /ti/status               providers, where the results come from, cache
GET  /ti/indicators           every indicator in the run's incidents, worst first
GET  /ti/indicators/{value}   one indicator with each provider's full result
POST /ti/lookup               look up a value now (same never-send rules; rate limited)

Results come from <run>/enrichment.json when the engine has run
(python -m killchain.enrich), else from the incidents' own `enrichment`.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from killchain.enrich.cache import TiCache
from killchain.enrich.engine import Engine
from killchain.enrich.indicators import classify, collect
from killchain.enrich.settings import CACHE_PATH, load_dotenv, ti_config

from .bundle import RunBundle

_RANK = {"known-malicious": 3, "suspicious": 2, "no-reports": 1, "unknown": 0}


class TiStore:
    def __init__(self, bundle: RunBundle, cache_path: Path = CACHE_PATH, offline: Optional[bool] = None,
                 otx_client: Any = None):
        load_dotenv()                      # keys from .env; never logged
        self.bundle = bundle
        self.offline = (os.environ.get("KILLCHAIN_TI_OFFLINE", "").lower() in ("1", "true", "yes")
                        if offline is None else offline)
        self.cache = TiCache(cache_path)
        self.engine = Engine.default(self.cache, bundle.incidents, bundle.alerts, offline=self.offline,
                                     otx_client=otx_client)
        self.known = collect(bundle.incidents, bundle.alerts)     # where each indicator appears
        self.doc = bundle.enrichment
        self.entities: Dict[str, Dict[str, Any]] = (
            dict(self.doc["entities"]) if self.doc else self._from_incidents())
        self.source = "enrichment.json" if self.doc else "incident data"
        self._calls: Deque[float] = deque()
        self._calls_lock = threading.Lock()
        self.per_minute = int((ti_config().get("on_demand") or {}).get("per_minute") or 20)

    def _from_incidents(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for n, inc in sorted(self.bundle.incidents.items()):
            for value, e in (inc.get("enrichment") or {}).items():
                cur = out.setdefault(value, {**e, "incidents": []})
                cur["incidents"].append(n)
        return out

    def _titles(self, numbers: List[int]) -> List[Dict[str, Any]]:
        return [{"incident_number": n, "title": self.bundle.incidents[n].get("title")}
                for n in numbers if n in self.bundle.incidents]

    def row(self, value: str, e: Dict[str, Any]) -> Dict[str, Any]:
        providers = e.get("providers") or []
        otx = next((p for p in providers if p.get("provider") == "otx"), None)
        return {
            "value": value,
            "kind": e.get("kind"),
            "zone": e.get("zone"),
            "verdict": e.get("verdict", "unknown"),
            "reputation": e.get("reputation", 0.0),
            "flagged_by": [p["provider"] for p in providers if p.get("malicious")],
            "answered_by": [p["provider"] for p in providers if p.get("available") and p.get("provider") != "local"],
            "sendable": e.get("sendable", (self.known.get(value).sendable if value in self.known else None)),
            "pulses": (otx or {}).get("detail", {}).get("pulse_count") if otx and otx.get("available") else None,
            "tags": e.get("tags") or [],
            "flags": e.get("flags") or [],
            "incidents": self._titles(e.get("incidents") or []),
        }

    def status(self) -> Dict[str, Any]:
        summary = (self.doc or {}).get("summary") or {}
        return {
            "source": self.source,
            "generated_at": (self.doc or {}).get("generated_at"),
            "offline": self.offline,
            "providers": self.engine.status(),
            "indicators": len(self.entities),
            "verdicts": _count(e.get("verdict", "unknown") for e in self.entities.values()),
            "last_run": {k: summary.get(k) for k in ("lookups", "cache_hits", "failures", "skipped_private", "wall_secs")}
                        if summary else None,
            "cache": self.cache.stats(),
            "on_demand_per_minute": self.per_minute,
            "note": (self.doc or {}).get("note"),
        }

    def allow_call(self) -> Optional[float]:
        """None when an on-demand lookup may run now, else seconds to wait."""
        now = time.monotonic()
        with self._calls_lock:
            while self._calls and now - self._calls[0] > 60:
                self._calls.popleft()
            if len(self._calls) >= self.per_minute:
                return round(60 - (now - self._calls[0]), 1)
            self._calls.append(now)
        return None

    def lookup(self, value: str) -> Dict[str, Any]:
        ind = classify(value)
        if ind is None:
            raise ValueError("Not an IP address, domain, URL or file hash.")
        if ind.value in self.known:                  # keep where it appears in the run
            ind.incidents, ind.steps = self.known[ind.value].incidents, self.known[ind.value].steps
        res = self.engine.enrich_one(ind)
        res["value"] = ind.value
        res["in_run"] = ind.value in self.known
        res["not_sent_because"] = ind.reason
        res["incidents"] = self._titles(sorted(ind.incidents))
        return res


def _count(values) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


router = APIRouter(prefix="/ti", tags=["threat intel"])


def _store(request: Request) -> TiStore:
    return request.app.state.ti


@router.get("/status")
def ti_status(request: Request) -> Dict[str, Any]:
    return _store(request).status()


@router.get("/indicators")
def ti_indicators(
    request: Request,
    verdict: Optional[str] = Query(None, description="known-malicious | suspicious | no-reports | unknown"),
    kind: Optional[str] = Query(None, description="ip | domain | url | hash"),
    q: Optional[str] = Query(None, description="text in the value or a tag"),
    sendable: Optional[bool] = Query(None, description="true: only values that may be sent outside"),
    limit: int = Query(500, ge=1, le=2000),
) -> Dict[str, Any]:
    s = _store(request)
    rows = [s.row(v, e) for v, e in s.entities.items()]
    if verdict:
        rows = [r for r in rows if r["verdict"] == verdict]
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    if sendable is not None:
        rows = [r for r in rows if bool(r["sendable"]) == sendable]
    if q:
        needle = q.strip().lower()
        rows = [r for r in rows if needle in r["value"].lower() or any(needle in t.lower() for t in r["tags"])]
    rows.sort(key=lambda r: (-_RANK.get(r["verdict"], 0), -(r["reputation"] or 0), -len(r["incidents"]), r["value"]))
    return {"total": len(rows), "source": s.source, "indicators": rows[:limit]}


@router.get("/indicators/{value:path}")
def ti_indicator(value: str, request: Request) -> Dict[str, Any]:
    s = _store(request)
    e = s.entities.get(value.strip()) or s.entities.get(value.strip().lower())
    if e is None:
        raise HTTPException(status_code=404, detail=f"{value} is not an indicator of this run")
    key = value.strip() if value.strip() in s.entities else value.strip().lower()
    return {**s.row(key, e), "providers": e.get("providers") or []}


class LookupBody(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)


@router.post("/lookup")
def ti_lookup(body: LookupBody, request: Request) -> Dict[str, Any]:
    s = _store(request)
    wait = s.allow_call()
    if wait is not None:
        raise HTTPException(status_code=429, detail=f"Lookup limit of {s.per_minute} a minute reached; try again in {wait} s.",
                            headers={"Retry-After": str(int(wait) + 1)})
    try:
        return s.lookup(body.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
