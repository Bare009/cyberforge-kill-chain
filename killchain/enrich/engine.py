"""Threat-intel engine (docs/build-plan.md P9): look up a run's indicators, combine the answers.

For every indicator in the run's incidents:
- the local provider always answers (no network);
- each outside provider (OTX) is asked only when the indicator may be sent,
  the provider has a key, and the cache has no fresh answer;
- offline mode uses only the cache (stale answers included) and local context.

Per entity: reputation = the highest score among outside providers that
answered; verdict known-malicious (>= 0.8), suspicious (>= 0.4 or flagged by
any provider), no-reports (answered, nothing found), unknown (nobody outside
answered, including every private address, which is never sent).

The result never changes which incidents or steps exist.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .cache import TiCache
from .indicators import Indicator, collect
from .providers.base import Provider
from .providers.local import LocalProvider, local_flags
from .providers.otx import OTXProvider
from .settings import ti_config

log = logging.getLogger(__name__)


@dataclass
class EngineStats:
    indicators: int = 0
    sendable: int = 0
    lookups: int = 0              # outside requests made (after the cache)
    cache_hits: int = 0
    failures: int = 0
    skipped_private: int = 0
    providers: Dict[str, str] = field(default_factory=dict)   # name -> ok | no key | disabled | offline
    errors: List[str] = field(default_factory=list)
    wall_secs: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def verdict_of(providers: List[Dict[str, Any]], cfg: Optional[Dict[str, Any]] = None) -> Tuple[str, float]:
    """(verdict, reputation) from the outside providers' results."""
    cfg = cfg or (ti_config().get("verdict") or {})
    outside = [p for p in providers if p.get("provider") != "local" and p.get("available")]
    if not outside:
        return "unknown", 0.0
    rep = max((p["score"] for p in outside if isinstance(p.get("score"), (int, float))), default=0.0)
    flagged = any(p.get("malicious") for p in outside)
    if rep >= float(cfg.get("known_malicious", 0.8)):
        return "known-malicious", rep
    if rep >= float(cfg.get("suspicious", 0.4)) or flagged:
        return "suspicious", rep
    return "no-reports", rep


def step_flags(providers: List[Dict[str, Any]]) -> List[str]:
    """Short notes for a chain step, e.g. "OTX: 12 pulses (cobalt strike)" or "dynamic-DNS domain"."""
    out: List[str] = []
    for p in providers:
        if p.get("provider") == "otx" and p.get("available"):
            d = p.get("detail") or {}
            n = int(d.get("pulse_count") or 0)
            if d.get("allow_listed"):
                out.append("OTX: allow-listed")
            elif n:
                extra = (d.get("malware_families") or d.get("tags") or [])[:2]
                out.append(f"OTX: {n} pulse{'s' if n != 1 else ''}" + (f" ({', '.join(extra)})" if extra else ""))
        elif p.get("provider") == "local":
            out += local_flags(p)
    return out


class Engine:
    def __init__(self, providers: List[Provider], cache: TiCache, *, offline: bool = False,
                 workers: Optional[int] = None):
        cfg = ti_config()
        self.providers = providers
        self.cache = cache
        self.offline = offline
        self.workers = workers or int(cfg.get("workers") or 4)
        self._lock = threading.Lock()
        self.ttl_s = {name: float(((cfg.get("providers") or {}).get(name) or {}).get("ttl_hours") or 24) * 3600
                      for name in ("otx",)}

    @classmethod
    def default(cls, cache: TiCache, incidents: Dict[int, Dict[str, Any]], alerts: Iterable[Dict[str, Any]],
                *, offline: bool = False, events: Any = None, otx_client: Any = None) -> "Engine":
        cfg = ti_config()
        pcfg = cfg.get("providers") or {}
        provs: List[Provider] = []
        if (pcfg.get("local") or {}).get("enabled", True):
            provs.append(LocalProvider(incidents, alerts, events))
        if (pcfg.get("otx") or {}).get("enabled", True):
            provs.append(OTXProvider(pcfg.get("otx") or {}, cache, timeout_s=float(cfg.get("timeout_s") or 5),
                                     retries=int(cfg.get("retries") or 2), backoff_s=cfg.get("backoff_s"),
                                     client=otx_client))
        return cls(provs, cache, offline=offline)

    def status(self) -> Dict[str, str]:
        out = {}
        for p in self.providers:
            ok, why = p.ready()
            out[p.name] = "offline" if (ok and p.network and self.offline) else why
        return out

    def _ask(self, p: Provider, ind: Indicator, stats: EngineStats) -> Optional[Dict[str, Any]]:
        """One provider's answer for one indicator, from the cache or the network."""
        if not p.network:
            return p.lookup(ind)
        if ind.kind not in p.kinds:
            return None
        ok, _ = p.ready()
        cached = self.cache.get(p.name, ind.kind, ind.value, allow_expired=self.offline or not ok)
        if cached is not None:
            with self._lock:
                stats.cache_hits += 1
            return cached
        if not ind.sendable:
            return None
        if self.offline or not ok:
            return None
        with self._lock:
            stats.lookups += 1
        res = p.lookup(ind)
        if res.get("available"):
            self.cache.put(p.name, ind.kind, ind.value, res, self.ttl_s.get(p.name, 86400))
        else:
            with self._lock:
                stats.failures += 1
                msg = f"{p.name}: {res.get('error')}"
                if res.get("error") and msg not in stats.errors:
                    stats.errors.append(msg)
        return res

    def enrich_one(self, ind: Indicator, stats: Optional[EngineStats] = None) -> Dict[str, Any]:
        stats = stats or EngineStats()
        results = [r for r in (self._ask(p, ind, stats) for p in self.providers) if r is not None]
        verdict, rep = verdict_of(results)
        tags = list(dict.fromkeys(t for r in results for t in r.get("tags") or []))
        return {
            "kind": ind.kind, "zone": ind.zone, "verdict": verdict, "reputation": round(rep, 3),
            "providers": results, "tags": tags[:20], "flags": step_flags(results),
            "sendable": ind.sendable,      # may go to outside services (private values never do)
            "incidents": sorted(ind.incidents),
        }

    def run(self, indicators: Dict[str, Indicator]) -> Tuple[Dict[str, Dict[str, Any]], EngineStats]:
        t0 = time.perf_counter()
        stats = EngineStats(indicators=len(indicators),
                            sendable=sum(1 for i in indicators.values() if i.sendable),
                            skipped_private=sum(1 for i in indicators.values() if not i.sendable),
                            providers=self.status())
        values = sorted(indicators)
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            out = dict(zip(values, pool.map(lambda v: self.enrich_one(indicators[v], stats), values)))
        stats.wall_secs = round(time.perf_counter() - t0, 2)
        return out, stats


def enrich_run(incidents: Dict[int, Dict[str, Any]], alerts: List[Dict[str, Any]], cache: TiCache, *,
               offline: bool = False, events: Any = None, otx_client: Any = None) -> Dict[str, Any]:
    """The enrichment.json document for a run."""
    from .providers.base import now_iso

    indicators = collect(incidents, alerts)
    engine = Engine.default(cache, incidents, alerts, offline=offline, events=events, otx_client=otx_client)
    entities, stats = engine.run(indicators)

    steps: Dict[str, Dict[str, List[str]]] = {}
    for n, inc in incidents.items():
        per: Dict[str, List[str]] = {}
        for s in inc.get("chain") or []:
            flags: List[str] = []
            for v in (s.get("src"), s.get("dst")):
                if v in entities:
                    flags += [f for f in entities[v]["flags"] if f not in flags]
            if flags:
                per[str(s["n"])] = flags
        if per:
            steps[str(n)] = per

    verdicts: Dict[str, int] = {}
    for e in entities.values():
        verdicts[e["verdict"]] = verdicts.get(e["verdict"], 0) + 1
    return {
        "generated_at": now_iso(),
        "offline": offline,
        "providers": stats.providers,
        "summary": {**stats.as_dict(), "verdicts": verdicts},
        "entities": entities,
        "steps": steps,
        "note": ("The data set's addresses and domains are synthetic: most come back with no reports, and a hit "
                 "may be unrelated history of a reused real address. External reputation never changes "
                 "which incidents or steps exist."),
    }
