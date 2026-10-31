"""FastAPI app over a precomputed run bundle (FR-7). No login.

Built so far (P11): /health, /incidents, /incidents/{id}, /incidents/{id}/path
(day 1); /mitre/catalogue, /mitre/matrix, /mitre/techniques/{id} (day 2, in
mitre.py); /incidents/{id}/events (evidence.py) and /entities/{value}
(entities.py) (day 3); /ti/status, /ti/indicators, /ti/indicators/{value},
POST /ti/lookup (ti.py) (day 4); /dashboard/summary, /alerts, /unexplained,
/rules, /rules/{id} (views.py) and /incidents/{id}/report (day 5);
POST /incidents/{id}/ask, /rules/draft|test|save (agents.py); /live/status,
/live/stream (live.py); /metrics, /system (system.py) (day 6).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .bundle import RunBundle, default_raw_dir, load_bundle, resolve_run_dir
from .entities import entity_view
from .evidence import EvidenceStore
from .mitre import MitreStore
from .mitre import router as mitre_router
from .ti import TiStore
from .ti import router as ti_router
from .agents import Agents
from .agents import router as agents_router
from .live import LiveWatcher
from .live import router as live_router
from .system import router as system_router
from .views import RuleStore
from .views import router as views_router
from killchain.enrich.settings import CACHE_PATH
from killchain.connectors.poller import connectors_lifespan
from killchain.connectors.routes import router as connectors_router
from killchain.connectors.webhook import router as ingest_router

# The Vite dev server and the Docker web container (P14).
DEFAULT_CORS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080"

JSON = "application/json"


def _cors_origins() -> List[str]:
    raw = os.environ.get("KILLCHAIN_CORS_ORIGINS") or DEFAULT_CORS
    return [o.strip() for o in raw.split(",") if o.strip()]


def _bundle(request: Request) -> RunBundle:
    return request.app.state.bundle


def _incident_number(b: RunBundle, ident: str) -> int:
    n = b.resolve(ident)
    if n is None:
        raise HTTPException(status_code=404, detail=f"incident {ident} not found in run {b.run}")
    return n


def _technique_matches(wanted: str, techniques: List[str]) -> bool:
    """T1190 matches T1190; a parent (T1110) also matches its sub-techniques (T1110.001)."""
    w = wanted.upper()
    return any(t.upper() == w or t.upper().startswith(w + ".") for t in techniques)


def _entity_values(inc: Dict[str, Any]) -> List[str]:
    ents = inc.get("entities") or {}
    return [v for k in ("ips", "hosts", "users", "domains") for v in (ents.get(k) or [])]


def llm_status(b: RunBundle, cache: Path) -> Dict[str, Any]:
    """LLM agents for /health: on or off, the configured models (no keys), reports in this run and
    today's budget per model from the agents' SQLite file."""
    from killchain.agents.settings import endpoints, llm_enabled

    chain = endpoints("large")
    out: Dict[str, Any] = {"enabled": llm_enabled(), "configured": [e.name for e in chain],
                           "reports": (b.run_summary.get("llm") or {}).get("reports", 0)}
    ai = sum(1 for i in b.incidents.values() if i.get("report_source") == "ai")
    out["ai_reports"] = ai
    out["template_reports"] = len(b.incidents) - ai
    budget: List[Dict[str, Any]] = []
    if chain and Path(cache).exists():
        from killchain.agents.llm import LLMClient, LLMStore

        store = LLMStore(Path(cache))
        try:
            budget = LLMClient(chain, store).budget()
        finally:
            store.close()
    out["budget"] = budget
    return out


def create_app(run: Optional[Union[str, Path]] = None, raw_dir: Optional[Union[str, Path]] = None, *,
               ti_cache: Optional[Union[str, Path]] = None, ti_offline: Optional[bool] = None,
               ti_client: Any = None, llm_cache: Optional[Union[str, Path]] = None,
               llm_client: Any = None, watch: bool = False, watch_interval: float = 1.0) -> FastAPI:
    """Build the app for one run: a folder path or a run name (see resolve_run_dir).

    `raw_dir` is where the raw logs named in the evidence are (default
    KILLCHAIN_RAW_DIR, else data/raw); without them evidence has no raw text.
    `ti_cache` is the threat-intel SQLite cache (default data/cache/ti.sqlite),
    `ti_offline` keeps on-demand lookups off the network (default
    KILLCHAIN_TI_OFFLINE), and `ti_client` replaces the HTTP client (tests).
    `watch` starts the live watcher: the bundle is reloaded when its files change
    (the CLI turns it on; tests call app.state.live.poll() instead).
    """
    run_dir = Path(run) if isinstance(run, Path) else resolve_run_dir(run)
    bundle = load_bundle(run_dir)

    app = FastAPI(
        title="KillChain API",
        description="Incidents, numbered attack chains, attack paths and reach next for one analysed run.",
        version="0.1.0",
        lifespan=connectors_lifespan,     # SIEM connections: API-pull poller, optional syslog
    )
    raw = Path(raw_dir) if raw_dir else default_raw_dir()
    ti_cache_path = Path(ti_cache) if ti_cache else CACHE_PATH

    def attach(b: RunBundle) -> RunBundle:
        """Make `b` the bundle every endpoint serves (start-up, and each live reload)."""
        state = {
            "mitre": MitreStore(b.alerts),
            "evidence": EvidenceStore(run_dir, b.incidents, raw),
            "ti": TiStore(b, ti_cache_path, offline=ti_offline, otx_client=ti_client),
            "rules": RuleStore(b),
        }
        for k, v in state.items():          # built first, then swapped in together
            setattr(app.state, k, v)
        app.state.bundle = b
        app.state.dashboard = None          # rebuilt on the next request (needs the TI status)
        return b

    attach(bundle)
    from killchain.agents.settings import CACHE_PATH as LLM_CACHE

    app.state.llm_cache = Path(llm_cache) if llm_cache else LLM_CACHE
    app.state.agents = Agents(run_dir, app.state.llm_cache, http_client=llm_client)
    app.state.live = LiveWatcher(run_dir, reload=lambda: attach(load_bundle(run_dir)),
                                 get_bundle=lambda: app.state.bundle, interval=watch_interval)
    if watch:
        app.state.live.start()
    app.include_router(mitre_router)
    app.include_router(ti_router)
    app.include_router(views_router)
    app.include_router(agents_router)
    app.include_router(live_router)
    app.include_router(system_router)
    app.include_router(connectors_router)     # /settings/siem-vendors, /settings/siem-integrations...
    app.include_router(ingest_router)         # /ingest/webhook/{connector_id}
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["GET", "POST", "PATCH", "DELETE"],   # PATCH/DELETE: SIEM connection edits
        allow_headers=["Content-Type"],
    )

    @app.get("/health", tags=["system"])
    def health(request: Request) -> Dict[str, Any]:
        """Run name, counts and whether the bundle matched the contracts."""
        b = _bundle(request)
        return {
            "status": "degraded" if b.errors else "ok",
            "run": b.run,
            "sample": b.sample,
            "counts": {
                "incidents": len(b.incidents),
                "alerts": len(b.alerts),
                "events": sum(int(a.get("event_count") or 0) for a in b.alerts),
            },
            "contract_errors": len(b.errors),
            "data_quality": b.run_summary.get("data_quality"),
            "threat_intel": {k: v for k, v in request.app.state.ti.status().items()
                             if k in ("source", "offline", "providers", "indicators", "generated_at")},
            "llm": llm_status(b, request.app.state.llm_cache),
        }

    @app.get("/incidents/{ident}/report", tags=["incidents"])
    def get_report(ident: str, request: Request,
                   source: Optional[str] = Query(None, pattern="^(ai|template)$",
                                                 description="ai | template; default: the one the incident shows")
                   ) -> Dict[str, Any]:
        """The incident's report Markdown: the AI narrator's (when it passed the fact check) or the template."""
        b = _bundle(request)
        inc = b.incidents[_incident_number(b, ident)]
        rep = inc.get("report") or {}
        cur = rep.get("source") or inc.get("report_source") or "template"
        available = [cur] + (["template"] if cur == "ai" and rep.get("template_markdown") else [])
        want = source or cur
        if want not in available:
            raise HTTPException(status_code=404, detail=f"incident {inc['incident_number']} has no {want} report")
        md = rep.get("markdown") if want == cur else rep.get("template_markdown")
        return {"incident_number": inc["incident_number"], "source": want, "available": available,
                "markdown": md, "model": rep.get("model") if want == "ai" else None,
                "triage": rep.get("triage") if want == "ai" else None}

    @app.get("/incidents", tags=["incidents"])
    def list_incidents(
        request: Request,
        severity: Optional[int] = Query(None, ge=1, le=5, description="minimum severity"),
        tactic: Optional[str] = Query(None, description="ATT&CK tactic short name, e.g. initial-access"),
        technique: Optional[str] = Query(None, description="technique id; a parent also matches its sub-techniques"),
        entity: Optional[str] = Query(None, description="exact IP, host, user or domain"),
        q: Optional[str] = Query(None, description="text in the title or an entity"),
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> Dict[str, Any]:
        """Incidents worst first (incident_number is the risk order), as rows of index.json."""
        b = _bundle(request)
        rows = b.index_rows
        if severity is not None:
            rows = [r for r in rows if (r.get("severity") or 0) >= severity]
        if tactic:
            t = tactic.strip().lower().replace(" ", "-")
            rows = [r for r in rows if t in (r.get("tactics") or [])]
        if technique:
            rows = [r for r in rows if _technique_matches(technique.strip(), r.get("techniques") or [])]
        if entity:
            e = entity.strip()
            rows = [r for r in rows if e in _entity_values(b.incidents.get(r["incident_number"], {}))]
        if q:
            needle = q.strip().lower()
            rows = [
                r for r in rows
                if needle in (r.get("title") or "").lower()
                or any(needle in v.lower() for v in _entity_values(b.incidents.get(r["incident_number"], {})))
            ]
        return {
            "run": b.run,
            "total": len(rows),
            "limit": limit,
            "offset": offset,
            "incidents": rows[offset: offset + limit],
        }

    @app.get("/incidents/{ident}", tags=["incidents"])
    def get_incident(ident: str, request: Request) -> Response:
        """The full incident (contract C). `ident` is the incident number or its stable hash."""
        b = _bundle(request)
        return Response(content=b.incident_bytes[_incident_number(b, ident)], media_type=JSON)

    @app.get("/incidents/{ident}/path", tags=["incidents"])
    def get_path(ident: str, request: Request) -> Response:
        """Numbered chain, attack path graph and reach next (FR-5, FR-6)."""
        b = _bundle(request)
        n = _incident_number(b, ident)
        data = b.path_bytes.get(n)
        if data is None:
            raise HTTPException(status_code=500, detail=f"incident {n} has no path view; see /health contract errors")
        return Response(content=data, media_type=JSON)

    @app.get("/incidents/{ident}/events", tags=["incidents"])
    def get_events(
        ident: str,
        request: Request,
        step: Optional[int] = Query(None, ge=1, description="only this chain step"),
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
    ) -> Dict[str, Any]:
        """Evidence lines behind the chain, in time order, with the raw log text read at byte_offset."""
        b = _bundle(request)
        n = _incident_number(b, ident)
        ev: EvidenceStore = request.app.state.evidence
        try:
            out = ev.lines(n, step, offset, limit)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
        out["steps"] = [{"step": s, "lines": c} for s, c in ev.counts_by_step(n)]
        return out

    @app.get("/entities/{value}", tags=["entities"])
    def get_entity(value: str, request: Request) -> Dict[str, Any]:
        """Every incident and alert involving an IP, host, account or domain, plus its threat intel."""
        view = entity_view(_bundle(request), value)
        if view is None:
            raise HTTPException(status_code=404, detail=f"{value} does not appear in run {_bundle(request).run}")
        return view

    return app
