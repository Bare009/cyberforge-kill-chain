"""FastAPI app over a precomputed run bundle (FR-7). No login.

Built so far (P11, day 1): /health, /incidents, /incidents/{id},
/incidents/{id}/path. The other endpoints of docs/build-plan.md P11 are added
page by page.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .bundle import RunBundle, load_bundle, resolve_run_dir

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


def create_app(run: Optional[Union[str, Path]] = None) -> FastAPI:
    """Build the app for one run: a folder path or a run name (see resolve_run_dir)."""
    run_dir = Path(run) if isinstance(run, Path) else resolve_run_dir(run)
    bundle = load_bundle(run_dir)

    app = FastAPI(
        title="KillChain API",
        description="Incidents, numbered attack chains, attack paths and reach next for one analysed run.",
        version="0.1.0",
    )
    app.state.bundle = bundle
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["GET", "POST"],
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
        }

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

    return app
