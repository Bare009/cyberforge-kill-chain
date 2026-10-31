"""FastAPI app over the precomputed incident files (FR-7), no login.

Run: python -m killchain.api --run sample-run
Built: GET /health, /incidents, /incidents/{id}, /incidents/{id}/path.
Planned (docs/build-plan.md P11): dashboard, events, report, ask, alerts,
unexplained, mitre, ti, rules, entities, live, metrics.
"""

from .app import create_app

__all__ = ["create_app"]
