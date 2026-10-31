"""Per-incident risk score (B-1), so the worst incident is listed first.

A fixed weighted sum of seven parts (severity, furthest stage, breadth, success, asset importance, reach
next, threat intel), 0-100, stored in each incident's `risk_parts` with a `detail` sentence per part.
`python -m killchain score --run <run>` scores and renumbers the bundle (risk.py, cli.py).
"""

from .risk import apply_risk, band, load_enrichment, rank, risk_parts

__all__ = ["apply_risk", "band", "load_enrichment", "rank", "risk_parts"]
