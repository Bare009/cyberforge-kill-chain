"""Plain-English incident reports (B-2).

The template report (template.py) is built from the incident's facts only, offline, and is the
fallback for the P10b narrator. `python -m killchain report --run <run>` writes it into every incident.
"""

from .template import ACTIONS, render, report_for

__all__ = ["ACTIONS", "render", "report_for"]
