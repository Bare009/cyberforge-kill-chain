"""Incident builder (FR-4, B-3).

Groups detections that share an IP, user, host or domain within a time window
into incidents, caps hub entities so unrelated attacks do not merge, and counts
the raw alerts merged into each incident. See `engine` for the steps and
`config/correlate.yaml` for the settings.
"""

from .engine import UnionFind, contract_errors, correlate, pair_weights, promotion, time_ok, write_outputs
from .entities import classify_ip, entity_rows, find_hubs, load_settings

__all__ = ["UnionFind", "classify_ip", "contract_errors", "correlate", "entity_rows", "find_hubs", "load_settings",
           "pair_weights", "promotion", "time_ok", "write_outputs"]
