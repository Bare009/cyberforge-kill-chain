"""Local context: what the run itself says about an indicator. No network, no score.

From the indicator: address class and zone (config/network.yaml), dynamic-DNS
or unusual top-level domain, a random-looking name.
From the run: the incidents and steps it is in, its alerts, rules, first and
last seen.
From the events (when a prepared or parsed run is given): how often it shows
up in IPS, AV and webfilter logs, failed admin logins from it, how many
internal hosts talked to it, its countries.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from ..indicators import Indicator
from ..settings import ti_config
from .base import Provider, result

log = logging.getLogger(__name__)
NAME = "local"


def label_entropy(label: str) -> float:
    """Shannon entropy in bits per character."""
    if not label:
        return 0.0
    counts = Counter(label)
    n = len(label)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def domain_traits(domain: str) -> Dict[str, Any]:
    cfg = ti_config().get("domains") or {}
    d = domain.lower().rstrip(".")
    labels = d.split(".")
    tld = labels[-1] if labels else ""
    ddns = next((s for s in cfg.get("dynamic_dns_suffixes") or [] if d == s or d.endswith("." + s)), None)
    first = labels[0] if labels else ""
    ent = round(label_entropy(first), 2)
    random_like = (len(first) >= int(cfg.get("random_label_min_length", 9))
                   and ent >= float(cfg.get("random_label_min_entropy", 3.2))
                   and any(ch.isdigit() for ch in first) or len(first) >= 30)
    return {
        "tld": tld,
        "dynamic_dns": ddns,
        "unusual_tld": tld in (cfg.get("unusual_tlds") or []),
        "first_label": first,
        "first_label_length": len(first),
        "first_label_entropy": ent,
        "random_looking": bool(random_like),
    }


class LocalProvider(Provider):
    name = NAME
    label = "Local context"
    kinds = frozenset({"ip", "domain", "url", "hash"})
    network = False

    def __init__(self, incidents: Dict[int, Dict[str, Any]], alerts: Iterable[Dict[str, Any]],
                 events: Any = None):
        """`events` is an optional DuckDB connection with the `events` view (killchain.db.connect)."""
        self.incidents = incidents
        self.alerts = list(alerts)
        self.events = events
        self._events_ok = events is not None

    def lookup(self, ind: Indicator) -> Dict[str, Any]:
        detail: Dict[str, Any] = {
            "zone": ind.zone, "role": ind.role, "importance": ind.importance,
            "sendable": ind.sendable, "not_sent_because": ind.reason,
            "incidents": sorted(ind.incidents),
            "steps": {str(k): sorted(v) for k, v in sorted(ind.steps.items())},
        }
        tags: List[str] = []

        if ind.kind == "ip":
            if ind.zone == "internet":
                tags.append("external")
            elif ind.zone == "public":
                tags.append("own public address")
            elif not ind.sendable and ind.zone in ("unknown", "internet"):
                tags.append("reserved range")
            else:
                tags.append(f"internal ({ind.zone})")
        elif ind.kind == "domain":
            t = domain_traits(ind.value)
            detail.update(t)
            if not ind.sendable:
                tags.append("internal domain")
            if t["dynamic_dns"]:
                tags.append("dynamic-DNS domain")
            if t["unusual_tld"]:
                tags.append(f"unusual TLD .{t['tld']}")
            if t["random_looking"]:
                tags.append("random-looking name")

        hits = self._alert_history(ind.value)
        detail.update(hits)
        if self._events_ok:
            try:
                detail["in_log"] = self._event_history(ind)
            except Exception as exc:                       # never fail the run on local context
                log.warning("local context: event history for %s failed: %s", ind.value, exc)
                detail["in_log"] = None
        return result(NAME, available=True, malicious=False, score=None, tags=tags, detail=detail)

    def _alert_history(self, value: str) -> Dict[str, Any]:
        mine = [a for a in self.alerts if value in (a.get("src_ip"), a.get("dst_ip"), a.get("host"), a.get("domain"))]
        starts = sorted(a["ts_start"] for a in mine if a.get("ts_start"))
        ends = sorted(a["ts_end"] for a in mine if a.get("ts_end"))
        return {
            "alerts": len(mine),
            "rules": sorted({a.get("rule_id") for a in mine if a.get("rule_id")}),
            "first_seen": starts[0] if starts else None,
            "last_seen": ends[-1] if ends else None,
        }

    def _event_history(self, ind: Indicator) -> Optional[Dict[str, Any]]:
        if ind.kind == "ip":
            row = self.events.execute(
                """
                SELECT count(*) AS events,
                       count(*) FILTER (WHERE log_subtype = 'ips') AS ips,
                       count(*) FILTER (WHERE log_subtype = 'virus') AS av,
                       count(*) FILTER (WHERE log_subtype = 'webfilter') AS webfilter,
                       count(*) FILTER (WHERE log_desc = 'Admin login failed' AND src_ip = ?) AS failed_admin_logins,
                       count(DISTINCT CASE WHEN dst_ip = ? THEN src_ip END) FILTER (WHERE src_internal) AS internal_sources,
                       count(DISTINCT CASE WHEN src_ip = ? THEN dst_ip END) FILTER (WHERE dst_internal) AS internal_targets,
                       min(ts) AS first_seen, max(ts) AS last_seen
                FROM events WHERE ts_valid AND (src_ip = ? OR dst_ip = ?)
                """, [ind.value] * 5).fetchone()
            countries = self.events.execute(
                """
                SELECT country, count(*) FROM (
                  SELECT src_country AS country FROM events WHERE ts_valid AND src_ip = ?
                  UNION ALL SELECT dst_country FROM events WHERE ts_valid AND dst_ip = ?)
                WHERE country IS NOT NULL AND country <> 'Reserved' GROUP BY 1 ORDER BY 2 DESC LIMIT 3
                """, [ind.value, ind.value]).fetchall()
            keys = ("events", "ips", "av", "webfilter", "failed_admin_logins", "internal_sources",
                    "internal_targets", "first_seen", "last_seen")
            out = dict(zip(keys, row))
            out["countries"] = [c for c, _ in countries]
        elif ind.kind == "domain":
            row = self.events.execute(
                """
                SELECT count(*), count(DISTINCT src_ip), min(ts), max(ts)
                FROM events WHERE ts_valid AND lower(hostname) = ?
                """, [ind.value]).fetchone()
            out = dict(zip(("events", "internal_sources", "first_seen", "last_seen"), row))
        else:
            return None
        for k in ("first_seen", "last_seen"):
            if out.get(k) is not None and not isinstance(out[k], str):
                out[k] = out[k].isoformat()
        return out


def local_flags(res: Dict[str, Any]) -> List[str]:
    """The local tags worth showing on a chain step."""
    keep = ("dynamic-DNS domain", "random-looking name")
    return [t for t in res.get("tags") or [] if t in keep or t.startswith("unusual TLD")]
