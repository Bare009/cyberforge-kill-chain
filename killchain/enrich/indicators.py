"""Indicators: what can be looked up, and which ones may be sent to an outside service.

Rules (docs/build-plan.md P9):
- Private, reserved and documentation addresses (config/network.yaml
  `private_ranges`, plus anything not globally routable) are classified locally
  and never sent. That includes the firewall's own public address 203.0.113.5.
- Internal domains (.local, .corp, ...) are never sent.
- A URL is sent only when its host is a public IP or public domain.
- Usernames are not indicators and are never collected.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlsplit

from .settings import Network, network, ti_config

HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

KINDS = ("ip", "domain", "url", "hash")


@dataclass
class Indicator:
    value: str
    kind: str                       # ip | domain | url | hash
    sendable: bool                  # may go to an outside service
    reason: Optional[str] = None    # why not, when not sendable
    zone: str = "unknown"
    role: Optional[str] = None
    importance: Optional[float] = None
    # where it appears in the run: incident numbers and the steps it is the src or dst of
    incidents: Set[int] = field(default_factory=set)
    steps: Dict[int, Set[int]] = field(default_factory=dict)

    def add_place(self, incident: int, step: Optional[int] = None) -> None:
        self.incidents.add(incident)
        if step is not None:
            self.steps.setdefault(incident, set()).add(step)


def classify(value: str, net: Optional[Network] = None) -> Optional[Indicator]:
    """An Indicator for a value, or None when it is not something threat intel can look up."""
    net = net or network()
    v = (value or "").strip()
    if not v or len(v) > 2048:
        return None
    try:
        ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        z = net.zone_of(v)
        private = net.is_private(v)
        return Indicator(v, "ip", sendable=not private,
                         reason="private, reserved or own address" if private else None,
                         zone=z["zone"], role=z["role"], importance=z["importance"])
    if HASH_RE.match(v):
        return Indicator(v.lower(), "hash", sendable=True, zone="unknown")
    if "://" in v:
        try:
            host = urlsplit(v).hostname or ""
        except ValueError:
            return None
        if urlsplit(v).scheme.lower() not in ("http", "https", "ftp"):
            return None
        inner = classify(host, net)
        ok = bool(inner and inner.sendable)
        return Indicator(v, "url", sendable=ok, reason=None if ok else "host is internal or not public",
                         zone=inner.zone if inner else "unknown")
    if DOMAIN_RE.match(v):
        d = v.lower().rstrip(".")
        internal = is_internal_domain(d)
        return Indicator(d, "domain", sendable=not internal, reason="internal domain" if internal else None,
                         zone="dmz" if internal else "internet")
    return None


def is_internal_domain(domain: str) -> bool:
    suffixes = (ti_config().get("domains") or {}).get("internal_suffixes") or []
    d = domain.lower()
    return any(d.endswith(s.lower()) for s in suffixes) or "." not in d


def collect(incidents: Dict[int, Dict[str, Any]], alerts: Iterable[Dict[str, Any]] = (),
            net: Optional[Network] = None) -> Dict[str, Indicator]:
    """Every IP, domain, URL and hash in the incidents, with the incidents and steps it appears in.

    Alerts add their domain and URL when they belong to an incident; alerts
    outside every incident are not looked up (the plan keeps lookups to the
    tens or hundreds of indicators in incidents).
    """
    net = net or network()
    out: Dict[str, Indicator] = {}

    def add(value: Any, incident: int, step: Optional[int] = None) -> None:
        if not isinstance(value, str):
            return
        ind = classify(value, net)
        if ind is None:
            return
        cur = out.setdefault(ind.value, ind)
        cur.add_place(incident, step)

    for n, inc in incidents.items():
        ents = inc.get("entities") or {}
        for k in ("ips", "hosts", "domains"):
            for v in ents.get(k) or []:
                add(v, n)
        for node in (inc.get("graph") or {}).get("nodes") or []:
            if node.get("kind") in ("external_ip", "internal_host", "server", "firewall", "domain"):
                add(node.get("id"), n)
        for s in inc.get("chain") or []:
            add(s.get("src"), n, s.get("n"))
            add(s.get("dst"), n, s.get("n"))

    step_of = {s.get("alert_id"): (n, s.get("n")) for n, inc in incidents.items() for s in inc.get("chain") or []}
    for a in alerts:
        place = step_of.get(a.get("alert_id"))
        if place is None:
            continue
        for k in ("domain", "url"):
            add(a.get(k), place[0], place[1])
    return out
