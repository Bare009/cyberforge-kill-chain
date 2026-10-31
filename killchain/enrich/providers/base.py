"""Provider interface and result shape.

A result (one provider, one indicator) is the contract's provider entry
(docs/contracts.md, Enrichment) plus `fetched_at` and, on failure, `error`:
  {provider, available, malicious, score 0-1 or null, tags[], detail{}, fetched_at, error?}
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from ..indicators import Indicator


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def result(provider: str, *, available: bool, malicious: bool = False, score: Optional[float] = None,
           tags: Optional[List[str]] = None, detail: Optional[Dict[str, Any]] = None,
           error: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "provider": provider, "available": available, "malicious": bool(malicious),
        "score": None if score is None else round(max(0.0, min(1.0, float(score))), 3),
        "tags": tags or [], "detail": detail or {}, "fetched_at": now_iso(),
    }
    if error:
        out["error"] = error
    return out


class ProviderError(Exception):
    """A lookup failed; `retry` says whether trying again may help (429, 5xx, timeout)."""

    def __init__(self, message: str, retry: bool = False):
        super().__init__(message)
        self.retry = retry


class Provider:
    name = "base"
    label = "Base"
    kinds: FrozenSet[str] = frozenset()
    network = True            # False: runs locally, never cached, always allowed

    def ready(self) -> Tuple[bool, str]:
        """(usable, reason). Reasons: ok | disabled | no key."""
        return True, "ok"

    def lookup(self, ind: Indicator) -> Dict[str, Any]:
        raise NotImplementedError
