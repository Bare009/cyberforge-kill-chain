"""Line-level parser entry point for live mode (docs/build-plan.md P15).

    p = LineParser("firex.log")
    tables = p.parse([(raw, line_no, byte_offset), ...])   # {"firewall": pa.Table, "windows": pa.Table}

Each line is classified exactly as `worker.parse_range` does and fed to the same
FortiGateBatch / JsonBatch, so a live row has the same columns, line hash and
time quality as the batch parser gives it. The time-quality state (stuck clock,
backwards jumps) lasts across calls until reset(), as within one batch range.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, Tuple

import pyarrow as pa

from . import arrowutil as au
from .fortigate import PREFIX as FG_PREFIX, FortiGateBatch
from .jsonlog import JsonBatch
from .worker import _CTRL, _hash


class LineParser:
    def __init__(self, source: str, default_tz: int = 0, stuck_run: int = 1000, backwards_secs: int = 300) -> None:
        self.source = source
        self.default_tz = default_tz
        self.stuck_run = stuck_run
        self.backwards_secs = backwards_secs
        self.counts: Counter = Counter()
        self.reset()

    def reset(self) -> None:
        """Forget the time state (a new file after rotation or truncation)."""
        self.tqs = {s: au.TimeQuality(self.stuck_run, self.backwards_secs) for s in ("firewall", "windows")}

    def parse(self, lines: Iterable[Tuple[bytes, int, int]]) -> Dict[str, pa.Table]:
        """(raw without the newline, 1-based line number, byte offset) -> the non-empty stream tables."""
        fw, js = FortiGateBatch(), JsonBatch()
        counts = self.counts
        # Same classification as worker.parse_range (kept in step by hand; the batch loop is tuned for speed).
        for raw, line_no, offset in lines:
            if raw[-1:] == b"\r":
                raw = raw[:-1]
            if raw.startswith(FG_PREFIX):
                fw.add(raw, line_no, offset, _hash(raw))
                counts["firewall"] += 1
            elif raw[:1] == b"{":
                try:
                    obj = au.loads(raw)
                except ValueError:
                    obj = None
                if isinstance(obj, dict):
                    js.add(obj, line_no, offset, _hash(raw))
                    counts["windows"] += 1
                else:
                    reason = "binary" if not raw.isascii() or _CTRL.search(raw) else "bad_json"
                    counts["rejected:" + reason] += 1
            elif not raw.strip():
                counts["blank"] += 1
            else:
                stripped = raw.lstrip(b" \t\xef\xbb\xbf")
                if stripped is not raw and stripped.startswith(FG_PREFIX):
                    fw.add(stripped, line_no, offset, _hash(stripped))
                    counts["firewall"] += 1
                elif not raw.isascii() or _CTRL.search(raw):
                    counts["rejected:binary"] += 1
                else:
                    counts["rejected:unknown_format"] += 1
        out: Dict[str, pa.Table] = {}
        for name, b in (("firewall", fw), ("windows", js)):
            if len(b):
                out[name], _ = b.to_table(self.source, self.tqs[name], self.default_tz)
        return out
