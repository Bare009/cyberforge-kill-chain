"""Read what the live process publishes, for the API (docs/contracts.md, "Live mode"). Stdlib only.

    from killchain.live.feed import read_events, read_status
    status = read_status(run_dir)                 # live/status.json, or None
    recs = read_events(run_dir, after_seq=last)   # live/events.jsonl records with seq > last

A last line without a newline is still being written and is skipped; read it next time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

STATUS_FILE = Path("live") / "status.json"
EVENTS_FILE = Path("live") / "events.jsonl"


def read_status(run_dir: Union[str, Path]) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads((Path(run_dir) / STATUS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def read_events(run_dir: Union[str, Path], after_seq: int = 0, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    try:
        data = (Path(run_dir) / EVENTS_FILE).read_bytes()
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    end = data.rfind(b"\n")
    if end < 0:
        return out
    for raw in data[:end].split(b"\n"):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict) and int(rec.get("seq") or 0) > after_seq:
            out.append(rec)
            if limit and len(out) >= limit:
                break
    return out
