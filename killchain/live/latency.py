"""Measure live-mode latency: from a step's lines being written to its incident being visible.

measure() plays a slice (killchain.live.replay.play) into the file live mode tails and polls, every 0.25 s:
  pipeline side  live/events.jsonl: the first publish record whose new or changed incidents include the
                 step's rule_id and the attacker ip;
  API side       GET {api}/alerts?entity={ip}&incident=any&limit=1000: the first poll where an alert of the
                 step's rule has an incident_number (what the UI shows).
Both are reported from the step's last line written (the step is complete) and from its first line.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import feed
from .replay import load_meta, play

POLL = 0.25


def _api_alerts(api: str, ip: str) -> List[Dict[str, Any]]:
    url = f"{api.rstrip('/')}/alerts?entity={ip}&incident=any&limit=1000"
    with urllib.request.urlopen(url, timeout=5) as r:
        d = json.loads(r.read())
    return d.get("alerts") if isinstance(d, dict) else d


def measure(slice_path: Any, target: Any, run: Any, ip: str, api: Optional[str] = None, rate: float = 500,
            step_pause: float = 8.0, timeout: float = 90.0) -> Dict[str, Any]:
    meta = load_meta(slice_path)
    if not meta or not meta.get("steps"):
        raise ValueError(f"{slice_path}: no .meta.json with steps; make it with tools/replay.py slice")
    run = Path(run)
    rules = [s["rule_id"] for s in meta["steps"]]
    last_seq = max([e["seq"] for e in feed.read_events(run)] or [0])
    seen_pipe: Dict[str, Dict[str, Any]] = {}
    seen_api: Dict[str, float] = {}
    api_errors: List[str] = []
    marks: List[Dict[str, Any]] = []

    # Start from an empty target, and wait until live mode reset and the API dropped the last run's alerts;
    # a replay of the same lines gives the same alert ids, so old ones would read as instantly visible.
    target_p = Path(target)
    if target_p.exists() and target_p.stat().st_size:
        open(target_p, "wb").close()
        deadline = time.time() + 30
        while time.time() < deadline:
            recs = feed.read_events(run, after_seq=last_seq)
            if any(r.get("kind") == "reset" for r in recs):
                break
            time.sleep(POLL)
        else:
            raise TimeoutError("live mode did not report a reset within 30 s; is it running on this target?")
    if api:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if not any(a.get("rule_id") in rules for a in _api_alerts(api, ip)):
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(POLL)
        else:
            raise TimeoutError("the API still shows the previous replay's alerts after 30 s")
    last_seq = max([e["seq"] for e in feed.read_events(run)] or [0])

    def runner() -> None:
        marks.extend(play(slice_path, target, rate=rate, step_pause=step_pause, truncate=False, meta=meta))

    t = threading.Thread(target=runner, daemon=True)
    t_begin = time.time()
    t.start()
    done_at: Optional[float] = None
    while True:
        now = time.time()
        for rec in feed.read_events(run, after_seq=last_seq):
            last_seq = rec["seq"]
            if rec.get("kind") != "publish":
                continue
            for inc in (rec.get("new") or []) + (rec.get("changed") or []):
                if ip not in (inc.get("ips") or []):
                    continue
                for rid in inc.get("rule_ids") or []:
                    if rid in rules and rid not in seen_pipe:
                        seen_pipe[rid] = {"at": rec["at_epoch"], "seen_at": now, "seq": rec["seq"],
                                          "incident_number": inc.get("incident_number"),
                                          "timing_ms": rec.get("timing_ms"), "latency_ms": rec.get("latency_ms"),
                                          "steps": inc.get("steps"), "rule_ids": inc.get("rule_ids")}
        if api:
            try:
                for a in _api_alerts(api, ip):
                    rid = a.get("rule_id")
                    if rid in rules and rid not in seen_api and a.get("incident_number") is not None:
                        seen_api[rid] = now
            except Exception as e:  # noqa: BLE001 - the API may be mid-reload
                api_errors.append(f"{type(e).__name__}: {e}")
        all_seen = all(r in seen_pipe for r in rules) and (not api or all(r in seen_api for r in rules))
        if not t.is_alive():
            done_at = done_at or now
            if all_seen or now - done_at > 30:
                break
        if now - t_begin > timeout:
            break
        time.sleep(POLL)
    t.join(timeout=5)
    by_n = {m["n"]: m for m in marks}
    steps = []
    for s in meta["steps"]:
        m = by_n.get(s["n"], {})
        lw, fw = m.get("last_written_at"), m.get("first_written_at")
        p = seen_pipe.get(s["rule_id"])
        a = seen_api.get(s["rule_id"])
        steps.append({
            "n": s["n"], "rule_id": s["rule_id"], "lines": s.get("count"), "first_written_at": fw,
            "last_written_at": lw,
            "pipeline_s": round(p["at"] - lw, 2) if p and lw else None,
            "api_s": round(a - lw, 2) if a and lw else None,
            "pipeline_from_first_s": round(p["at"] - fw, 2) if p and fw else None,
            "api_from_first_s": round(a - fw, 2) if a and fw else None,
            "publish": p,
        })
    return {"slice": str(slice_path), "target": str(target), "run": str(run), "ip": ip, "api": api, "rate": rate,
            "step_pause": step_pause, "started_at": t_begin, "steps": steps,
            "api_errors": api_errors[:10], "api_error_count": len(api_errors)}
