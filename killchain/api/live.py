"""Live updates (docs/build-plan.md P11 / P15): the API side of live mode.

The live process (track A, P15: `python -m killchain live`) tails a log and rewrites the
run's bundle files as new alerts and incidents appear; it reports its own state in
<run>/live/status.json. The API does not tail anything. It watches the run folder:

- every `interval` seconds it checks the bundle files (index.json, alerts.json, the threat
  intel, metrics.json, run_summary.json); when they changed and then stayed the same for one
  more check (a write in progress is never loaded), it reloads the bundle, swaps it in for
  every endpoint, and records which incidents are new, changed or gone and which alerts are new;
- it reads live/status.json and records when the live process's state changes.

GET /live/status   the watcher, the live process's last status and the recent events
GET /live/stream   the same events as Server-Sent Events (`bundle`, `status`), for the UI

The UI shows changed incidents within about two polls of the files being written.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import orjson
from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

log = logging.getLogger(__name__)
router = APIRouter()

WATCHED = ("index.json", "alerts.json", "ti.json", "enrichment.json", "metrics.json", "run_summary.json",
           "unexplained.json")
STATUS_FILE = Path("live") / "status.json"
STALE_AFTER_S = 15            # a live status older than this means the process is not running
MAX_EVENTS = 200
MAX_IDS = 50                  # ids listed per event


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sig(path: Path) -> Optional[Tuple[int, int]]:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def diff_bundles(old: Any, new: Any) -> Dict[str, Any]:
    """What changed between two loaded bundles, by stable incident_id and alert_id."""
    old_inc = {inc["incident_id"]: old.incident_bytes.get(n) for n, inc in old.incidents.items()}
    new_inc = {inc["incident_id"]: (n, new.incident_bytes.get(n)) for n, inc in new.incidents.items()}
    added = [n for iid, (n, _) in new_inc.items() if iid not in old_inc]
    changed = [n for iid, (n, b) in new_inc.items() if iid in old_inc and old_inc[iid] != b]
    removed = [iid for iid in old_inc if iid not in new_inc]
    old_alerts = {a.get("alert_id") for a in old.alerts}
    new_alerts = [a for a in new.alerts if a.get("alert_id") not in old_alerts]
    return {
        "new_incidents": sorted(added)[:MAX_IDS],
        "changed_incidents": sorted(changed)[:MAX_IDS],
        "removed_incidents": removed[:MAX_IDS],
        "new_alerts": [{k: a.get(k) for k in ("alert_id", "rule_id", "title", "severity", "ts_start",
                                               "incident_number", "src_ip", "dst_ip")}
                       for a in sorted(new_alerts, key=lambda a: a.get("ts_start") or "", reverse=True)[:MAX_IDS]],
        "counts": {"incidents": len(new.incidents), "alerts": len(new.alerts),
                   "new_alerts": len(new_alerts), "new_incidents": len(added), "changed_incidents": len(changed)},
    }


class LiveWatcher:
    """Polls a run folder; reloads the bundle through `reload` when its files change."""

    def __init__(self, run_dir: Path, reload: Callable[[], Any], get_bundle: Callable[[], Any],
                 interval: float = 2.0):
        self.run_dir = Path(run_dir)
        self.reload, self.get_bundle, self.interval = reload, get_bundle, interval
        self.version = 0
        self.events: Deque[Dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self.reloads = 0
        self.loaded_at = now_iso()
        self.last_error: Optional[str] = None
        self.watching = False
        self._sig = self._bundle_sig()
        self._pending: Optional[Tuple[Any, ...]] = None
        self._status_sig = _sig(self.run_dir / STATUS_FILE)
        self.status: Optional[Dict[str, Any]] = self._read_status()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- files
    def _bundle_sig(self) -> Tuple[Any, ...]:
        return tuple(_sig(self.run_dir / n) for n in WATCHED)

    def _read_status(self) -> Optional[Dict[str, Any]]:
        p = self.run_dir / STATUS_FILE
        if not p.is_file():
            return None
        try:
            d = orjson.loads(p.read_bytes())
            return d if isinstance(d, dict) else None
        except (OSError, orjson.JSONDecodeError):
            return None                  # being written; read it next time

    def process_state(self) -> str:
        """running | stopped | stale (no update for a while) | not started."""
        s = self.status
        if not s:
            return "not started"
        state = str(s.get("state") or "running")
        if state != "running":
            return state
        try:
            age = time.time() - datetime.fromisoformat(str(s.get("updated_at")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return "stale"
        return "running" if age <= STALE_AFTER_S else "stale"

    # -- events
    def _emit(self, kind: str, data: Dict[str, Any]) -> None:
        with self._lock:
            self.version += 1
            self.events.append({"id": self.version, "type": kind, "at": now_iso(), **data})

    def events_since(self, since: int) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["id"] > since]

    # -- one check (the thread calls this; tests call it directly)
    def poll(self) -> Optional[str]:
        """Returns 'reloaded', 'status', 'pending', 'error' or None."""
        what = None
        ssig = _sig(self.run_dir / STATUS_FILE)
        if ssig != self._status_sig:
            self._status_sig = ssig
            new = self._read_status()
            if new is not None or ssig is None:
                old_state = self.process_state()
                self.status = new
                self._emit("status", {"state": self.process_state(), "previous": old_state, "status": new})
                what = "status"
        sig = self._bundle_sig()
        if sig == self._sig:
            self._pending = None
            return what
        if sig != self._pending:              # changed since the last check: wait for it to settle
            self._pending = sig
            return what or "pending"
        old = self.get_bundle()
        try:
            new_bundle = self.reload()
        except Exception as exc:  # noqa: BLE001 - a half-written bundle; try again next time
            self.last_error = f"{type(exc).__name__}: {exc}"
            log.warning("live: reload failed, will retry: %s", self.last_error)
            self._pending = None
            return "error"
        self._sig, self._pending = sig, None
        self.reloads += 1
        self.loaded_at = now_iso()
        self.last_error = None
        d = diff_bundles(old, new_bundle)
        self._emit("bundle", d)
        log.info("live: reloaded %s: %s", self.run_dir.name, d["counts"])
        return "reloaded"

    # -- the thread
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.watching = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="live-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.watching = False

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.poll()
            except Exception:  # noqa: BLE001 - never let the watcher die
                log.exception("live: poll failed")

    def snapshot(self) -> Dict[str, Any]:
        b = self.get_bundle()
        return {
            "run": b.run,
            "watching": self.watching,
            "interval_s": self.interval,
            "version": self.version,
            "reloads": self.reloads,
            "loaded_at": self.loaded_at,
            "last_error": self.last_error,
            "process_state": self.process_state(),
            "process": self.status,
            "counts": {"incidents": len(b.incidents), "alerts": len(b.alerts)},
            "how_to_start": "python -m killchain live --run <run> --input <log>  (or: docker compose --profile live up)",
            "events": list(self.events)[-20:][::-1],
        }


def _w(request: Request) -> LiveWatcher:
    return request.app.state.live


@router.get("/live/status", tags=["live"])
def live_status(request: Request) -> Dict[str, Any]:
    """Whether the API is watching the run, the live process's last status, and the latest changes."""
    return _w(request).snapshot()


def _sse(event: Dict[str, Any]) -> str:
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"


@router.get("/live/stream", tags=["live"])
async def live_stream(request: Request,
                      since: Optional[int] = Query(None, ge=0, description="send events after this id (default: only new ones)"),
                      limit: Optional[int] = Query(None, ge=1, le=1000, description="close after this many events")
                      ) -> StreamingResponse:
    """Server-Sent Events: `hello` once, then `bundle` (incidents and alerts changed) and `status`."""
    w = _w(request)
    header = request.headers.get("last-event-id")
    last = int(header) if header and header.isdigit() else (since if since is not None else w.version)

    async def gen():
        nonlocal last
        sent = 0
        hello = {"id": last, "type": "hello", "at": now_iso(), "version": w.version,
                 "process_state": w.process_state(), "watching": w.watching}
        yield "retry: 3000\n\n" + _sse(hello)
        sent += 1
        quiet = 0.0
        while not (limit and sent >= limit):
            if await request.is_disconnected():
                break
            evs = w.events_since(last)
            for e in evs:
                yield _sse(e)
                last = e["id"]
                sent += 1
                if limit and sent >= limit:
                    return
            if not evs:
                await asyncio.sleep(0.5)
                quiet += 0.5
                if quiet >= 15:
                    quiet = 0.0
                    yield ": ping\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
