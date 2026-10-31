"""The live loop: tail -> parse -> append to the window -> detect -> correlate ... bundle -> publish.

    eng = LiveEngine("data/raw/live-demo.log", "data/runs/live-demo")
    eng.start()          # guard, rules, backfill from the checkpoint, first publish
    eng.run(stop)        # tick() every interval_s until stop is set
    eng.close()

A tick reads the new complete lines, parses them with the batch parser's line code and appends them to
the in-memory window (killchain.live.table). When the window changed, every active rule reruns over it,
and when the alerts changed (signature: alert_id, event_count, ts_end, success) correlation, chain, reach,
score, report and bundle rebuild the run in a staging folder, which is then published into the run folder
(killchain.live.publish). Each publish that changed something appends a record to live/events.jsonl;
live/status.json is rewritten every tick. The checkpoint is saved only after a publish succeeded.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .. import db
from ..parser.arrowutil import parse_tz
from ..parser.lines import LineParser
from . import publish as pub
from .pipeline import StagePipeline, alert_signatures
from .settings import ROOT, load_settings, select_rules
from .table import LiveTable
from .tailer import FileTailer

CHECKPOINT = Path("live") / "checkpoint.json"
PUBLISHED = Path("live") / "published.json"
PARSE_CHUNK = 100_000
MAX_LIST = pub.MAX_LIST


class GuardError(Exception):
    """The run folder holds a batch bundle; live would replace it."""


class StartError(Exception):
    """Rule errors or an unusable run folder."""


@dataclass
class TickResult:
    new_lines: int = 0
    rows_added: int = 0
    rows_dropped: int = 0
    rebuilt: bool = False
    published: bool = False
    record: Optional[Dict[str, Any]] = None
    reset: Optional[str] = None
    error: Optional[str] = None
    timing_ms: Dict[str, int] = field(default_factory=dict)


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _read_json(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class LiveEngine:
    def __init__(self, input: Union[str, Path], run: Union[str, Path], settings: Optional[Dict[str, Any]] = None,
                 rules_roots: Optional[List[Union[str, Path]]] = None, assume_tz: str = "+00:00",
                 from_start: bool = False, overwrite: bool = False) -> None:
        self.input = Path(input)
        self.run_dir = Path(run)
        self.settings = settings or load_settings()
        self.rules_roots = [str(r) for r in (rules_roots or [ROOT / "rules"])]
        self.default_tz = parse_tz(assume_tz, 0)
        self.from_start = from_start
        self.overwrite = overwrite
        self.interval = float(self.settings["interval_s"])
        self.window_s = int(float(self.settings["window_hours"]) * 3600)
        self.ticks = 0
        self.lines_total = 0
        self.resets = 0
        self.dirty = True
        self.sigs: Optional[frozenset] = None
        self.alerts_by_id: Dict[str, Dict[str, Any]] = {}
        self.last_publish_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.last_tick: Optional[Dict[str, Any]] = None
        self.last_tick_t: Optional[float] = None
        self.lines_per_sec = 0.0
        self.started_at = time.time()
        self.closed = False

    # ── start ────────────────────────────────────────────────────────────────
    def start(self) -> Dict[str, Any]:
        run = self.run_dir
        if (run / "index.json").exists() and not (run / CHECKPOINT).exists() and not self.overwrite:
            raise GuardError(f"{run} holds a batch bundle (index.json) and no live checkpoint; live mode would "
                             f"replace it with a {self.window_s // 3600} h window. Use a new run folder "
                             f"(e.g. data/runs/live-demo) or pass --overwrite.")
        from ..detect import engine
        from ..detect.rules import load_rules

        rules, errors = load_rules(self.rules_roots)
        active, skipped, errs = select_rules(rules, self.window_s, self.settings["skip_rules"])
        errors += errs
        duck = self.settings["duckdb"]
        self.table = LiveTable(db.load_network(), duck.get("memory_limit"), duck.get("threads"))
        cur = self.table.con.cursor()
        errors += [m for m in (engine.check_rule(cur, r) for r in active) if m]
        cur.close()
        if errors:
            raise StartError("rule errors:\n  " + "\n  ".join(errors))
        self.rules, self.skipped = active, skipped
        try:
            (run / "live").mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise StartError(f"cannot write {run / 'live'}: {e}") from None
        self.work = run / "live" / "work" / run.name
        if self.work.exists():
            shutil.rmtree(self.work)
        self.pipeline = StagePipeline(self.work, self.rules)

        ck = None if self.from_start else _read_json(run / CHECKPOINT)
        self.tailer = FileTailer(self.input, int(self.settings["max_line_bytes"]),
                                 int(float(self.settings["max_backfill_mb"]) * 2**20))
        info = self.tailer.start(ck)
        pubd = _read_json(run / PUBLISHED) or {}
        self.prev = pubd.get("incidents") or {}
        self.prev_alert_ids = set(pubd.get("alerts") or [])
        self.parser = LineParser(self.input.name, self.default_tz)
        self.events = pub.EventLog(run)
        self.events.append("start", source=self.input.name, path=str(self.input.resolve()), mode=info["mode"],
                           from_line=info["backfill_from"][1], from_offset=info["backfill_from"][0], pid=os.getpid())
        self.start_info = info
        self.tick(first=True)
        return info

    # ── one tick ─────────────────────────────────────────────────────────────
    def tick(self, first: bool = False) -> TickResult:
        t_start = time.perf_counter()
        read_at = time.time()
        res = TickResult()
        tm = res.timing_ms
        r = self.tailer.poll()
        if r.reset:
            self.table.clear()
            self.parser.reset()
            self.resets += 1
            self.dirty = True
            res.reset = r.reason
            self.events.append("reset", reason=r.reason, source=self.input.name)
        res.new_lines = len(r.lines)
        self.lines_total += len(r.lines)
        t0 = time.perf_counter()
        tables: List[Dict[str, Any]] = []
        for i in range(0, len(r.lines), PARSE_CHUNK):
            tables.append(self.parser.parse(r.lines[i:i + PARSE_CHUNK]))
        tm["parse"] = round((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        for t in tables:
            res.rows_added += sum(self.table.append(t).values())
        if res.rows_added:
            res.rows_dropped = self.table.trim(self.window_s, int(self.settings["max_rows"]))
        tm["insert"] = round((time.perf_counter() - t0) * 1000)

        ok = True
        if res.rows_added or res.rows_dropped or self.dirty or first:
            ok = self._rebuild_and_publish(res, r, read_at, first)
        if ok:
            self.dirty = False
            self.last_error = None
            self._save_checkpoint()
        tm["total"] = round((time.perf_counter() - t_start) * 1000)
        now = time.time()
        if self.last_tick_t is not None:
            self.lines_per_sec = round(res.new_lines / max(now - self.last_tick_t, 1e-6), 1)
        self.last_tick_t = now
        self.ticks += 1
        self.last_tick = {"at": _iso(now), "new_lines": res.new_lines, "rows_added": res.rows_added,
                          "rows_dropped": res.rows_dropped, "rebuilt": res.rebuilt, "published": res.published,
                          "timing_ms": dict(tm)}
        self._write_status("running", r)
        return res

    def _rebuild_and_publish(self, res: TickResult, r: Any, read_at: float, first: bool) -> bool:
        tm = res.timing_ms
        force = bool(res.reset or first or self.dirty)
        rb = self.pipeline.rebuild(self.table, None if force else (lambda a: alert_signatures(a) != self.sigs))
        tm.update(rb.timings_ms)
        res.rebuilt = True
        if not rb.ok:
            res.error = self.last_error = rb.error + (" | " + " / ".join(rb.log_tail[-3:]) if rb.log_tail else "")
            self.dirty = True
            return False
        if rb.stopped_after_detect:
            return True
        sigs = alert_signatures(rb.alerts)
        cur_alerts = {a["alert_id"]: a for a in (_read_json(self.work / "alerts.json") or [])}
        affected = pub.affected_entities(self.alerts_by_id, cur_alerts, set(self.sigs or ()), set(sigs))
        diff = pub.diff_incidents(self.prev, self.work, None if (first or res.reset) else affected)
        t0 = time.perf_counter()
        try:
            pub.publish(self.work, self.run_dir)
        except OSError as e:
            res.error = self.last_error = f"publish: {type(e).__name__}: {e}"
            self.dirty = True
            tm["publish"] = round((time.perf_counter() - t0) * 1000)
            return False
        done = time.time()
        tm["publish"] = round((time.perf_counter() - t0) * 1000)
        res.published = True
        self.last_publish_at = _iso(done)
        new_alerts = [{"alert_id": aid, "rule_id": a.get("rule_id"), "incident_number": a.get("incident_number")}
                      for aid, a in cur_alerts.items() if aid not in self.prev_alert_ids]
        if not diff.empty or new_alerts:
            lines = {"first_line": r.lines[0][1], "last_line": r.lines[-1][1]} if r.lines else None
            info = self.table.info()
            timing = {k: tm.get(k, 0) for k in ("parse", "insert", "detect", "correlate", "chain", "reach", "score",
                                               "report", "bundle", "publish")}
            timing["total"] = round(sum(timing.values()))
            res.record = self.events.append(
                "publish", tick=self.ticks, new=diff.new, changed=diff.changed, removed=diff.removed,
                new_alerts=new_alerts[:MAX_LIST], affected_entities=affected[:MAX_LIST],
                counts={"incidents": len(diff.current), "alerts": len(cur_alerts), "rows": info["rows"],
                        "lines_total": self.lines_total},
                lines=lines, timing_ms=timing,
                latency_ms={"read_to_publish": round((done - read_at) * 1000) if r.lines else None})
        self.sigs = sigs
        self.alerts_by_id = cur_alerts
        self.prev = pub.published_state(diff.current)
        self.prev_alert_ids = set(cur_alerts)
        pub.atomic_write_text(self.run_dir / PUBLISHED, json.dumps(
            {"incidents": self.prev, "alerts": sorted(self.prev_alert_ids)}, ensure_ascii=False))
        return True

    def _save_checkpoint(self) -> None:
        old = self.table.oldest()
        ck = self.tailer.checkpoint(old[1] if old else None, old[0] if old else None)
        ck["saved_at"] = _iso(time.time())
        pub.atomic_write_text(self.run_dir / CHECKPOINT, json.dumps(ck, indent=1))

    # ── status ───────────────────────────────────────────────────────────────
    def status(self, state: str, r: Any = None) -> Dict[str, Any]:
        info = self.table.info()
        size = r.size if r is not None else (self.input.stat().st_size if self.input.exists() else 0)
        return {
            "state": state, "updated_at": _iso(time.time()), "source": self.input.name,
            "path": str(self.input.resolve()), "input_state": self.tailer.status,
            "offset": self.tailer.offset, "size": size, "lines_total": self.lines_total,
            "lines_per_sec": self.lines_per_sec, "last_line_ts": info["last_ts"],
            "pid": os.getpid(), "started_at": _iso(self.started_at), "interval_s": self.interval,
            "window_hours": self.window_s / 3600,
            "window": {"rows": info["rows"], "first_ts": info["first_ts"], "last_ts": info["last_ts"]},
            "rules": {"active": [x.id for x in self.rules], "skipped": self.skipped},
            "last_tick": self.last_tick, "last_publish_at": self.last_publish_at,
            "events_seq": self.events.seq, "resets": self.resets, "error": self.last_error,
        }

    def _write_status(self, state: str, r: Any = None) -> None:
        try:
            self.events.write_status(self.status(state, r))
        except OSError as e:
            self.last_error = f"status: {e}"

    # ── loop ─────────────────────────────────────────────────────────────────
    def run(self, stop: threading.Event, on_tick: Any = None) -> None:
        while not stop.is_set():
            t0 = time.perf_counter()
            res = self.tick()
            if on_tick:
                on_tick(res)
            stop.wait(max(0.0, self.interval - (time.perf_counter() - t0)))

    def close(self, state: str = "stopped") -> None:
        if self.closed:
            return
        self.closed = True
        if not self.dirty:
            self._save_checkpoint()
        self.events.append("stop", source=self.input.name, lines_total=self.lines_total)
        self._write_status(state)
        self.table.con.close()
