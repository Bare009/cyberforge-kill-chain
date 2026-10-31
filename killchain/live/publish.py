"""Publish a staged rebuild into the run folder, work out what changed, and write live/ records.

Publish order (the API reloads when its watched files change, so those go last, index.json last of all):
  1. files the API does not watch: the parquet intermediates, chains.json, reach.json, score.json and the
     <stage>/_stats.json files;
  2. the incidents/ folder, swapped as a whole (as graph/incident_files.write does);
  3. the watched files: unexplained.json, ti.json, alerts.json, run_summary.json, index.json.
Every file is copied to <name>.tmp and renamed into place. On Windows a rename fails while another
process has the file open (the API reading it), so a PermissionError is retried 20 times, 50 ms apart.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from . import feed

QUIET = ("alerts.parquet", "alert_evidence.parquet", "incidents.parquet", "incident_alerts.parquet",
         "unexplained.parquet", "chains.json", "incident_lines.parquet", "access_graph.parquet",
         "access_hosts.parquet", "reach.json", "score.json")
STAGE_STATS = ("detect", "correlate", "chain", "reach", "score", "report", "bundle")
WATCHED = ("unexplained.json", "ti.json", "alerts.json", "run_summary.json", "index.json")
RETRIES, RETRY_WAIT = 20, 0.05
MAX_LIST = 50
ENTITY_KEYS = ("src_ip", "dst_ip", "user", "host", "domain")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _retry(fn: Callable[[], Any]) -> Any:
    for i in range(RETRIES):
        try:
            return fn()
        except PermissionError:
            if i == RETRIES - 1:
                raise
            time.sleep(RETRY_WAIT)


def replace(src: Path, dst: Path) -> None:
    _retry(lambda: os.replace(src, dst))


def atomic_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".tmp")
    shutil.copyfile(src, tmp)
    replace(tmp, dst)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    replace(tmp, path)


def _swap_dir(src: Path, run: Path, name: str) -> None:
    new, cur, old = run / (name + ".tmp"), run / name, run / (name + ".old")
    for p in (new, old):
        if p.exists():
            shutil.rmtree(p)
    shutil.copytree(src, new)
    if cur.exists():
        replace(cur, old)
    replace(new, cur)
    if old.exists():
        shutil.rmtree(old, ignore_errors=True)


def publish(work: Path, run: Path) -> List[str]:
    """Copy a staged rebuild into the run folder in the safe order; returns the files written."""
    work, run = Path(work), Path(run)
    done: List[str] = []
    for name in QUIET + tuple(f"{s}/_stats.json" for s in STAGE_STATS):
        if (work / name).exists():
            atomic_copy(work / name, run / name)
            done.append(name)
    _swap_dir(work / "incidents", run, "incidents")
    done.append("incidents/")
    for name in WATCHED:
        if (work / name).exists():
            atomic_copy(work / name, run / name)
            done.append(name)
        elif name == "ti.json" and (run / name).exists():
            # live never runs enrich: an earlier ti.json would point at other incident numbers
            _retry(lambda: (run / name).unlink())
    return done


# ── what changed ─────────────────────────────────────────────────────────────

@dataclass
class Diff:
    new: List[Dict[str, Any]] = field(default_factory=list)
    changed: List[Dict[str, Any]] = field(default_factory=list)
    removed: List[Dict[str, Any]] = field(default_factory=list)
    current: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not (self.new or self.changed or self.removed)


def _summary(inc: Dict[str, Any]) -> Dict[str, Any]:
    return {"incident_id": inc["incident_id"], "incident_number": inc["incident_number"], "title": inc["title"],
            "risk_score": inc["risk_score"], "risk_band": inc["risk_band"], "severity": inc["severity"],
            "steps": len(inc.get("chain") or []), "rule_ids": [s.get("rule_id") for s in inc.get("chain") or []],
            "tactics": list(inc.get("tactics") or []), "ips": list((inc.get("entities") or {}).get("ips") or [])[:10],
            "grew_from": []}


def _entities(inc: Dict[str, Any]) -> Set[str]:
    e = inc.get("entities") or {}
    return {str(v) for k in ("ips", "hosts", "users", "domains") for v in e.get(k) or []}


def read_incidents(work: Path) -> Dict[str, Dict[str, Any]]:
    """incident_id -> {sha, alerts, number, entities, summary} for every incidents/<n>.json in work."""
    import polars as pl

    members: Dict[str, List[str]] = {}
    p = work / "incident_alerts.parquet"
    if p.exists():
        for iid, aid in pl.read_parquet(p, columns=["incident_id", "alert_id"]).iter_rows():
            members.setdefault(iid, []).append(aid)
    out: Dict[str, Dict[str, Any]] = {}
    for f in sorted((work / "incidents").glob("*.json")):
        raw = f.read_bytes()
        inc = json.loads(raw)
        alerts = members.get(inc["incident_id"]) or [
            a["alert_id"] for s in inc.get("chain") or [] for a in [s, *(s.get("supporting") or [])] if a.get("alert_id")]
        out[inc["incident_id"]] = {"sha": hashlib.sha1(raw).hexdigest(), "alerts": sorted(set(alerts)),
                                   "number": inc["incident_number"], "entities": sorted(_entities(inc)),
                                   "summary": _summary(inc)}
    return out


def diff_incidents(prev: Dict[str, Dict[str, Any]], work: Path, affected: Optional[Iterable[str]] = None) -> Diff:
    """New, changed and removed incidents against the last publish.

    new:     incident_id not published before. An incident gets a new id whenever it gains an alert
             (incident_id = hash of its alert ids), so a new incident whose alert set contains a removed
             one's lists it in grew_from, and the removed one says replaced_by.
    changed: same id, different file bytes, and it touches an affected entity (affected=None: any).
    """
    cur = read_incidents(Path(work))
    aff = None if affected is None else set(affected)
    d = Diff(current=cur)
    gone = {iid: v for iid, v in prev.items() if iid not in cur}
    replaced: Dict[str, str] = {}
    for iid, v in sorted(cur.items(), key=lambda kv: kv[1]["number"]):
        s = dict(v["summary"])
        if iid not in prev:
            mine = set(v["alerts"])
            s["grew_from"] = sorted(g for g, gv in gone.items() if gv["alerts"] and set(gv["alerts"]) <= mine)
            for g in s["grew_from"]:
                replaced.setdefault(g, iid)
            d.new.append(s)
        elif prev[iid]["sha"] != v["sha"] and (aff is None or aff & set(v["entities"])):
            d.changed.append(s)
    d.removed = [{"incident_id": g, "replaced_by": replaced.get(g)} for g in gone]
    return d


def published_state(cur: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {iid: {k: v[k] for k in ("sha", "alerts", "number", "entities", "summary")} for iid, v in cur.items()}


def affected_entities(prev_alerts: Dict[str, Dict[str, Any]], cur_alerts: Dict[str, Dict[str, Any]],
                      prev_sigs: Set[Any], cur_sigs: Set[Any]) -> List[str]:
    """Entities of alerts that are new, changed or gone since the last tick."""
    moved = {s[0] for s in (cur_sigs ^ prev_sigs)}
    out: Set[str] = set()
    for aid in moved:
        a = cur_alerts.get(aid) or prev_alerts.get(aid) or {}
        out.update(str(a[k]) for k in ENTITY_KEYS if a.get(k))
    return sorted(out)


# ── live/ records ────────────────────────────────────────────────────────────

class EventLog:
    """<run>/live/events.jsonl (append-only) and <run>/live/status.json (rewritten by rename)."""

    def __init__(self, run: Path) -> None:
        self.run = Path(run)
        self.path = self.run / feed.EVENTS_FILE
        self.status_path = self.run / feed.STATUS_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        last = feed.read_events(self.run)
        self.seq = last[-1]["seq"] if last else 0
        self._trim_partial()

    def _trim_partial(self) -> None:
        """A crash mid-write leaves a last line without a newline; drop it so the next record starts clean."""
        if not self.path.exists():
            return
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            with open(self.path, "r+b") as f:
                f.truncate(data.rfind(b"\n") + 1)

    def append(self, kind: str, **fields: Any) -> Dict[str, Any]:
        self.seq += 1
        rec = {"seq": self.seq, "kind": kind, "at": now_iso(), "at_epoch": round(time.time(), 3), **fields}
        line = json.dumps(rec, ensure_ascii=False, default=str) + "\n"
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
        return rec

    def write_status(self, status: Dict[str, Any]) -> None:
        atomic_write_text(self.status_path, json.dumps(status, indent=1, ensure_ascii=False, default=str))
