"""Replay a saved log slice into a file that live mode tails.

make_slice: cut the lines of one attacker's rule-layer alerts (each alert is one step) plus a sample of
background lines out of a batch run's raw log, in original line order, with a sidecar <slice>.meta.json
listing each step's slice line range.

play: append the slice to a target file at `rate` lines per second, pausing `step_pause` seconds before
each step after the first, so an incident appears and then grows one step at a time.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

PathLike = Union[str, Path]


def meta_path(slice_path: PathLike) -> Path:
    p = Path(slice_path)
    return p.with_name(p.name + ".meta.json")


def make_slice(raw: PathLike, run: PathLike, ip: str, out: PathLike, background: int = 2000,
               seed: int = 42) -> Dict[str, Any]:
    import polars as pl

    from .. import db

    raw, run, out = Path(raw), Path(run), Path(out)
    alerts = json.loads((run / "alerts.json").read_text(encoding="utf-8"))
    mine = [a for a in alerts if ip in (a.get("src_ip"), a.get("dst_ip"))]
    steps = sorted((a for a in mine if a.get("layer") == "rule"), key=lambda a: (a["ts_start"], a["rule_id"]))
    if not steps:
        raise ValueError(f"no rule-layer alert names {ip} in {run / 'alerts.json'}")
    context = [a for a in mine if a.get("layer") != "rule"]
    ev = pl.read_parquet(run / "alert_evidence.parquet", columns=["alert_id", "source", "line", "byte_offset"])
    ev = ev.filter(pl.col("source") == raw.name)
    step_of: Dict[int, int] = {}
    offsets: Dict[int, int] = {}
    for k, a in enumerate(steps, 1):
        for line, off in ev.filter(pl.col("alert_id") == a["alert_id"]).select("line", "byte_offset").iter_rows():
            if line not in step_of:
                step_of[line], offsets[line] = k, off
    lo, hi = min(step_of), max(step_of)
    ctx_ids = [a["alert_id"] for a in context]
    for line, off in ev.filter(pl.col("alert_id").is_in(ctx_ids)).select("line", "byte_offset").iter_rows():
        if line not in offsets and lo <= line <= hi:
            offsets[line] = off
    con = db.connect(run_dir=run)
    q = ip.replace("'", "''")
    # the sample is taken from the filtered rows (a sample on `events` itself would be drawn before the WHERE)
    bg = con.execute(f"SELECT line, byte_offset FROM (SELECT line, byte_offset FROM events WHERE line BETWEEN {lo} "
                     f"AND {hi} AND coalesce(src_ip, '') <> '{q}' AND coalesce(dst_ip, '') <> '{q}') t "
                     f"USING SAMPLE reservoir({int(background)} ROWS) REPEATABLE ({int(seed)})").fetchall()
    con.close()
    n_bg = 0
    for line, off in bg:
        if line not in offsets:
            offsets[line] = off
            n_bg += 1
    out.parent.mkdir(parents=True, exist_ok=True)
    first: Dict[int, int] = {}
    last: Dict[int, int] = {}
    count: Dict[int, int] = {}
    with open(raw, "rb") as src, open(out, "wb") as dst:
        for i, line in enumerate(sorted(offsets), 1):
            src.seek(offsets[line])
            text = src.readline()
            if not text.endswith(b"\n"):
                text += b"\n"
            dst.write(text)
            k = step_of.get(line)
            if k:
                first.setdefault(k, i)
                last[k] = i
                count[k] = count.get(k, 0) + 1
    meta = {"source": raw.name, "run": run.name, "ip": ip, "lines": len(offsets), "background": n_bg,
            "context_lines": len(offsets) - n_bg - len(step_of),
            "original_lines": [lo, hi],
            "steps": [{"n": k, "rule_id": a["rule_id"], "alert_id": a["alert_id"], "first": first.get(k),
                       "last": last.get(k), "count": count.get(k, 0)} for k, a in enumerate(steps, 1)]}
    meta_path(out).write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return meta


def load_meta(slice_path: PathLike) -> Optional[Dict[str, Any]]:
    p = meta_path(slice_path)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def play(slice_path: PathLike, target: PathLike, rate: float = 500, step_pause: float = 6.0, truncate: bool = True,
         on_step: Optional[Callable[[int], Any]] = None, stop: Optional[threading.Event] = None,
         meta: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Append the slice to target. Returns marks [{n, rule_id, first_written_at, last_written_at}] (epoch s,
    taken right after the flush that wrote the step's first and last line). on_step(k) is called after step k
    is written, before the pause in front of step k+1."""
    lines = Path(slice_path).read_bytes().splitlines(keepends=True)
    meta = meta if meta is not None else load_meta(slice_path)
    steps = sorted((meta or {}).get("steps") or [], key=lambda s: s["first"])
    starts = {s["first"]: s for s in steps[1:]}          # a pause before each step after the first
    firsts = {s["first"]: s for s in steps}
    lasts = {s["last"]: s for s in steps}
    marks = {s["n"]: {"n": s["n"], "rule_id": s["rule_id"], "lines": s.get("count"), "first_written_at": None,
                      "last_written_at": None} for s in steps}
    batch = max(1, int(rate // 10))
    stop = stop or threading.Event()
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    prev_step: Optional[int] = None
    with open(target, "wb" if truncate else "ab") as f:
        pending: List[Dict[str, Any]] = []         # marks to stamp at the next flush

        def flush() -> None:
            f.flush()
            t = time.time()
            for p in pending:
                marks[p["n"]][p["key"]] = t
            pending.clear()

        i = 0
        while i < len(lines) and not stop.is_set():
            n = i + 1
            if n in starts:
                flush()
                if on_step is not None and prev_step is not None:
                    on_step(prev_step)
                if step_pause:
                    stop.wait(step_pause)
            end = min(len(lines), i + batch)
            for b in sorted(starts):                    # never run a batch across the start of a step
                if n < b <= end:
                    end = b - 1
                    break
            for j in range(i, end):
                f.write(lines[j])
                m = j + 1
                if m in firsts:
                    pending.append({"n": firsts[m]["n"], "key": "first_written_at"})
                    prev_step = firsts[m]["n"]
                if m in lasts:
                    pending.append({"n": lasts[m]["n"], "key": "last_written_at"})
            flush()
            i = end
            if i < len(lines):
                stop.wait(0.1)
        flush()
    if on_step is not None and prev_step is not None:
        on_step(prev_step)
    return [marks[k] for k in sorted(marks)]
