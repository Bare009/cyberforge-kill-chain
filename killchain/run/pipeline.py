"""Runs every stage of the pipeline as a subprocess and records what each one did.

The record (schema in docs/tasks/trackA/item3-plan.md) goes to <run>/pipeline.json and, under the
`pipeline` key, into the run_summary.json that bundle writes. Bundle rebuilds run_summary.json from
scratch, so the key is added after bundle and pipeline.json keeps a copy a later rebundle cannot drop.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

STAGES: List[str] = ["parse", "prepare", "detect", "correlate", "chain", "reach", "score", "report",
                     "enrich", "narrate", "bundle"]
REQUIRED = set(STAGES) - {"enrich", "narrate"}
RECORD_VERSION = 1
TAIL_LINES = 20


@dataclass
class Context:
    input: Path
    name: str
    data_dir: Path
    offline: bool = False
    no_llm: bool = False
    reuse_parsed: bool = False
    from_stage: Optional[str] = None
    workers: Optional[int] = None
    ti_cache: Optional[Path] = None

    @property
    def root(self) -> Path:
        return Path(__file__).resolve().parents[2]

    @property
    def parsed_dir(self) -> Path:
        return self.data_dir / "parsed" / self.name

    @property
    def run_dir(self) -> Path:
        return self.data_dir / "runs" / self.name


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def command_for(stage: str, ctx: Context) -> List[str]:
    py, P, R = sys.executable, str(ctx.parsed_dir), str(ctx.run_dir)
    if stage == "parse":
        cmd = [py, "-m", "killchain", "parse", str(ctx.input), "--out", P, "--overwrite"]
        return cmd + (["--workers", str(ctx.workers)] if ctx.workers else [])
    if stage == "prepare":
        return [py, "-m", "killchain", "db", "--prepare", "--parsed", P, "--run", R]
    if stage == "reach":
        return [py, "-m", "killchain", "reach", "--run", R, "--parsed", P]
    if stage in ("detect", "correlate", "chain", "score", "report"):
        return [py, "-m", "killchain", stage, "--run", R]
    if stage == "enrich":
        cmd = [py, "-m", "killchain.enrich", "--run", R] + (["--offline"] if ctx.offline else [])
        return cmd + (["--cache", str(ctx.ti_cache)] if ctx.ti_cache else [])
    if stage == "narrate":
        return [py, "-m", "killchain.agents", "narrate", "--run", R]
    if stage == "bundle":
        return [py, "-m", "killchain.bundle", "--run", R, "--parsed", P]
    raise ValueError(f"unknown stage {stage}")


NO_KEY = "no LLM key in .env (LLM_PRIMARY_API_KEY / LLM_FALLBACK_API_KEY); template reports kept"


def llm_gate(ctx: Context) -> Optional[str]:
    """Why the narrator is skipped, or None to run it."""
    if ctx.no_llm:
        return "--no-llm"
    if ctx.offline:
        return "--offline (the narrator needs the network)"
    from killchain.agents import settings as llm_settings

    if not llm_settings.llm_enabled():
        return "LLM off (LLM_ENABLED is not true in .env)"
    if not llm_settings.endpoints("large"):
        return NO_KEY
    return None


def run_stage(stage: str, cmd: List[str], ctx: Context) -> Dict[str, Any]:
    """Run one stage, stream its output as `[stage] line` and into <run>/logs/<stage>.log."""
    from killchain.parser.cli import MemoryMonitor

    logs = ctx.run_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    tail: deque = deque(maxlen=TAIL_LINES)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    monitor = MemoryMonitor()
    monitor.start()
    t0 = time.perf_counter()
    with open(logs / f"{stage}.log", "w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, cwd=str(ctx.root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                                encoding="utf-8", errors="replace")
        assert proc.stdout is not None
        for raw in proc.stdout:
            text = raw.rstrip("\r\n")
            log.write(text + "\n")
            tail.append(text)
            sys.stdout.write(f"[{stage}] {text}\n")
            sys.stdout.flush()
        code = proc.wait()
    wall = time.perf_counter() - t0
    peak = monitor.stop()
    return {"exit_code": code, "wall_secs": round(wall, 2),
            "peak_rss_mb": None if peak is None else round(peak / 2**20),
            "log": f"logs/{stage}.log", "tail": list(tail)}


def _numbers(d: Dict[str, Any], dicts: Tuple[str, ...] = ()) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if k in ("wall_secs", "peak_rss_mb") or isinstance(v, bool):
            continue
        if isinstance(v, (int, float)) or (k in dicts and isinstance(v, dict)):
            out[k] = v
    return out


def stage_counts(stage: str, ctx: Context) -> Dict[str, Any]:
    P, R = ctx.parsed_dir, ctx.run_dir
    if stage == "parse":
        st = _read(P / "_stats.json")
        if not isinstance(st, dict):
            return {}
        classes = st.get("lines_by_class") or {}
        junk = sum(int(j.get("bytes") or 0) for j in st.get("junk_ranges") or [])
        junk += int((st.get("junk_small") or {}).get("bytes") or 0)
        return {"bytes": st.get("bytes"), "lines": st.get("lines"),
                "rows": {s: v.get("rows", 0) for s, v in (st.get("streams") or {}).items()},
                "rejected_lines": sum(v for k, v in classes.items() if k.startswith("rejected:")),
                "junk_bytes": junk}
    if stage == "prepare":
        db = R / "events.duckdb"
        return {"mb": round(db.stat().st_size / 2**20)} if db.exists() else {}
    if stage == "enrich":
        doc = _read(R / "enrichment.json")
        if not isinstance(doc, dict):
            return {}
        s = doc.get("summary") or {}
        out = {k: s.get(k) for k in ("indicators", "lookups", "cache_hits", "failures")}
        return {**out, "offline": doc.get("offline"), "providers": doc.get("providers")}
    if stage == "narrate":
        doc = _read(R / "report.json")
        if not isinstance(doc, dict):
            return {}
        usage = doc.get("usage") or {}
        return {"reports": len(doc.get("incidents") or {}), "failures": len(doc.get("failures") or {}),
                "calls": usage.get("calls"), "tokens": usage.get("tokens")}
    st = _read(R / stage / "_stats.json")
    return _numbers(st, ("layers", "bands")) if isinstance(st, dict) else {}


def check_events(ctx: Context) -> Optional[str]:
    """After parse: the exit-3 message when the input has no events, else None."""
    st = _read(ctx.parsed_dir / "_stats.json") or {}
    rows = sum(int(v.get("rows") or 0) for v in (st.get("streams") or {}).values())
    if rows:
        return None
    if not st.get("bytes"):
        return f"run: no events in {ctx.input}: the file is empty (0 bytes)"
    classes = ", ".join(f"{k}={v}" for k, v in (st.get("lines_by_class") or {}).items())
    return (f"run: no events in {ctx.input}: none of its {st.get('lines', 0)} lines is a FortiGate or JSON event "
            f"({classes})")


def _same_input(st: Dict[str, Any], ctx: Context) -> Tuple[bool, str, Any]:
    inputs = st.get("inputs") or [{}]
    path, size = inputs[0].get("path") or "?", inputs[0].get("size")
    same = (os.path.normcase(str(Path(path).resolve())) == os.path.normcase(str(ctx.input.resolve()))
            and size == ctx.input.stat().st_size)
    return same, path, size


def check_reuse(ctx: Context) -> Optional[str]:
    if not ctx.reuse_parsed:
        return None
    st = _read(ctx.parsed_dir / "_stats.json")
    if not isinstance(st, dict):
        return None      # nothing to reuse: parse runs as usual (a note says so)
    same, path, size = _same_input(st, ctx)
    if same:
        return None
    return (f"run: --reuse-parsed: {ctx.parsed_dir} was parsed from {path} ({size} bytes), not {ctx.input}; "
            f"drop --reuse-parsed to parse again")


def check_from(ctx: Context) -> Optional[str]:
    if ctx.from_stage in (None, "parse"):
        return None
    if (ctx.parsed_dir / "_stats.json").exists():
        return None
    return f"run: --from {ctx.from_stage} needs an earlier parse of {ctx.name} in {ctx.parsed_dir}"


def notes_before(stage: str, ctx: Context, written: set) -> List[str]:
    file, by = {"score": ("enrichment.json", "enrich"), "bundle": ("report.json", "narrate")}.get(stage, (None, None))
    if file is None or by in written:
        return []
    p = ctx.run_dir / file
    if not p.exists():
        return []
    when = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return [f"{stage} read {file} from an earlier run ({when}); this run did not write it"]


def _atomic_json(path: Path, doc: Dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def merge_summary(run_dir: Path, record: Dict[str, Any]) -> Optional[str]:
    """Put the record under `pipeline` in run_summary.json, keeping every other key as bundle wrote it.
    Returns a warning (and writes nothing) when the existing file is not valid JSON."""
    path = run_dir / "run_summary.json"
    if path.exists():
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return f"{path} is not valid JSON ({exc}); left it alone, the record is in pipeline.json only"
        if not isinstance(summary, dict):
            return f"{path} is not a JSON object; left it alone, the record is in pipeline.json only"
    else:
        summary = {"run": record.get("name")}
    summary["pipeline"] = record
    _atomic_json(path, summary)
    return None


def write_record(run_dir: Path, record: Dict[str, Any]) -> None:
    _atomic_json(run_dir / "pipeline.json", record)


def _machine() -> Dict[str, Any]:
    try:
        import psutil

        ram = round(psutil.virtual_memory().total / 2**20)
    except ImportError:
        ram = None
    return {"cpus": os.cpu_count(), "ram_mb": ram, "python": platform.python_version()}


def _skipped(name: str, reason: str, counts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"name": name, "status": "skipped", "reason": reason, "exit_code": None, "wall_secs": None,
            "peak_rss_mb": None, "counts": counts or {}, "command": None, "log": None, "tail": None}


def run_pipeline(ctx: Context) -> Tuple[int, Dict[str, Any]]:
    """Run the stages in order. Returns (exit code, record). The caller has checked the input and name.
    Exit codes: 0 ok, 1 a required stage failed, 2 a usage error (nothing written), 3 no events."""
    ctx.input = ctx.input.resolve()
    ctx.data_dir = ctx.data_dir.resolve()
    record: Dict[str, Any] = {
        "version": RECORD_VERSION, "name": ctx.name,
        "input": {"path": str(ctx.input), "bytes": ctx.input.stat().st_size},
        "parsed_dir": str(ctx.parsed_dir), "run_dir": str(ctx.run_dir),
        "options": {"offline": ctx.offline, "no_llm": ctx.no_llm, "reuse_parsed": ctx.reuse_parsed,
                    "from": ctx.from_stage, "workers": ctx.workers},
        "machine": _machine(), "started_at": _now(), "finished_at": None, "status": None, "exit_code": None,
        "wall_secs": None, "peak_rss_mb": None, "stages": [], "warnings": [], "notes": [], "error": None,
    }
    for check in (check_from, check_reuse):
        msg = check(ctx)
        if msg:
            record.update(status="usage_error", exit_code=2, error=msg)
            return 2, record

    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    stages: List[Dict[str, Any]] = record["stages"]
    warnings: List[str] = record["warnings"]
    notes: List[str] = record["notes"]
    written: set = set()
    stop: Optional[str] = None          # reason every remaining stage is skipped
    code = 0
    start = STAGES.index(ctx.from_stage) if ctx.from_stage else 0
    parse_reused = False

    for i, stage in enumerate(STAGES):
        if stop:
            stages.append(_skipped(stage, stop))
            continue
        if i < start:
            stages.append(_skipped(stage, f"--from {ctx.from_stage}"))
            continue
        if stage == "parse" and ctx.reuse_parsed:
            if (ctx.parsed_dir / "_stats.json").exists():
                parse_reused = True
                stages.append(_skipped(stage, "--reuse-parsed", stage_counts(stage, ctx)))
            else:
                notes.append(f"--reuse-parsed: no earlier parse in {ctx.parsed_dir}; parsing")
        if stage == "prepare" and parse_reused:
            db, st = ctx.run_dir / "events.duckdb", ctx.parsed_dir / "_stats.json"
            if db.exists() and db.stat().st_mtime > st.stat().st_mtime:
                stages.append(_skipped(stage, "--reuse-parsed", stage_counts(stage, ctx)))
                continue
        if stage == "narrate":
            reason = llm_gate(ctx)
            if reason:
                stages.append(_skipped(stage, reason))
                if reason == NO_KEY:
                    warnings.append(f"narrate: {reason}")
                    print(f"run: narrate skipped: {reason}", file=sys.stderr)
                continue
        if not (stage == "parse" and parse_reused):
            notes.extend(notes_before(stage, ctx, written))
            cmd = command_for(stage, ctx)
            res = run_stage(stage, cmd, ctx)
            ok = res["exit_code"] == 0
            entry = {"name": stage, "status": "ok" if ok else "failed",
                     "reason": None if ok else f"exit code {res['exit_code']}",
                     "exit_code": res["exit_code"], "wall_secs": res["wall_secs"], "peak_rss_mb": res["peak_rss_mb"],
                     "counts": stage_counts(stage, ctx) if ok else {}, "command": cmd, "log": res["log"],
                     "tail": None if ok else res["tail"]}
            stages.append(entry)
            if ok:
                written.add(stage)
            if ok and stage == "enrich" and (entry["counts"].get("failures") or 0) > 0:
                doc = _read(ctx.run_dir / "enrichment.json") or {}
                errs = (doc.get("summary") or {}).get("errors") or ["no error text"]
                entry["status"] = "degraded"
                warnings.append(f"enrich: {entry['counts']['failures']} of {entry['counts'].get('lookups')} lookups "
                                f"failed ({errs[0]}); threat intel is partial")
            if not ok:
                if stage in REQUIRED:
                    record["error"] = (f"run: stage {stage} failed (exit {res['exit_code']}); log {ctx.run_dir / res['log']}"
                                       + "\n  " + "\n  ".join(res["tail"]))
                    stop = f"earlier stage {stage} failed"
                    code = 1
                    continue
                warnings.append(f"{stage} failed (exit {res['exit_code']}); the run goes on without it, "
                                f"see {ctx.run_dir / res['log']}")
                continue
        if stage == "parse":
            msg = check_events(ctx)
            if msg:
                record["error"] = msg
                stop = "no events in the input"
                code = 3

    peaks = [s["peak_rss_mb"] for s in stages if s["peak_rss_mb"] is not None]
    record.update(finished_at=_now(), exit_code=code, wall_secs=round(time.perf_counter() - t0, 2),
                  peak_rss_mb=max(peaks) if peaks else None)
    record["status"] = {1: "failed", 3: "no_events"}.get(code, "ok")
    warn = merge_summary(ctx.run_dir, _finish(record, warnings))
    if warn:
        warnings.append(warn)
        _finish(record, warnings)
    write_record(ctx.run_dir, record)
    return code, record


def _finish(record: Dict[str, Any], warnings: List[str]) -> Dict[str, Any]:
    if record["exit_code"] == 0:
        record["status"] = "ok_with_warnings" if warnings else "ok"
    return record
