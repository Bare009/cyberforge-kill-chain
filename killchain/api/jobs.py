"""Analyse a new log from the UI: upload it, run the whole pipeline on it, then serve the result.

Uploads go to the raw-log folder the API reads evidence from (`--raw-dir`, KILLCHAIN_RAW_DIR,
else data/raw), so the Evidence tab can show the new run's raw lines. A file of many GB is sent
in chunks: each chunk is appended to <raw>/.incoming/<name>.part, and the last one moves the
file to <raw>/<name>. A chunk must start where the server's copy ends, so an interrupted upload
resumes from GET /uploads/{name}.

A job runs `python -m killchain run` on one file of the raw folder in a subprocess (one job at
a time) and reads its output for progress: the `run: stage <name> ...` lines and the parser's
percentage lines. When it succeeds the API switches to the new run.

GET  /uploads                    logs in the raw folder, partial uploads, free disk, defaults
GET  /uploads/{name}             bytes the server has of one upload
POST /uploads/{name}             one chunk (raw body) at ?offset=..&total=..
POST /uploads/{name}/discard     drop a partial upload
POST /jobs                       run the pipeline on a log in the raw folder
GET  /jobs/current               the running or last job, with per-stage progress
POST /jobs/current/cancel        stop it
GET  /runs                       analysed runs
POST /runs/select                serve another run

Set KILLCHAIN_UPLOADS=0 to turn uploads and jobs off (the API has no login).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from killchain.run.pipeline import STAGES

from .bundle import EMPTY_RUN, REPO_ROOT, empty_bundle

log = logging.getLogger(__name__)
router = APIRouter()

FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
INCOMING = ".incoming"
PART = ".part"
MAX_CHUNK = 256 * 2**20            # bytes per POST /uploads/{name}
# free space needed before an upload starts, as a share of the file: the copy itself plus the
# parsed Parquet and events.duckdb the pipeline writes (about 0.35 of the log on the test files)
PROCESSING_SHARE = 0.5
SPARE_BYTES = 2 * 2**30
TAIL = 40
STAGE_RE = re.compile(r"^run: stage (\w+) (started|ok|failed|skipped|degraded)(?: (\S+))?$")
PCT_RE = re.compile(r"^\[parse\] \[[^\]]+\]\s+([\d.]+)%\s+([\d.]+) GiB\s+([\d.]+) s")
COUNT_RE = re.compile(r"^\[parse\] \[[^\]]+\] counting lines")
PARSED_RE = re.compile(r"^\[parse\] parsed ")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def uploads_enabled() -> bool:
    return os.environ.get("KILLCHAIN_UPLOADS", "1").strip().lower() not in ("0", "false", "no", "off")


def _need_enabled() -> None:
    if not uploads_enabled():
        raise HTTPException(status_code=403, detail="uploads and jobs are turned off on this server (KILLCHAIN_UPLOADS=0)")


def _check_file_name(name: str) -> str:
    if not FILE_RE.match(name) or name.endswith(PART):
        raise HTTPException(status_code=400, detail=f"bad file name {name!r}: use letters, digits, '.', '_' and '-' "
                                                    "(up to 128 characters, not starting with a dot)")
    return name


def _read_json(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def default_workers() -> int:
    """Parser processes for a job: PARSE_WORKERS, else up to 8. On the 16-core, 16 GB test machine a
    freshly uploaded copy of the 6.1 GiB firex-10G log parsed in 158 s with 8 workers (parse peak
    3.2 GB) and 229 s with 4 (1.7 GB); the run's peak, 6 GB, is DuckDB in the prepare stage either way."""
    fallback = max(1, min(8, (os.cpu_count() or 2) - 2))
    try:
        return max(1, int(os.environ.get("PARSE_WORKERS") or fallback))
    except ValueError:
        return fallback


# ── uploads ──────────────────────────────────────────────────────────────────

class Uploads:
    """Chunked uploads into one raw-log folder."""

    def __init__(self, raw_dir: Path):
        self.raw_dir = Path(raw_dir).resolve()
        self.incoming = self.raw_dir / INCOMING
        self._locks: Dict[str, asyncio.Lock] = {}

    def final(self, name: str) -> Path:
        return self.raw_dir / name

    def part(self, name: str) -> Path:
        return self.incoming / (name + PART)

    def status(self, name: str) -> Dict[str, Any]:
        f, p = self.final(name), self.part(name)
        if f.is_file():
            size = f.stat().st_size
            return {"name": name, "received": size, "size": size, "complete": True}
        received = p.stat().st_size if p.is_file() else 0
        return {"name": name, "received": received, "size": None, "complete": False}

    def check_space(self, total: int, received: int, data_dir: Path) -> None:
        """Refuse an upload that would fill the disk before the pipeline has room to run."""
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        need_raw = total - received + SPARE_BYTES
        need_data = int(total * PROCESSING_SHARE)
        same = os.stat(self.raw_dir).st_dev == os.stat(data_dir).st_dev
        free_raw = shutil.disk_usage(self.raw_dir).free
        if same:
            if free_raw < need_raw + need_data:
                raise HTTPException(status_code=507, detail=(
                    f"not enough disk space: the upload and its processing need about "
                    f"{(need_raw + need_data) / 2**30:.1f} GiB, {free_raw / 2**30:.1f} GiB is free on {self.raw_dir}"))
            return
        free_data = shutil.disk_usage(data_dir).free
        if free_raw < need_raw:
            raise HTTPException(status_code=507, detail=f"not enough disk space for the upload: need "
                                                        f"{need_raw / 2**30:.1f} GiB, {free_raw / 2**30:.1f} GiB free on {self.raw_dir}")
        if free_data < need_data:
            raise HTTPException(status_code=507, detail=f"not enough disk space to process the log: need about "
                                                        f"{need_data / 2**30:.1f} GiB, {free_data / 2**30:.1f} GiB free on {data_dir}")

    async def write(self, name: str, offset: int, total: int, request: Request, data_dir: Path) -> Dict[str, Any]:
        lock = self._locks.setdefault(name, asyncio.Lock())
        async with lock:
            f = self.final(name)
            if f.is_file():
                size = f.stat().st_size
                if size == total:            # already here (an earlier upload of the same file)
                    return {**self.status(name), "already": True}
                raise HTTPException(status_code=409, detail=(
                    f"a different file named {name} is already on the server ({size:,} bytes, yours is "
                    f"{total:,}); rename yours before uploading"))
            p = self.part(name)
            have = p.stat().st_size if p.is_file() else 0
            if offset != have:
                return JSONResponse(status_code=409, content={
                    "detail": f"the server has {have:,} bytes of {name}; send the chunk at that offset",
                    "received": have})
            if offset == 0:
                self.check_space(total, 0, data_dir)
            length = request.headers.get("content-length")
            if length is not None and (not length.isdigit() or int(length) > MAX_CHUNK):
                raise HTTPException(status_code=413, detail=f"chunks are at most {MAX_CHUNK // 2**20} MB")
            if length is not None and offset + int(length) > total:
                raise HTTPException(status_code=400, detail="the chunk goes past the file's total size")
            self.incoming.mkdir(parents=True, exist_ok=True)
            written = 0
            ok = False
            fh = open(p, "ab")
            try:
                async for piece in request.stream():
                    if not piece:
                        continue
                    written += len(piece)
                    if written > MAX_CHUNK or offset + written > total:
                        raise HTTPException(status_code=400, detail="the chunk goes past the file's total size")
                    fh.write(piece)
                ok = True
            finally:
                if not ok:                    # keep the file at a chunk boundary so a retry can resume
                    fh.truncate(offset)
                fh.close()
            received = offset + written
            if received == total:
                os.replace(p, f)
                log.info("upload: %s complete (%d bytes)", name, total)
                return self.status(name)
            return {"name": name, "received": received, "size": None, "complete": False}

    def discard(self, name: str) -> Dict[str, Any]:
        p = self.part(name)
        if p.is_file():
            p.unlink()
        return self.status(name)

    def listing(self, data_dir: Path) -> Dict[str, Any]:
        runs_by_input: Dict[str, List[str]] = {}
        for r in sorted((data_dir / "runs").glob("*/pipeline.json")):
            inp = ((_read_json(r) or {}).get("input") or {}).get("path")
            if inp:
                runs_by_input.setdefault(Path(inp).name, []).append(r.parent.name)
        files = []
        if self.raw_dir.is_dir():
            for f in sorted(self.raw_dir.iterdir()):
                if not f.is_file() or f.name.startswith(".") or f.name.endswith(".json"):
                    continue
                st = f.stat()
                if st.st_size == 0:
                    continue
                files.append({"name": f.name, "size": st.st_size,
                              "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              "runs": runs_by_input.get(f.name, [])})
        partial = []
        if self.incoming.is_dir():
            for p in sorted(self.incoming.glob("*" + PART)):
                partial.append({"name": p.name[: -len(PART)], "received": p.stat().st_size})
        usage = shutil.disk_usage(self.raw_dir) if self.raw_dir.is_dir() else None
        return {"enabled": uploads_enabled(), "raw_dir": str(self.raw_dir), "files": files, "partial": partial,
                "free_bytes": usage.free if usage else None, "max_chunk": MAX_CHUNK,
                "defaults": {"workers": default_workers(), "cpus": os.cpu_count()}}


# ── jobs ─────────────────────────────────────────────────────────────────────

class Job:
    """One `python -m killchain run` subprocess and what its output says about progress."""

    def __init__(self, file: Path, run: str, data_dir: Path, *, offline: bool, no_llm: bool, workers: int,
                 upload_secs: Optional[float], switch: bool, on_done: Callable[["Job", str], None],
                 on_saved: Callable[["Job"], None]):
        self.id = uuid.uuid4().hex[:12]
        self.file, self.run, self.data_dir = file, run, data_dir
        self.options = {"offline": offline, "no_llm": no_llm, "workers": workers, "switch": switch}
        self.upload_secs = upload_secs
        self.file_bytes = file.stat().st_size
        self.state = "running"
        self.started_at, self.finished_at = now_iso(), None
        self._t0, self._t1 = time.time(), None
        self.stages: Dict[str, Dict[str, Any]] = {s: {"name": s, "status": "pending", "wall_secs": None}
                                                  for s in STAGES}
        self._started: Dict[str, float] = {}
        self.current: Optional[str] = None
        self.parse: Dict[str, Any] = {"phase": None, "pct": 0.0, "gib": 0.0, "secs": None}
        self.tail: Deque[str] = deque(maxlen=TAIL)
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.switched = False
        self.cancelled = False
        self.on_done, self.on_saved = on_done, on_saved
        self._lock = threading.Lock()
        cmd = [sys.executable, "-m", "killchain", "run", "--input", str(file), "--name", run,
               "--data-dir", str(data_dir), "--workers", str(workers)]
        if offline:
            cmd.append("--offline")
        if no_llm:
            cmd.append("--no-llm")
        self.command = cmd
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        self.proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env=env, encoding="utf-8", errors="replace")
        self._thread = threading.Thread(target=self._read, name=f"job-{self.id}", daemon=True)
        self._thread.start()

    # -- output
    def feed(self, line: str) -> None:
        """Take one line of the run's output (the reader thread calls this; tests too)."""
        text = line.rstrip("\r\n")
        with self._lock:
            m = STAGE_RE.match(text)
            if m:
                stage, what, secs = m.group(1), m.group(2), m.group(3)
                s = self.stages.get(stage)
                if s is None:
                    return
                if what == "started":
                    s["status"] = "running"
                    self._started[stage] = time.time()
                    self.current = stage
                else:
                    s["status"] = what
                    s["wall_secs"] = float(secs) if secs and secs != "-" else None
                    if self.current == stage:
                        self.current = None
                return
            self.tail.append(text)
            m = PCT_RE.match(text)
            if m:
                self.parse.update(phase="parsing", pct=float(m.group(1)), gib=float(m.group(2)), secs=float(m.group(3)))
            elif COUNT_RE.match(text):
                self.parse["phase"] = "counting"
            elif PARSED_RE.match(text):
                self.parse.update(phase="done", pct=100.0)

    def _read(self) -> None:
        assert self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                self.feed(line)
        finally:
            code = self.proc.wait()
            self._finish(code)

    def _finish(self, code: int) -> None:
        run_dir = self.data_dir / "runs" / self.run
        record = _read_json(run_dir / "pipeline.json") if code != 2 else None
        summary = _read_json(run_dir / "run_summary.json") or {}
        with self._lock:
            self._t1 = time.time()
            self.finished_at = now_iso()
            self.current = None
            if isinstance(record, dict) and record.get("name") == self.run and record.get("started_at", "") >= self.started_at[:19]:
                for s in record.get("stages") or []:
                    if s.get("name") in self.stages:
                        self.stages[s["name"]].update(status=s.get("status"), wall_secs=s.get("wall_secs"),
                                                      reason=s.get("reason"))
                counts = summary.get("counts") or {}
                dq = summary.get("data_quality") or {}
                self.result = {
                    "status": record.get("status"), "exit_code": record.get("exit_code"),
                    "wall_secs": record.get("wall_secs"), "peak_rss_mb": record.get("peak_rss_mb"),
                    "incidents": counts.get("incidents"), "critical_incidents": counts.get("critical_incidents"),
                    "alerts": counts.get("alerts"), "unexplained": counts.get("unexplained"),
                    "events": dq.get("events"), "lines": dq.get("lines"),
                    "warnings": record.get("warnings") or [], "error": record.get("error"),
                }
            else:
                record = None
            if self.cancelled:
                final = "cancelled"
            elif record is not None:
                final = record.get("status") or ("ok" if code == 0 else "failed")
            else:
                final = "failed"
                self.error = f"python -m killchain run exited with code {code}: " + " | ".join(list(self.tail)[-5:])
            for s in self.stages.values():
                if s["status"] in ("pending", "running"):
                    s["status"] = "cancelled" if self.cancelled else ("failed" if s["status"] == "running" else "skipped")
            self.current = "loading" if final in ("ok", "ok_with_warnings") and self.options["switch"] else None
        # the state stays "running" until the API serves the new run, so the UI switches with it
        try:
            self.on_done(self, final)
        except Exception:  # noqa: BLE001 - a failed switch is reported on the job, the job itself is done
            log.exception("job %s: after-run step failed", self.id)
        with self._lock:
            self.current = None
            self.state = final
        try:
            self.on_saved(self)
        except Exception:  # noqa: BLE001
            log.exception("job %s: could not save the job record", self.id)

    # -- control
    def cancel(self) -> None:
        if self.state != "running":
            return
        self.cancelled = True
        try:
            import psutil

            parent = psutil.Process(self.proc.pid)
            procs = parent.children(recursive=True) + [parent]
            for p in procs:
                try:
                    p.terminate()
                except psutil.NoSuchProcess:
                    pass
            _, alive = psutil.wait_procs(procs, timeout=5)
            for p in alive:
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    pass
        except Exception:  # noqa: BLE001 - psutil missing or the process is gone: fall back to the parent
            self.proc.kill()

    @property
    def running(self) -> bool:
        return self.state == "running"

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            now = self._t1 or time.time()
            stages = []
            for name in STAGES:
                s = dict(self.stages[name])
                if s["status"] == "running" and name in self._started:
                    s["wall_secs"] = round(now - self._started[name], 1)
                stages.append(s)
            return {
                "id": self.id, "state": self.state, "file": self.file.name, "file_bytes": self.file_bytes,
                "run": self.run, "options": self.options, "started_at": self.started_at,
                "finished_at": self.finished_at, "elapsed_secs": round(now - self._t0, 1),
                "upload_secs": self.upload_secs, "current": self.current, "stages": stages,
                "parse": dict(self.parse), "tail": list(self.tail)[-15:], "result": self.result,
                "switched": self.switched, "error": self.error,
            }


class Jobs:
    """At most one running job; the last one is kept (and saved) for the UI."""

    def __init__(self, data_dir: Path, activate: Callable[[Path], Any]):
        self.data_dir = Path(data_dir)
        self.activate = activate
        self.job: Optional[Job] = None
        self.saved: Optional[Dict[str, Any]] = _read_json(self.data_dir / "jobs" / "last.json")
        self._lock = threading.Lock()

    def start(self, file: Path, run: str, **kw: Any) -> Job:
        with self._lock:
            if self.job and self.job.running:
                raise HTTPException(status_code=409, detail=f"a job is already running ({self.job.file.name} -> "
                                                            f"{self.job.run}); wait for it or cancel it")
            self.job = Job(file, run, self.data_dir, on_done=self._done, on_saved=self._save, **kw)
            return self.job

    def _done(self, job: Job, final: str) -> None:
        if final in ("ok", "ok_with_warnings") and job.options["switch"]:
            try:
                self.activate(self.data_dir / "runs" / job.run)
                job.switched = True
            except Exception as exc:  # noqa: BLE001
                job.error = f"the run finished but the API could not load it: {type(exc).__name__}: {exc}"
                log.warning("job %s: %s", job.id, job.error)

    def _save(self, job: Job) -> None:
        snap = job.snapshot()
        self.saved = snap
        try:
            out = self.data_dir / "jobs"
            out.mkdir(parents=True, exist_ok=True)
            tmp = out / "last.json.tmp"
            tmp.write_text(json.dumps(snap, indent=1), encoding="utf-8")
            os.replace(tmp, out / "last.json")
        except OSError as exc:
            log.warning("job %s: could not save last.json: %s", job.id, exc)

    def current(self) -> Optional[Dict[str, Any]]:
        if self.job is not None:
            return self.job.snapshot()
        return self.saved


# ── runs ─────────────────────────────────────────────────────────────────────

def run_info(run_dir: Path, active: Optional[Path]) -> Optional[Dict[str, Any]]:
    if not (run_dir / "index.json").is_file():
        return None
    summary = _read_json(run_dir / "run_summary.json") or {}
    pipe = summary.get("pipeline") or _read_json(run_dir / "pipeline.json") or {}
    counts = summary.get("counts") or {}
    totals = summary.get("totals") or {}
    inp = pipe.get("input") or {}
    return {
        "name": run_dir.name,
        "active": active is not None and run_dir.resolve() == active.resolve(),
        "sample": bool(summary.get("sample")),
        "incidents": counts.get("incidents"),
        "critical_incidents": counts.get("critical_incidents"),
        "alerts": counts.get("alerts"),
        "events": (summary.get("data_quality") or {}).get("events"),
        "processing_secs": totals.get("processing_secs"),
        "bundled_at": summary.get("bundled_at"),
        "input": Path(inp["path"]).name if inp.get("path") else None,
        "input_bytes": inp.get("bytes"),
    }


def find_run(name: str, data_dir: Path) -> Optional[Path]:
    """A run folder by name: data/runs/<name>, else examples/<name> (the committed sample)."""
    if not RUN_RE.match(name):
        return None
    for base in (data_dir / "runs", REPO_ROOT / "examples"):
        p = base / name
        if (p / "index.json").is_file():
            return p
    return None


# ── endpoints ────────────────────────────────────────────────────────────────

def _uploads(request: Request) -> Uploads:
    return request.app.state.uploads


def _jobs(request: Request) -> Jobs:
    return request.app.state.jobs


@router.get("/uploads", tags=["analyse"])
def list_uploads(request: Request) -> Dict[str, Any]:
    """Logs in the raw folder (with the runs made from each), partial uploads, free disk, job defaults."""
    return _uploads(request).listing(request.app.state.data_dir)


@router.get("/uploads/{name}", tags=["analyse"])
def upload_status(name: str, request: Request) -> Dict[str, Any]:
    """How many bytes of `name` the server has; `complete` when the whole file is in the raw folder."""
    return _uploads(request).status(_check_file_name(name))


@router.post("/uploads/{name}", tags=["analyse"])
async def upload_chunk(name: str, request: Request,
                       offset: int = Query(..., ge=0, description="byte of the file this chunk starts at"),
                       total: int = Query(..., gt=0, description="size of the whole file in bytes")) -> Any:
    """Append one chunk (the raw request body, at most 256 MB). It must start where the server's
    copy ends; a 409 says where that is. The chunk that completes the file moves it into the raw folder."""
    _need_enabled()
    return await _uploads(request).write(_check_file_name(name), offset, total, request, request.app.state.data_dir)


@router.post("/uploads/{name}/discard", tags=["analyse"])
def discard_upload(name: str, request: Request) -> Dict[str, Any]:
    """Delete a partial upload (a complete file is never deleted here)."""
    _need_enabled()
    return _uploads(request).discard(_check_file_name(name))


class JobRequest(BaseModel):
    file: str = Field(..., description="a log in the raw folder (see GET /uploads)")
    run: Optional[str] = Field(None, description="run name; default: the file name without its extension")
    offline: bool = Field(False, description="no threat-intel lookups or AI reports (nothing leaves the machine)")
    no_llm: bool = Field(False, description="skip the AI narrator; template reports")
    workers: Optional[int] = Field(None, ge=1, le=64, description="parser processes")
    replace: bool = Field(False, description="overwrite an existing run of that name")
    switch: bool = Field(True, description="serve the new run when it finishes")
    upload_secs: Optional[float] = Field(None, ge=0, description="how long the upload took (shown with the result)")


@router.post("/jobs", tags=["analyse"], status_code=202)
def start_job(body: JobRequest, request: Request) -> Dict[str, Any]:
    """Run parse ... bundle on a log of the raw folder. Poll GET /jobs/current for progress."""
    _need_enabled()
    up = _uploads(request)
    name = _check_file_name(body.file)
    path = up.final(name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"{name} is not in the raw folder {up.raw_dir}; upload it first")
    run = body.run or Path(name).stem
    if not RUN_RE.match(run) or run == EMPTY_RUN:
        raise HTTPException(status_code=400, detail=f"bad run name {run!r}: use letters, digits, '.', '_' and '-'")
    data_dir: Path = request.app.state.data_dir
    run_dir = data_dir / "runs" / run
    active = request.app.state.bundle.run_dir
    if run_dir.exists() and run_dir.resolve() == Path(active).resolve():
        raise HTTPException(status_code=409, detail=f"run {run} is the one being served; pick another name")
    if run_dir.exists() and not body.replace:
        raise HTTPException(status_code=409, detail=f"a run named {run} already exists; pick another name or replace it")
    job = _jobs(request).start(path, run, offline=body.offline, no_llm=body.no_llm,
                               workers=body.workers or default_workers(), upload_secs=body.upload_secs,
                               switch=body.switch)
    return job.snapshot()


@router.get("/jobs/current", tags=["analyse"])
def current_job(request: Request) -> Dict[str, Any]:
    """The running job, else the last one (also after an API restart); `job` is null when there was none."""
    return {"enabled": uploads_enabled(), "job": _jobs(request).current()}


@router.post("/jobs/current/cancel", tags=["analyse"])
def cancel_job(request: Request) -> Dict[str, Any]:
    """Stop the running job and every process it started."""
    _need_enabled()
    jobs = _jobs(request)
    if not jobs.job or not jobs.job.running:
        raise HTTPException(status_code=409, detail="no job is running")
    jobs.job.cancel()
    return jobs.job.snapshot()


@router.get("/runs", tags=["analyse"])
def list_runs(request: Request) -> Dict[str, Any]:
    """Analysed runs in data/runs (and the committed sample), newest first; `active` is the one served."""
    data_dir: Path = request.app.state.data_dir
    active = Path(request.app.state.bundle.run_dir)
    rows = []
    for base in (data_dir / "runs", REPO_ROOT / "examples"):
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir():
                    info = run_info(d, active)
                    if info and not any(r["name"] == info["name"] for r in rows):
                        rows.append(info)
    if not any(r["active"] for r in rows):
        info = run_info(active, active)
        if info:
            rows.append(info)
    rows.sort(key=lambda r: (not r["active"], r["sample"], -(datetime.fromisoformat(r["bundled_at"].replace("Z", "+00:00")).timestamp()
                                                              if r.get("bundled_at") else 0)))
    return {"active": request.app.state.bundle.run, "runs": rows}


class SelectRequest(BaseModel):
    run: str


@router.post("/runs/select", tags=["analyse"])
def select_run(body: SelectRequest, request: Request) -> Dict[str, Any]:
    """Serve another run: every endpoint answers from it from now on."""
    if body.run == EMPTY_RUN:                 # back to no run: an empty Dashboard, ready for a new log
        e = empty_bundle()
        b = request.app.state.activate(e.run_dir, e)
        return {"active": b.run, "incidents": 0, "alerts": 0}
    run_dir = find_run(body.run, request.app.state.data_dir)
    if run_dir is None:
        raise HTTPException(status_code=404, detail=f"no run named {body.run!r}")
    b = request.app.state.activate(run_dir)
    return {"active": b.run, "incidents": len(b.incidents), "alerts": len(b.alerts)}
