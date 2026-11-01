"""Runs every stage of the pipeline as a subprocess and records what each one did.

The record (schema in docs/tasks/trackA/item3-plan.md) goes to <run>/pipeline.json and, under the
`pipeline` key, into the run_summary.json that bundle writes. Bundle rebuilds run_summary.json from
scratch, so the key is added after bundle and pipeline.json keeps a copy a later rebundle cannot drop.

The first stage, schema, detects the input's format and maps its fields (killchain/schema). FortiGate
input (and input of no recognised format) is then parsed by `python -m killchain parse` exactly as before;
anything else by the generic parser (`python -m killchain schema --mapping <run>/schema.yaml`). What was
read (format, products, categories, mapping, rules that can run, vendor alerts, network zones) goes to the
record's `schema` part and to run_summary.json `schema` (docs/schema.md).
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

STAGES: List[str] = ["schema", "parse", "prepare", "detect", "correlate", "chain", "reach", "score", "report",
                     "enrich", "narrate", "bundle"]
# schema may fail (a bug, an odd file): the FortiGate parser then reads the input, as before the stage existed
REQUIRED = set(STAGES) - {"schema", "enrich", "narrate"}
RECORD_VERSION = 1
TAIL_LINES = 20
SCHEMA_NO_RECORDS = 3        # `python -m killchain schema` exit code when no record can be read


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


def schema_mapping(ctx: Context) -> Optional[Dict[str, Any]]:
    """The run's schema.yaml (written by the schema stage), or None."""
    p = ctx.run_dir / "schema.yaml"
    if not p.is_file():
        return None
    try:
        import yaml

        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def uses_fortigate_parser(ctx: Context) -> bool:
    """FortiGate input (and input of no recognised format) goes to the FortiGate parser exactly as before
    the schema stage existed; so does a run without a schema.yaml (--from parse on an older run)."""
    m = schema_mapping(ctx)
    return m is None or m.get("format") == "fortigate"


def _llm_off(ctx: Context) -> bool:
    return ctx.no_llm or ctx.offline


def command_for(stage: str, ctx: Context) -> List[str]:
    py, P, R = sys.executable, str(ctx.parsed_dir), str(ctx.run_dir)
    workers = ["--workers", str(ctx.workers)] if ctx.workers else []
    if stage == "schema":
        cmd = [py, "-m", "killchain", "schema", "--input", str(ctx.input), "--name", ctx.name,
               "--data-dir", str(ctx.data_dir)]
        return cmd + (["--no-llm"] if _llm_off(ctx) else [])
    if stage == "parse":
        if uses_fortigate_parser(ctx):
            report = _read(ctx.run_dir / "schema_report.json") or {}
            src = report.get("plain_input") or str(ctx.input)        # a .gz / .zip is read from its plain copy
            return [py, "-m", "killchain", "parse", src, "--out", P, "--overwrite"] + workers
        return [py, "-m", "killchain", "schema", "--input", str(ctx.input), "--name", ctx.name,
                "--data-dir", str(ctx.data_dir), "--mapping", str(ctx.run_dir / "schema.yaml"), "--out", P] + workers
    if stage == "prepare":
        return [py, "-m", "killchain", "db", "--prepare", "--parsed", P, "--run", R]
    if stage == "reach":
        return [py, "-m", "killchain", "reach", "--run", R, "--parsed", P]
    if stage == "detect":
        return [py, "-m", "killchain", "detect", "--run", R] + (["--no-llm"] if _llm_off(ctx) else [])
    if stage in ("correlate", "chain", "score", "report"):
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
    if stage == "schema":
        rep = _read(R / "schema_report.json")
        if not isinstance(rep, dict):
            return {}
        rules = (rep.get("rules") or {}).get("counts") or {}
        return {"format": rep.get("format"), "parser": rep.get("parser"),
                "sample": (rep.get("sample") or {}).get("records"), "categories": rep.get("categories") or {},
                "rules_can_run": rules.get("can_run"), "rules_skipped": rules.get("skipped")}
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
    if st.get("parser") == "generic":
        return (f"run: no events in {ctx.input}: read as {st.get('format')}, but none of its {st.get('lines', 0)} "
                f"lines gave a record ({classes})")
    return (f"run: no events in {ctx.input}: none of its {st.get('lines', 0)} lines is a FortiGate event or a record "
            f"of another supported format (CSV/TSV, JSON, NDJSON, key=value, syslog/CEF/LEEF, Windows XML) ({classes})")


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
    if ctx.from_stage in (None, "schema", "parse"):
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


def _category_counts(ctx: Context) -> Tuple[Dict[str, int], Dict[str, int]]:
    """({category: rows}, {product: rows}) over the whole parsed run (the generic parser's columns)."""
    import duckdb

    db_path = ctx.run_dir / "events.duckdb"
    if not db_path.exists():
        return {}, {}
    try:
        con = duckdb.connect(str(db_path), read_only=True)
    except Exception:  # noqa: BLE001 - a locked or broken file: the sample counts are reported instead
        return {}, {}
    try:
        con.execute("SET TimeZone = 'UTC'")
        cats = dict(con.execute("SELECT coalesce(category, 'none'), count(*) FROM events GROUP BY 1 "
                                "ORDER BY 2 DESC").fetchall())
        prods = dict(con.execute("SELECT product, count(*) FROM events WHERE product IS NOT NULL GROUP BY 1 "
                                 "ORDER BY 2 DESC LIMIT 20").fetchall())
    except Exception:  # noqa: BLE001 - an older prepared run without the optional columns
        cats, prods = {}, {}
    finally:
        con.close()
    return {str(k): int(v) for k, v in cats.items()}, {str(k): int(v) for k, v in prods.items()}


def schema_summary(ctx: Context, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """What the run read and what could run on it, for run_summary.json `schema` (docs/schema.md)."""
    rep = _read(ctx.run_dir / "schema_report.json")
    if not isinstance(rep, dict):
        return None
    mapping = schema_mapping(ctx) or {}
    stages = {s["name"]: s for s in record.get("stages") or []}
    parsed = _read(ctx.parsed_dir / "_stats.json") or {}
    rows = sum(int(v.get("rows") or 0) for v in (parsed.get("streams") or {}).values())
    fortigate = rep.get("parser") == "fortigate"
    cats, prods = ({}, {}) if fortigate else _category_counts(ctx)
    if fortigate:
        prods = {"FortiGate": rows} if mapping.get("detected") is None and rows else {}
    methods: Dict[str, int] = {}
    for c in rep.get("columns") or []:
        methods[c["method"]] = methods.get(c["method"], 0) + 1
    rules = rep.get("rules") or {}
    det = _read(ctx.run_dir / "detect" / "_stats.json") or {}
    vend = det.get("vendor") or {}
    net = _read(ctx.run_dir / "network_zones.json") or {}
    llm = rep.get("llm") or {}
    out: Dict[str, Any] = {
        "format": rep.get("format"),
        "detected": mapping.get("detected") or (rep.get("format_detail") or {}).get("format"),
        "fallback": "fortigate" if mapping.get("detected") == "unknown" else None,
        "parser": rep.get("parser"), "fingerprint": rep.get("fingerprint"), "schema_source": rep.get("schema_source"),
        "products": prods,
        "categories": cats or rep.get("categories") or {},
        "categories_from": "parsed events" if cats else "sample",
        "sample_records": (rep.get("sample") or {}).get("records"),
        "mapping": {"methods": methods,
                    "mapped": sorted(c["column"] for c in rep.get("columns") or []
                                     if c["method"] not in ("unmapped",)),
                    "unmapped": sorted(c["column"] for c in rep.get("columns") or [] if c["method"] == "unmapped"),
                    "time_coverage": (rep.get("time") or {}).get("coverage"),
                    "dropped": len((rep.get("validation") or {}).get("dropped") or [])},
        "llm": {"used": bool(llm.get("used")), "reason": llm.get("reason"),
                "added": len(llm.get("added") or [])},
        "rules": {"can_run": [r["id"] for r in rules.get("can_run") or []],
                  "skipped": [{"id": r["id"], "missing": r.get("missing")} for r in rules.get("skipped") or []]},
        "alerts_by_layer": det.get("layers") or {},
        "vendor_alerts": {"records": vend.get("records", 0), "alerts": (det.get("layers") or {}).get("vendor", 0),
                          "technique_sources": vend.get("technique_sources") or {},
                          "llm_skipped": (vend.get("llm") or {}).get("skipped")},
        "network": {k: net.get(k) for k in ("source", "file", "reason", "internal_ips", "configured_share", "zones",
                                            "servers", "named_hosts") if k in net} or None,
        "secs": (stages.get("schema") or {}).get("wall_secs"),
        "prepare_secs": rep.get("secs"),
    }
    return out


def merge_summary(run_dir: Path, record: Dict[str, Any]) -> Optional[str]:
    """Put the record under `pipeline` (and its `schema` part also at the top, as `schema`) in
    run_summary.json, keeping every other key as bundle wrote it. Returns a warning (and writes nothing)
    when the existing file is not valid JSON."""
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
    if record.get("schema") is not None:
        summary["schema"] = record["schema"]
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

    existed = {"run_dir": ctx.run_dir.exists(), "parsed_dir": ctx.parsed_dir.exists()}
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

    def add(entry: Dict[str, Any]) -> None:
        """Record a stage and say so on stdout (`run: stage <name> <status> <secs>`), which the API's
        job runner reads for progress."""
        stages.append(entry)
        secs = "-" if entry["wall_secs"] is None else f"{entry['wall_secs']}"
        print(f"run: stage {entry['name']} {entry['status']} {secs}", flush=True)

    for i, stage in enumerate(STAGES):
        if stop:
            add(_skipped(stage, stop))
            continue
        if i < start:
            add(_skipped(stage, f"--from {ctx.from_stage}"))
            continue
        if stage == "parse" and ctx.reuse_parsed:
            if (ctx.parsed_dir / "_stats.json").exists():
                parse_reused = True
                add(_skipped(stage, "--reuse-parsed", stage_counts(stage, ctx)))
            else:
                notes.append(f"--reuse-parsed: no earlier parse in {ctx.parsed_dir}; parsing")
        if stage == "prepare" and parse_reused:
            db, st = ctx.run_dir / "events.duckdb", ctx.parsed_dir / "_stats.json"
            # the network choice (network_zones.json) is made by prepare: without it, prepare runs again
            if db.exists() and db.stat().st_mtime > st.stat().st_mtime and (ctx.run_dir / "network_zones.json").exists():
                add(_skipped(stage, "--reuse-parsed", stage_counts(stage, ctx)))
                continue
        if stage == "narrate":
            reason = llm_gate(ctx)
            if reason:
                add(_skipped(stage, reason))
                if reason == NO_KEY:
                    warnings.append(f"narrate: {reason}")
                    print(f"run: narrate skipped: {reason}", file=sys.stderr)
                continue
        if not (stage == "parse" and parse_reused):
            notes.extend(notes_before(stage, ctx, written))
            if stage == "schema":
                for old in ("schema.yaml", "schema_report.json"):    # an earlier run's mapping must not be used
                    (ctx.run_dir / old).unlink(missing_ok=True)
            cmd = command_for(stage, ctx)
            print(f"run: stage {stage} started", flush=True)
            res = run_stage(stage, cmd, ctx)
            ok = res["exit_code"] == 0
            entry = {"name": stage, "status": "ok" if ok else "failed",
                     "reason": None if ok else f"exit code {res['exit_code']}",
                     "exit_code": res["exit_code"], "wall_secs": res["wall_secs"], "peak_rss_mb": res["peak_rss_mb"],
                     "counts": stage_counts(stage, ctx) if ok else {}, "command": cmd, "log": res["log"],
                     "tail": None if ok else res["tail"]}
            no_records = stage == "schema" and res["exit_code"] == SCHEMA_NO_RECORDS
            if no_records:              # the stage worked: the file holds nothing it can read
                entry.update(status="ok", reason="no record could be read")
            add(entry)
            if ok:
                written.add(stage)
            if ok and stage == "enrich" and (entry["counts"].get("failures") or 0) > 0:
                doc = _read(ctx.run_dir / "enrichment.json") or {}
                errs = (doc.get("summary") or {}).get("errors") or ["no error text"]
                entry["status"] = "degraded"
                warnings.append(f"enrich: {entry['counts']['failures']} of {entry['counts'].get('lookups')} lookups "
                                f"failed ({errs[0]}); threat intel is partial")
            if ok and stage == "schema":
                notes.extend(schema_notes(ctx, warnings))
            if ok and stage == "detect":
                notes.extend(detect_notes(ctx))
            if no_records:
                why = next((t for t in reversed(res["tail"]) if t.startswith("schema: ")),
                           res["tail"][-1] if res["tail"] else "no record could be read")
                record["error"] = f"run: no events in {ctx.input}: {why[len('schema: '):] if why.startswith('schema: ') else why}"
                stop = "no events in the input"
                code = 3
                continue
            if not ok:
                if stage in REQUIRED:
                    record["error"] = (f"run: stage {stage} failed (exit {res['exit_code']}); log {ctx.run_dir / res['log']}"
                                       + "\n  " + "\n  ".join(res["tail"]))
                    stop = f"earlier stage {stage} failed"
                    code = 1
                    continue
                warnings.append(f"{stage} failed (exit {res['exit_code']}); the run goes on without it"
                                + (" (the FortiGate parser reads the file)" if stage == "schema" else "")
                                + f", see {ctx.run_dir / res['log']}")
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
    if code == 3:
        # nothing to show: the run and parsed folders this attempt created are removed, so no empty run is
        # listed and the name can be used again (folders that existed before are kept, with this record)
        removed = remove_attempt(ctx, existed)
        record["removed"] = removed
        if removed.get("run_dir"):
            return code, record
    try:
        record["schema"] = schema_summary(ctx, record)
    except Exception as exc:  # noqa: BLE001 - the summary is a report; it never fails a finished run
        warnings.append(f"schema summary not written: {type(exc).__name__}: {exc}")
    warn = merge_summary(ctx.run_dir, _finish(record, warnings))
    if warn:
        warnings.append(warn)
        _finish(record, warnings)
    write_record(ctx.run_dir, record)
    return code, record


def remove_attempt(ctx: Context, existed: Dict[str, bool]) -> Dict[str, bool]:
    """Delete the run and parsed folders of a run that found no events, when this run created them."""
    import shutil

    out: Dict[str, bool] = {}
    for key, path in (("run_dir", ctx.run_dir), ("parsed_dir", ctx.parsed_dir)):
        out[key] = False
        if not existed.get(key) and path.exists():
            shutil.rmtree(path, ignore_errors=True)
            out[key] = not path.exists()
    return out


def schema_notes(ctx: Context, warnings: List[str]) -> List[str]:
    """After the schema stage: what it read, and why the LLM was not asked (when it was not)."""
    rep = _read(ctx.run_dir / "schema_report.json") or {}
    mapping = schema_mapping(ctx) or {}
    notes: List[str] = []
    if mapping.get("detected") == "unknown":
        warnings.append(f"schema: no supported format recognised in {ctx.input.name}; read with the FortiGate "
                        f"parser, which rejects the lines it cannot parse")
    else:
        notes.append(f"schema: {rep.get('format')} via the {rep.get('parser')} parser"
                     + (f" ({rep.get('schema_source')} mapping)" if rep.get("parser") == "generic" else ""))
    llm = rep.get("llm") or {}
    if rep.get("parser") == "generic" and not llm.get("used") and llm.get("reason"):
        notes.append(f"schema: LLM not asked about unmatched fields: {llm['reason']}")
    return notes


def detect_notes(ctx: Context) -> List[str]:
    v = (_read(ctx.run_dir / "detect" / "_stats.json") or {}).get("vendor") or {}
    llm = v.get("llm") or {}
    if v.get("records") and llm.get("names") and llm.get("skipped"):
        return [f"detect: LLM not asked to label {llm['names']} vendor alert name(s): {llm['skipped']}"]
    return []


def _finish(record: Dict[str, Any], warnings: List[str]) -> Dict[str, Any]:
    if record["exit_code"] == 0:
        record["status"] = "ok_with_warnings" if warnings else "ok"
    return record
