"""Generic parser: a whole file of any supported format -> <out>/firewall/part-*.parquet with canonical.SCHEMA.

Same layout, columns and _stats.json as the FortiGate parser (killchain/parser), so db.py and every later
stage read the result unchanged. The mapping (schema.yaml) is fixed before the parse; no LLM is called.

Line formats (ndjson, kv, syslog) and CSV without quoted newlines are split into byte ranges that start
on line boundaries and parsed in worker processes, like the FortiGate parser: a first pass counts
newlines per range so `line` is the true 1-based line number, `byte_offset` is where the line starts.
CSV ranges are read with pyarrow's CSV reader (columnar); a range it cannot read row-for-line falls back
to Python's csv module. JSON documents (arrays, {"data": [...]}, pretty-printed objects), XML events
and CSV with quoted newlines are read in one process; a JSON record's `line` is the line of its opening
brace and `byte_offset` the brace's byte (not the record index).

Lines that are not records (bad JSON, binary, not key=value) are rejected and counted, as in the
FortiGate parser. Records with a value that does not fit its column get parse_issue bad_number /
bad_time and keep the text in `extra` (_bad_<column>); a CSV row with the wrong number of fields gets
stray_text. Fields that map to no column are kept in `extra` as a JSON object.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from ..parser import arrowutil as au
from ..parser.cli import MemoryMonitor, plan_ranges, summarize
from ..parser.worker import count_newlines
from . import canonical as C
from . import formats as F
from .convert import Mapper, records_getter
from .mapping import load_synonyms

STREAM = "firewall"
SAMPLES_PER_REASON = 3
READ_BLOCK = 8 << 20          # line formats are read this much at a time
RECORD_BATCH = 16384          # decoded records (Python dicts) per batch; CSV batches stay at batch_rows
CSV_MAX_RANGE = 32 << 20      # a CSV range is read whole (pyarrow), so keep it small


def _hash(raw: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "little", signed=True)


def unique_header(header: List[str]) -> List[str]:
    seen: Counter = Counter()
    out = []
    for h in header:
        h = h or "column"
        seen[h] += 1
        out.append(h if seen[h] == 1 else f"{h}_{seen[h]}")
    return out


def _json_escape(a: pa.Array) -> pa.Array:
    a = pc.replace_substring(a, "\\", "\\\\")
    a = pc.replace_substring(a, '"', '\\"')
    for c, r in (("\n", "\\n"), ("\r", "\\r"), ("\t", "\\t")):
        a = pc.replace_substring(a, c, r)
    return pc.replace_substring_regex(a, r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "")


def json_objects(names: List[str], arrays: List[pa.Array], n: int) -> pa.Array:
    """Per row a JSON object of the non-null values (string columns), or null."""
    pieces = []
    for name, a in zip(names, arrays):
        if a.null_count == len(a):
            continue
        key = json.dumps(name, ensure_ascii=False)
        piece = pc.binary_join_element_wise(pa.scalar(key + ':"'), _json_escape(a), pa.scalar('",'), "")
        pieces.append(pc.fill_null(piece, ""))
    if not pieces:
        return pa.nulls(n, pa.string())
    # (null_handling="skip" can drop all-null rows in some pyarrow versions, so every piece is non-null
    # text ending in a comma and the last comma is cut off)
    body = pc.binary_join_element_wise(*pieces, "") if len(pieces) > 1 else pieces[0]
    empty = pc.equal(pc.utf8_length(body), 0)
    body = pc.binary_join_element_wise(pa.scalar("{"), pc.utf8_slice_codeunits(body, 0, -1), pa.scalar("}"), "")
    return pc.if_else(empty, pa.scalar(None, pa.string()), body)


# ── one batch sink (per task) ────────────────────────────────────────────────

class Sink:
    """Writes batches of one task to one Parquet part and keeps the stream statistics."""

    def __init__(self, out_dir: Path, part: str, mapper: Mapper, source: str, tq: au.TimeQuality) -> None:
        self.path = out_dir / STREAM / f"part-{part}.parquet"
        self.mapper, self.source, self.tq = mapper, source, tq
        self.writer: Optional[pq.ParquetWriter] = None
        self.st: Dict[str, Any] = {"rows": 0, "quality": Counter(), "issues": Counter(), "min_ok": None, "max_ok": None}
        self.issue_samples: List[Dict[str, Any]] = []

    def write(self, get, n, lines, offsets, hashes, extras, issues) -> None:
        if not n:
            return
        table, info = self.mapper.table(get, n, self.source, lines, offsets, hashes, extras, issues, self.tq)
        if self.writer is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.writer = pq.ParquetWriter(self.path, C.SCHEMA, compression="zstd", compression_level=3)
        self.writer.write_table(table)
        st = self.st
        st["rows"] += n
        st["quality"].update(info["quality"])
        st["issues"].update(info.get("issues") or {})
        if info.get("issues") and len(self.issue_samples) < 10:
            flagged = table.filter(table["parse_issue"].is_valid()).select(["line", "byte_offset", "parse_issue"])
            self.issue_samples += flagged.slice(0, SAMPLES_PER_REASON).to_pylist()[: 10 - len(self.issue_samples)]
        if "min_ok" in info:
            st["min_ok"] = info["min_ok"] if st["min_ok"] is None else min(st["min_ok"], info["min_ok"])
            st["max_ok"] = info["max_ok"] if st["max_ok"] is None else max(st["max_ok"], info["max_ok"])

    def close(self) -> Dict[str, Any]:
        if self.writer is not None:
            self.writer.close()
        st = self.st
        return {"rows": st["rows"], "quality": dict(st["quality"]), "issues": dict(st["issues"]),
                "min_ok": st["min_ok"], "max_ok": st["max_ok"]}


class RecordBatcher:
    """Collects decoded records and flushes them to a Sink every batch_rows records."""

    def __init__(self, sink: Sink, batch_rows: int) -> None:
        self.sink, self.batch_rows = sink, batch_rows
        self.used = sink.mapper.used_fields()
        self.fields = sink.mapper.needed_fields()
        self.recs: List[Dict[str, Any]] = []
        self.meta: List[Tuple[int, int, int]] = []
        self.issues: List[Optional[List[str]]] = []

    def add(self, rec: Dict[str, Any], line: int, offset: int, raw: bytes, issue: Optional[List[str]] = None) -> None:
        self.recs.append(rec)
        self.meta.append((line, offset, _hash(raw)))
        self.issues.append(issue)
        if len(self.recs) >= self.batch_rows:
            self.flush()

    def flush(self) -> None:
        if not self.recs:
            return
        recs = self.recs
        extras = []
        for r in recs:
            rest = {k: v for k, v in r.items() if k not in self.used and v is not None and v != ""}
            extras.append(rest or None)
        lines, offsets, hashes = zip(*self.meta)
        self.sink.write(records_getter(recs, self.fields), len(recs), lines, offsets, hashes, extras, self.issues)
        self.recs, self.meta, self.issues = [], [], []


# ── worker: one byte range of a line or CSV file ─────────────────────────────

def _line_positions(data: bytes) -> Tuple[np.ndarray, np.ndarray]:
    arr = np.frombuffer(data, dtype=np.uint8)
    nl = np.flatnonzero(arr == 10)
    starts = np.concatenate([[0], nl + 1]).astype(np.int64)
    ends = np.concatenate([nl, [len(data)]]).astype(np.int64)
    if starts[-1] >= len(data):
        starts, ends = starts[:-1], ends[:-1]
    return starts, ends


def _csv_fast(data: bytes, header: List[str], delim: str) -> Optional[pa.Table]:
    import pyarrow.csv as pacsv

    try:
        return pacsv.read_csv(
            io.BytesIO(data),
            read_options=pacsv.ReadOptions(column_names=header, use_threads=False, block_size=1 << 26),
            parse_options=pacsv.ParseOptions(delimiter=delim, quote_char='"', double_quote=True,
                                             newlines_in_values=False, ignore_empty_lines=True),
            convert_options=pacsv.ConvertOptions(column_types={h: pa.string() for h in header},
                                                 strings_can_be_null=True, quoted_strings_can_be_null=True,
                                                 null_values=[""]))
    except (pa.ArrowInvalid, pa.ArrowException):
        return None


def _parse_csv_range(data: bytes, task: Dict[str, Any], sink: Sink, counts: Counter) -> None:
    header: List[str] = task["header"]
    delim = task["delimiter"]
    start, base = task["start"], task["base_line"]
    starts, ends = _line_positions(data)
    raw_lines = [data[s:e] for s, e in zip(starts.tolist(), ends.tolist())]
    nonblank = [i for i, r in enumerate(raw_lines) if r.rstrip(b"\r").strip()]
    counts["blank"] += len(raw_lines) - len(nonblank)
    mapper = sink.mapper
    used = mapper.used_fields()
    rest_cols = [h for h in header if h not in used]
    table = _csv_fast(data, header, delim)
    if table is not None and table.num_rows == len(nonblank):
        counts[STREAM] += table.num_rows
        br = task["batch_rows"]
        for b0 in range(0, table.num_rows, br):
            t = table.slice(b0, br)
            idx = nonblank[b0:b0 + t.num_rows]
            n = t.num_rows
            cache: Dict[str, pa.Array] = {}

            def get(f: str, t=t, n=n, cache=cache) -> pa.Array:
                if f not in cache:
                    cache[f] = t.column(f).combine_chunks() if f in t.column_names else pa.nulls(n, pa.string())
                return cache[f]
            extras = json_objects(rest_cols, [get(h) for h in rest_cols], n)
            lines = [base + i for i in idx]
            offsets = [start + int(starts[i]) for i in idx]
            hashes = [_hash(raw_lines[i].rstrip(b"\r")) for i in idx]
            sink.write(get, n, lines, offsets, hashes, extras, None)
        return
    # Slow path: Python csv per line (a quote or column-count problem somewhere in the range).
    batcher = RecordBatcher(sink, task["batch_rows"])
    for i in nonblank:
        raw = raw_lines[i].rstrip(b"\r")
        row = next(csv.reader([raw.decode("utf-8", "replace")], delimiter=delim), [])
        rec = {h: (v if v != "" else None) for h, v in zip(header, row)}
        issue = None
        if len(row) != len(header):
            issue = ["stray_text"]
            if len(row) > len(header):
                rec["_stray"] = delim.join(row[len(header):])[:500]
            rec["_columns"] = len(row)
        batcher.add(rec, base + i, start + int(starts[i]), raw, issue)
        counts[STREAM] += 1
    batcher.flush()


def _blocks(path: str, start: int, end: int) -> Iterator[Tuple[int, bytes]]:
    """(offset, bytes) of whole lines from start to end, READ_BLOCK at a time."""
    with open(path, "rb") as f:
        f.seek(start)
        left, pos, carry = end - start, start, b""
        while left > 0:
            block = f.read(min(READ_BLOCK, left))
            if not block:
                break
            left -= len(block)
            data = carry + block if carry else block
            if left > 0:
                cut = data.rfind(b"\n")
                if cut < 0:
                    carry = data
                    continue
                carry, data = data[cut + 1:], data[:cut + 1]
            else:
                carry = b""
            yield pos, data
            pos += len(data)
        if carry:
            yield pos, carry


def _parse_line_range(task: Dict[str, Any], sink: Sink, counts: Counter,
                      samples: Dict[str, List[Dict[str, Any]]], syn) -> int:
    m = task["mapping"]
    dec = F.Decoder(m["format"], tuple(m.get("wrappers") or ()), syn.message_patterns, tuple(m.get("expand") or ()))
    batcher = RecordBatcher(sink, min(task["batch_rows"], RECORD_BATCH))
    line_no = task["base_line"]
    for base, data in _blocks(task["path"], task["start"], task["end"]):
        pos = 0
        n = len(data)
        for raw in data.split(b"\n"):
            if pos >= n:
                break
            length = len(raw)
            line = raw[:-1] if raw[-1:] == b"\r" else raw
            if not line.strip():
                counts["blank"] += 1
            else:
                body = line.lstrip(b"\xef\xbb\xbf") if base + pos == 0 else line
                rec, why = dec.line(body)
                if rec is None:
                    why = "unknown_format" if why == "not_json" else why
                    if why != "binary" and _binary(line):
                        why = "binary"
                    counts["rejected:" + why] += 1
                    bucket = samples.setdefault(why, [])
                    if len(bucket) < SAMPLES_PER_REASON:
                        bucket.append({"line": line_no, "byte": base + pos, "head": repr(line[:160])})
                else:
                    batcher.add(rec, line_no, base + pos, line)
                    counts[STREAM] += 1
            pos += length + 1
            line_no += 1
    batcher.flush()
    return line_no - task["base_line"]


def _binary(line: bytes) -> bool:
    try:
        line.decode("utf-8")
        return bool(au.CTRL_RE.search(line))
    except UnicodeDecodeError:
        return True


def parse_range(task: Dict[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    syn = load_synonyms(Path(task["synonyms"])) if task.get("synonyms") else load_synonyms()
    mapper = Mapper(task["mapping"], syn)
    sink = Sink(Path(task["out"]), task["part"], mapper, task["source"],
                au.TimeQuality(task["stuck_run"], task["backwards_secs"]))
    counts: Counter = Counter()
    samples: Dict[str, List[Dict[str, Any]]] = {}
    if task["mapping"]["format"] == "csv":
        with open(task["path"], "rb") as f:
            f.seek(task["start"])
            data = f.read(task["end"] - task["start"])
        _parse_csv_range(data, task, sink, counts)
        lines = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
        del data
    else:
        lines = _parse_line_range(task, sink, counts, samples, syn)
    st = sink.close()
    return {"part": task["part"], "start": task["start"], "end": task["end"], "bytes": task["end"] - task["start"],
            "lines": lines,
            "lines_by_class": dict(counts), "stream": st, "issue_samples": sink.issue_samples,
            "samples": samples, "secs": time.perf_counter() - t0}


# ── single-process formats ───────────────────────────────────────────────────

def _iter_doc(path: Path, mapping: Dict[str, Any], syn) -> Iterator[Tuple[Dict[str, Any], int, int, bytes, Optional[List[str]]]]:
    fmt = mapping["format"]
    dec = F.Decoder("ndjson", tuple(mapping.get("wrappers") or ()), syn.message_patterns, tuple(mapping.get("expand") or ()))
    if fmt == "json":
        for rec, ln, off, raw in F.iter_json_doc(path):
            yield dec.finish(rec), ln, off, raw, None
    elif fmt == "xml":
        for rec, ln, off, raw in F.iter_xml(path):
            yield dec.finish(rec), ln, off, raw, None
    elif fmt == "csv":
        header = F.csv_header(path, mapping.get("delimiter") or ",")
        for rec, ln, off, raw in F.iter_csv(path, mapping.get("delimiter") or ","):
            issue = ["stray_text"] if len(rec) != len([h for h in header if h]) else None
            yield rec, ln, off, raw.rstrip(b"\r\n"), issue
    else:
        raise ValueError(f"not a document format: {fmt}")


def _parse_single(path: Path, out: Path, mapping: Dict[str, Any], args: Dict[str, Any], syn) -> Dict[str, Any]:
    t0 = time.perf_counter()
    mapper = Mapper(mapping, syn)
    sink = Sink(out, "00-00000", mapper, path.name, au.TimeQuality(args["stuck_run"], args["backwards_secs"]))
    batcher = RecordBatcher(sink, args["batch_rows"])
    counts: Counter = Counter()
    for rec, ln, off, raw, issue in _iter_doc(path, mapping, syn):
        batcher.add(rec, ln, off, raw, issue)
        counts[STREAM] += 1
    batcher.flush()
    st = sink.close()
    size = path.stat().st_size
    return {"part": "00-00000", "start": 0, "end": size, "bytes": size, "lines": F.count_lines_before(path, size),
            "lines_by_class": dict(counts), "stream": st, "issue_samples": sink.issue_samples, "samples": {},
            "secs": time.perf_counter() - t0}


# ── entry point ──────────────────────────────────────────────────────────────

def _iso(us: Optional[int]) -> Optional[str]:
    return None if us is None else datetime.fromtimestamp(us / 1e6, tz=timezone.utc).isoformat()


def _prepare_out(out: Path, overwrite: bool) -> None:
    old = [p for s in ("firewall", "windows") for p in (out / s).glob("part-*.parquet")]
    if old and not overwrite:
        raise FileExistsError(f"{out} already holds {len(old)} Parquet parts; pass overwrite=True to replace them")
    for p in old:
        p.unlink()
    out.mkdir(parents=True, exist_ok=True)


def parse_generic(path: Path, out: Path, mapping: Dict[str, Any], *, source_path: Optional[Path] = None,
                  workers: Optional[int] = None, chunk_mb: Optional[int] = None, batch_rows: int = 65536,
                  stuck_run: int = 1000, backwards_secs: int = 300, overwrite: bool = True,
                  synonyms_path: Optional[Path] = None, quiet: bool = False, summary: bool = True) -> Dict[str, Any]:
    """Parse `path` (plain, not compressed) with a fixed mapping into out/firewall/. Returns the _stats.json dict."""
    from .mapping import SYNONYMS_YAML

    syn_path = Path(synonyms_path or SYNONYMS_YAML)
    syn = load_synonyms(syn_path)
    _prepare_out(out, overwrite)
    workers = workers or max(1, min(14, (os.cpu_count() or 2) - 2))
    fmt = mapping["format"]
    size = path.stat().st_size
    monitor = MemoryMonitor()
    monitor.start()
    t0 = time.perf_counter()
    results: List[Dict[str, Any]] = []
    ranged = fmt in F.LINE_FORMATS or (fmt == "csv" and not mapping.get("multiline"))
    args = {"batch_rows": batch_rows, "stuck_run": stuck_run, "backwards_secs": backwards_secs}
    tasks_n = 1
    if ranged:
        start, base = 0, 1
        header: List[str] = []
        if fmt == "csv":
            with open(path, "rb") as f:
                first = f.readline()
            start, base = len(first), 2
            header = unique_header(F.csv_header(path, mapping.get("delimiter") or ","))
        # Ranges of about size / workers (8-64 MB), so a mid-sized file still uses every worker.
        top = CSV_MAX_RANGE if fmt == "csv" else 64 << 20
        chunk = chunk_mb << 20 if chunk_mb else min(top, max(8 << 20, (size - start) // workers + 1))
        ranges = plan_ranges(str(path), start, size, chunk) if size > start else []
        tasks = []
        for i, (a, b) in enumerate(ranges):
            tasks.append({"path": str(path), "source": path.name, "start": a, "end": b, "base_line": None,
                          "out": str(out), "part": f"00-{i:05d}", "mapping": mapping, "header": header,
                          "delimiter": mapping.get("delimiter") or ",", "synonyms": str(syn_path), **args})
        tasks_n = len(tasks)
        if len(tasks) <= 1:
            for t in tasks:
                t["base_line"] = base
                results.append(parse_range(t))
        else:
            with ProcessPoolExecutor(max_workers=min(workers, len(tasks))) as pool:
                counts = list(pool.map(count_newlines, [(str(path), a, b) for a, b in ranges]))
                for t, c in zip(tasks, counts):
                    t["base_line"] = base
                    base += c
                futs = [pool.submit(parse_range, t) for t in tasks]
                done = 0
                for fut in as_completed(futs):
                    r = fut.result()
                    results.append(r)
                    done += r["bytes"]
                    if not quiet:
                        print(f"[{path.name}] {100 * done / max(size, 1):5.1f}%  {time.perf_counter() - t0:7.1f} s",
                              file=sys.stderr, flush=True)
    else:
        results.append(_parse_single(path, out, mapping, args, syn))
    wall = time.perf_counter() - t0
    peak = monitor.stop()
    stats = _aggregate(results, path, source_path, size, wall, peak, workers if tasks_n > 1 else 1, mapping)
    if ranged and fmt == "csv":
        stats["lines"] += 1                       # the header line
        stats["lines_by_class"]["header"] = 1
    if summary:
        t1 = time.perf_counter()
        stats["summary"] = summarize(out)
        stats["summary_secs"] = round(time.perf_counter() - t1, 2)
    (out / "_stats.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    return stats


def _aggregate(results, path: Path, source_path: Optional[Path], size: int, wall: float, peak, workers: int,
               mapping: Dict[str, Any]) -> Dict[str, Any]:
    classes: Counter = Counter()
    q: Counter = Counter()
    iss: Counter = Counter()
    rows = 0
    lo = hi = None
    issue_samples: List[Dict[str, Any]] = []
    rejects: Dict[str, List[Dict[str, Any]]] = {}
    for r in sorted(results, key=lambda r: r["start"]):
        classes.update(r["lines_by_class"])
        st = r["stream"]
        rows += st["rows"]
        q.update(st["quality"])
        iss.update(st["issues"])
        if st["min_ok"] is not None:
            lo = st["min_ok"] if lo is None else min(lo, st["min_ok"])
            hi = st["max_ok"] if hi is None else max(hi, st["max_ok"])
        issue_samples += r["issue_samples"][: max(0, 10 - len(issue_samples))]
        for k, v in r["samples"].items():
            b = rejects.setdefault(k, [])
            b += v[: max(0, 10 - len(b))]
    lines = sum(r["lines"] for r in results)
    inp = {"path": str((source_path or path).resolve()), "size": (source_path or path).stat().st_size,
           "start": 0, "end": size, "first_line": 1, "tasks": len(results)}
    if source_path is not None and source_path != path:
        inp["decompressed"] = str(path.resolve())
    return {
        "parser": "generic", "format": mapping.get("format"), "schema_fingerprint": mapping.get("fingerprint"),
        "inputs": [inp], "workers": workers, "wall_secs": round(wall, 2),
        "worker_cpu_secs": round(sum(r["secs"] for r in results), 1),
        "bytes": size, "lines": lines, "mb_per_sec": round(size / max(wall, 1e-9) / 2**20, 1),
        "lines_per_sec": round(lines / max(wall, 1e-9)), "peak_rss_mb": None if peak is None else round(peak / 2**20),
        "lines_by_class": dict(classes.most_common()),
        "streams": {STREAM: {"rows": rows, "ts_quality": dict(q.most_common()), "parse_issues": dict(iss.most_common()),
                             "first_ok_utc": _iso(lo), "last_ok_utc": _iso(hi)}} if rows else {},
        "parse_issue_samples": {STREAM: issue_samples} if issue_samples else {},
        "junk_ranges": [], "junk_small": {"ranges": 0, "bytes": 0}, "unknown_keys": {}, "reject_samples": rejects,
    }
