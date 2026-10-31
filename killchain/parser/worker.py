"""Work done inside each worker process: count newlines, or parse one byte range.

A range always starts at a line start and ends just after a newline (or at EOF),
so ranges can be parsed independently. The caller passes the 1-based number of
the range's first line, which keeps `line` identical to the line numbers in the
organisers' ground-truth manifest.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pyarrow.parquet as pq

from . import arrowutil as au
from .fortigate import PREFIX as FG_PREFIX, FortiGateBatch
from .jsonlog import JsonBatch

READ_BLOCK = 16 << 20
SAMPLES_PER_REASON = 3
MIN_JUNK_RANGE = 64 << 10
_CTRL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def count_newlines(args: Tuple[str, int, int]) -> int:
    path, start, end = args
    n = 0
    buf = bytearray(READ_BLOCK)
    with open(path, "rb", buffering=0) as f:
        f.seek(start)
        left = end - start
        while left > 0:
            got = f.readinto(memoryview(buf)[: min(READ_BLOCK, left)])
            if not got:
                break
            n += buf.count(b"\n", 0, got)
            left -= got
    return n


def _hash(raw: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "little", signed=True)


class _Junk:
    """Coalesces consecutive rejected lines into byte ranges."""

    def __init__(self) -> None:
        self.ranges: List[List[int]] = []  # [start, end, lines]
        self.cur: Optional[List[int]] = None
        self.small_bytes = 0
        self.small_count = 0

    def add(self, offset: int, length: int) -> None:
        cur = self.cur
        if cur is not None and cur[1] == offset:
            cur[1] = offset + length
            cur[2] += 1
            return
        self._close()
        self.cur = [offset, offset + length, 1]

    def extend(self, offset: int, length: int) -> None:
        """A blank line right after junk belongs to the same junk range."""
        cur = self.cur
        if cur is not None and cur[1] == offset:
            cur[1] = offset + length

    def _close(self) -> None:
        if self.cur is None:
            return
        if self.cur[1] - self.cur[0] >= MIN_JUNK_RANGE:
            self.ranges.append(self.cur)
        else:
            self.small_bytes += self.cur[1] - self.cur[0]
            self.small_count += 1
        self.cur = None

    def result(self) -> Dict[str, Any]:
        self._close()
        return {"ranges": self.ranges, "small_ranges": self.small_count, "small_bytes": self.small_bytes}


def parse_range(task: Dict[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    path, start, end = task["path"], task["start"], task["end"]
    out_dir = Path(task["out"])
    part = task["part"]
    source = task["source"]
    batch_rows = task["batch_rows"]
    default_tz = task["default_tz"]

    batches = {"firewall": FortiGateBatch(), "windows": JsonBatch()}
    tqs = {s: au.TimeQuality(task["stuck_run"], task["backwards_secs"]) for s in batches}
    writers: Dict[str, pq.ParquetWriter] = {}
    unknown: Dict[str, Counter] = {s: Counter() for s in batches}
    streams: Dict[str, Dict[str, Any]] = {s: {"rows": 0, "quality": Counter(), "issues": Counter(),
                                              "min_ok": None, "max_ok": None} for s in batches}
    issue_samples: Dict[str, List[Dict[str, Any]]] = {}
    lines_by_class: Counter = Counter()
    samples: Dict[str, List[Dict[str, Any]]] = {}
    junk = _Junk()

    def flush(stream: str) -> None:
        b = batches[stream]
        if not len(b):
            return
        table, info = b.to_table(source, tqs[stream], default_tz)
        w = writers.get(stream)
        if w is None:
            (out_dir / stream).mkdir(parents=True, exist_ok=True)
            w = pq.ParquetWriter(out_dir / stream / f"part-{part}.parquet", b.schema,
                                 compression="zstd", compression_level=3)
            writers[stream] = w
        w.write_table(table)
        st = streams[stream]
        st["rows"] += table.num_rows
        st["quality"].update(info["quality"])
        if info.get("issues"):
            st["issues"].update(info["issues"])
            flagged = table.filter(table["parse_issue"].is_valid()).select(["line", "byte_offset", "parse_issue"])
            for r in flagged.slice(0, SAMPLES_PER_REASON).to_pylist():
                bucket = issue_samples.setdefault(stream, [])
                if len(bucket) < 10:
                    bucket.append(r)
        if "min_ok" in info:
            st["min_ok"] = info["min_ok"] if st["min_ok"] is None else min(st["min_ok"], info["min_ok"])
            st["max_ok"] = info["max_ok"] if st["max_ok"] is None else max(st["max_ok"], info["max_ok"])
        unknown[stream].update(b.unknown_keys)
        batches[stream] = type(b)()

    def reject(reason: str, raw: bytes, line_no: int, offset: int, length: int) -> None:
        lines_by_class["rejected:" + reason] += 1
        # +1 for the newline, except on a last line that has none
        junk.add(offset, min(length + 1, end - offset))
        bucket = samples.setdefault(reason, [])
        if len(bucket) < SAMPLES_PER_REASON:
            bucket.append({"line": line_no, "byte": offset, "head": repr(raw[:160])})

    def add_firewall(raw: bytes, line_no: int, offset: int) -> None:
        b = batches["firewall"]
        b.add(raw, line_no, offset, _hash(raw))
        lines_by_class["firewall"] += 1
        if len(b) >= batch_rows:
            flush("firewall")

    def add_json(obj: Dict[str, Any], raw: bytes, line_no: int, offset: int) -> None:
        b = batches["windows"]
        b.add(obj, line_no, offset, _hash(raw))
        lines_by_class["windows"] += 1
        if len(b) >= batch_rows:
            flush("windows")

    line_no = task["base_line"]
    offset = start
    carry = b""
    with open(path, "rb", buffering=0) as f:
        f.seek(start)
        left = end - start
        while left > 0:
            block = f.read(min(READ_BLOCK, left))
            if not block:  # file shorter than planned: treat as EOF
                left = 0
            left -= len(block)
            data = carry + block if carry else block
            if left > 0:
                cut = data.rfind(b"\n")
                if cut < 0:
                    carry = data
                    continue
                carry = data[cut + 1:]
                data = data[: cut + 1]
            else:
                carry = b""
            parts = data.split(b"\n")
            if data.endswith(b"\n"):
                parts.pop()
            for raw in parts:
                length = len(raw)
                if raw[-1:] == b"\r":
                    raw = raw[:-1]
                if raw.startswith(FG_PREFIX):
                    add_firewall(raw, line_no, offset)
                elif raw[:1] == b"{":
                    try:
                        obj = au.loads(raw)
                    except ValueError:
                        obj = None
                    if isinstance(obj, dict):
                        add_json(obj, raw, line_no, offset)
                    else:
                        reason = "binary" if not raw.isascii() or _CTRL.search(raw) else "bad_json"
                        reject(reason, raw, line_no, offset, length)
                elif not raw.strip():
                    lines_by_class["blank"] += 1
                    junk.extend(offset, min(length + 1, end - offset))
                else:
                    stripped = raw.lstrip(b" \t\xef\xbb\xbf")
                    if stripped is not raw and stripped.startswith(FG_PREFIX):
                        add_firewall(stripped, line_no, offset)
                    elif not raw.isascii() or _CTRL.search(raw):
                        reject("binary", raw, line_no, offset, length)
                    else:
                        reject("unknown_format", raw, line_no, offset, length)
                offset += length + 1
                line_no += 1
    for s in batches:
        flush(s)
    for w in writers.values():
        w.close()

    return {
        "part": part,
        "source": source,
        "start": start,
        "end": end,
        "first_line": task["base_line"],
        "lines": line_no - task["base_line"],
        "bytes": end - start,
        "lines_by_class": dict(lines_by_class),
        "streams": {s: {**v, "quality": dict(v["quality"]), "issues": dict(v["issues"])}
                    for s, v in streams.items() if v["rows"]},
        "issue_samples": issue_samples,
        "unknown_keys": {s: dict(c) for s, c in unknown.items() if c},
        "samples": samples,
        "junk": junk.result(),
        "secs": time.perf_counter() - t0,
        "pid": os.getpid(),
    }
