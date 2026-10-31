"""python -m killchain.parser: stream raw log files into Parquet.

The file is split into byte ranges that start on line boundaries. A first
parallel pass counts newlines per range so every row gets its true 1-based line
number; a second pass parses the ranges in worker processes. No process ever
holds more than one read block plus one row batch, so memory stays flat no
matter how large the input is.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .arrowutil import parse_tz
from .worker import count_newlines, parse_range

STREAMS = ("firewall", "windows")


def parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="python -m killchain.parser",
        description="Parse FortiGate key=value and JSON-lines logs into Parquet, without loading files into memory.",
    )
    ap.add_argument("inputs", nargs="+", help="log files (each may mix FortiGate and JSON lines)")
    ap.add_argument("--out", required=True, help="output folder; gets firewall/ and windows/ Parquet parts")
    ap.add_argument("--workers", type=int, default=max(1, min(14, (os.cpu_count() or 2) - 2)))
    ap.add_argument("--chunk-mb", type=int, default=128, help="bytes per parse task (default 128 MB)")
    ap.add_argument("--batch-rows", type=int, default=65536, help="rows per Parquet row group")
    ap.add_argument("--start", type=int, default=0, help="first byte to parse; moved forward to a line start")
    ap.add_argument("--end", type=int, default=None, help="stop at this byte; moved forward to a line end")
    ap.add_argument("--max-mb", type=float, default=None, help="parse at most this many MB after --start")
    ap.add_argument("--assume-tz", default="+00:00", help="zone for timestamps that carry none (e.g. +05:30)")
    ap.add_argument("--stuck-run", type=int, default=1000,
                    help="identical consecutive timestamps that mark a stuck clock")
    ap.add_argument("--backwards-secs", type=int, default=300,
                    help="flag rows older than the newest good row by more than this")
    ap.add_argument("--overwrite", action="store_true", help="replace parts left by an earlier run")
    ap.add_argument("--no-summary", action="store_true", help="skip the Parquet summary after parsing")
    return ap.parse_args(argv)


# ── byte ranges ──────────────────────────────────────────────────────────────

def next_line_start(f, pos: int, size: int) -> int:
    """Smallest offset >= pos that starts a line (0, or the byte after a newline)."""
    if pos <= 0:
        return 0
    if pos >= size:
        return size
    f.seek(pos - 1)
    scanned = pos - 1
    while True:
        buf = f.read(1 << 20)
        if not buf:
            return size
        i = buf.find(b"\n")
        if i >= 0:
            return scanned + i + 1
        scanned += len(buf)


def plan_ranges(path: str, start: int, end: int, chunk: int) -> List[Tuple[int, int]]:
    size = os.path.getsize(path)
    bounds = [start]
    with open(path, "rb") as f:
        pos = start + chunk
        while pos < end:
            nxt = next_line_start(f, pos, size)
            if nxt >= end:
                break
            if nxt > bounds[-1]:
                bounds.append(nxt)
            pos = nxt + chunk
    if end > bounds[-1]:
        bounds.append(end)
    return list(zip(bounds[:-1], bounds[1:]))


# ── memory ───────────────────────────────────────────────────────────────────

class MemoryMonitor(threading.Thread):
    """Samples the summed RSS of this process and its workers."""

    def __init__(self, interval: float = 0.2) -> None:
        super().__init__(daemon=True)
        self.interval = interval
        self.peak = 0
        self._halt = threading.Event()
        try:
            import psutil

            self._psutil = psutil
            self._me = psutil.Process()
        except ImportError:
            self._psutil = None

    def run(self) -> None:
        if self._psutil is None:
            return
        err = self._psutil.Error
        while not self._halt.is_set():
            try:
                procs = [self._me] + self._me.children(recursive=True)
            except err:
                procs = [self._me]
            total = 0
            for p in procs:
                try:
                    total += p.memory_info().rss
                except err:
                    pass
            self.peak = max(self.peak, total)
            self._halt.wait(self.interval)

    def stop(self) -> Optional[int]:
        self._halt.set()
        self.join(timeout=2)
        return self.peak if self._psutil is not None else None


# ── output ───────────────────────────────────────────────────────────────────

def prepare_out(out: Path, overwrite: bool) -> None:
    old = [p for s in STREAMS for p in (out / s).glob("part-*.parquet")]
    if old and not overwrite:
        sys.exit(f"{out} already holds {len(old)} Parquet parts; pass --overwrite to replace them")
    for p in old:
        p.unlink()
    out.mkdir(parents=True, exist_ok=True)


def _iso(us: Optional[int]) -> Optional[str]:
    if us is None:
        return None
    return datetime.fromtimestamp(us / 1e6, tz=timezone.utc).isoformat()


def aggregate(results: List[Dict[str, Any]], files: List[Dict[str, Any]], wall: float,
              peak: Optional[int], args: argparse.Namespace) -> Dict[str, Any]:
    results.sort(key=lambda r: (r["source"], r["start"]))
    classes: Counter = Counter()
    streams: Dict[str, Dict[str, Any]] = {}
    unknown: Dict[str, Counter] = {}
    samples: Dict[str, List[Dict[str, Any]]] = {}
    junk: List[List[Any]] = []
    small = {"ranges": 0, "bytes": 0}
    for r in results:
        classes.update(r["lines_by_class"])
        for s, v in r["streams"].items():
            st = streams.setdefault(s, {"rows": 0, "quality": Counter(), "min_ok": None, "max_ok": None})
            st["rows"] += v["rows"]
            st["quality"].update(v["quality"])
            for k, pick in (("min_ok", min), ("max_ok", max)):
                if v[k] is not None:
                    st[k] = v[k] if st[k] is None else pick(st[k], v[k])
        for s, c in r["unknown_keys"].items():
            unknown.setdefault(s, Counter()).update(c)
        for reason, items in r["samples"].items():
            bucket = samples.setdefault(reason, [])
            bucket.extend(items[: max(0, 10 - len(bucket))])
        for a, b, n in r["junk"]["ranges"]:
            if junk and junk[-1][0] == r["source"] and junk[-1][2] == a:
                junk[-1][2] = b
                junk[-1][3] += n
            else:
                junk.append([r["source"], a, b, n])
        small["ranges"] += r["junk"]["small_ranges"]
        small["bytes"] += r["junk"]["small_bytes"]
    total_bytes = sum(r["bytes"] for r in results)
    total_lines = sum(r["lines"] for r in results)
    return {
        "inputs": files,
        "workers": args.workers,
        "chunk_mb": args.chunk_mb,
        "wall_secs": round(wall, 2),
        "worker_cpu_secs": round(sum(r["secs"] for r in results), 1),
        "bytes": total_bytes,
        "lines": total_lines,
        "mb_per_sec": round(total_bytes / max(wall, 1e-9) / 2**20, 1),
        "lines_per_sec": round(total_lines / max(wall, 1e-9)),
        "peak_rss_mb": None if peak is None else round(peak / 2**20),
        "lines_by_class": dict(classes.most_common()),
        "streams": {
            s: {"rows": v["rows"], "ts_quality": dict(v["quality"].most_common()),
                "first_ok_utc": _iso(v["min_ok"]), "last_ok_utc": _iso(v["max_ok"])}
            for s, v in streams.items()
        },
        "junk_ranges": [{"source": s, "start": a, "end": b, "bytes": b - a, "lines": n} for s, a, b, n in junk][:200],
        "junk_small": small,
        "unknown_keys": {s: dict(c.most_common(100)) for s, c in unknown.items()},
        "reject_samples": samples,
    }


def summarize(out: Path) -> Dict[str, Any]:
    """Row counts, exact duplicates and the event mix, read back from the Parquet parts."""
    import polars as pl

    res: Dict[str, Any] = {}
    for stream in STREAMS:
        parts = sorted(str(p) for p in (out / stream).glob("part-*.parquet"))
        if not parts:
            continue
        lf = pl.scan_parquet(parts)
        dup = (lf.group_by("line_hash").len().filter(pl.col("len") > 1)
               .select((pl.col("len") - 1).sum()).collect().item())
        keys = ["log_type", "log_subtype"] if stream == "firewall" else ["event_id", "event_category", "event_action"]
        kinds = (lf.filter(pl.col("ts_quality") != "stuck").group_by(keys).len()
                 .sort("len", descending=True).head(25).collect())
        res[stream] = {
            "rows": lf.select(pl.len()).collect().item(),
            "exact_duplicate_rows": int(dup or 0),
            "event_mix_excluding_stuck": [dict(zip(keys + ["rows"], row)) for row in kinds.rows()],
        }
    return res


# ── main ─────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    inputs = [Path(p) for p in args.inputs]
    for p in inputs:
        if not p.is_file():
            sys.exit(f"not a file: {p}")
    if len(inputs) > 1 and (args.start or args.end is not None or args.max_mb):
        sys.exit("--start, --end and --max-mb need exactly one input file")
    out = Path(args.out)
    prepare_out(out, args.overwrite)
    default_tz = parse_tz(args.assume_tz, 0)

    monitor = MemoryMonitor()
    monitor.start()
    t0 = time.perf_counter()
    results: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for fi, path in enumerate(inputs):
            size = path.stat().st_size
            with open(path, "rb") as f:
                start = next_line_start(f, args.start, size)
                end = size if args.end is None else next_line_start(f, min(args.end, size), size)
                if args.max_mb:
                    end = min(end, next_line_start(f, start + int(args.max_mb * 2**20), size))
            ranges = plan_ranges(str(path), start, end, args.chunk_mb << 20)
            prefix = plan_ranges(str(path), 0, start, args.chunk_mb << 20) if start else []
            counts = list(pool.map(count_newlines, [(str(path), a, b) for a, b in prefix + ranges]))
            base = 1 + sum(counts[: len(prefix)])
            files.append({"path": str(path.resolve()), "size": size, "start": start, "end": end,
                          "first_line": base, "tasks": len(ranges)})
            tasks = []
            for i, ((a, b), c) in enumerate(zip(ranges, counts[len(prefix):])):
                tasks.append({
                    "path": str(path), "source": path.name, "start": a, "end": b, "base_line": base,
                    "out": str(out), "part": f"{fi:02d}-{i:05d}", "batch_rows": args.batch_rows,
                    "default_tz": default_tz, "stuck_run": args.stuck_run, "backwards_secs": args.backwards_secs,
                })
                base += c
            total = max(end - start, 1)
            done, next_mark = 0, 0.1
            for fut in as_completed([pool.submit(parse_range, t) for t in tasks]):
                r = fut.result()
                results.append(r)
                done += r["bytes"]
                if done / total >= next_mark or done == total:
                    el = time.perf_counter() - t0
                    print(f"[{path.name}] {100 * done / total:5.1f}%  {done / 2**30:6.2f} GiB  {el:7.1f} s  "
                          f"peak RSS {monitor.peak / 2**20:7.0f} MB", file=sys.stderr, flush=True)
                    while next_mark <= done / total:
                        next_mark += 0.1
    wall = time.perf_counter() - t0
    peak = monitor.stop()

    stats = aggregate(results, files, wall, peak, args)
    if not args.no_summary:
        t1 = time.perf_counter()
        stats["summary"] = summarize(out)
        stats["summary_secs"] = round(time.perf_counter() - t1, 2)
    (out / "_stats.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False), encoding="utf-8")

    print(f"parsed {stats['bytes'] / 2**30:.2f} GiB, {stats['lines']:,} lines in {stats['wall_secs']} s "
          f"({stats['mb_per_sec']} MB/s, {stats['lines_per_sec']:,} lines/s), workers={args.workers}, "
          f"peak RSS {stats['peak_rss_mb']} MB")
    print("lines:", ", ".join(f"{k}={v:,}" for k, v in stats["lines_by_class"].items()))
    for s, v in stats["streams"].items():
        print(f"{s}: rows={v['rows']:,} ts_quality={v['ts_quality']} good time range "
              f"{v['first_ok_utc']} .. {v['last_ok_utc']}")
    if stats["junk_ranges"]:
        top = sorted(stats["junk_ranges"], key=lambda j: -j["bytes"])[:3]
        print("largest junk ranges:", "; ".join(f"{j['source']} bytes {j['start']:,}-{j['end']:,} "
                                                f"({j['bytes'] / 2**20:.1f} MB)" for j in top))
    print(f"stats: {out / '_stats.json'}")


if __name__ == "__main__":
    main()
