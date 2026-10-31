"""Independent audit of a parser run on a FortiGate log.

Does not reuse the parser's tokenizer or time code. Checks:
  1. completeness: an independent full-file scan counts every line and every
     line that starts with `date=`, and compares with the parser's counts;
  2. positions: line numbers are unique and contiguous, offsets increase;
  3. fields: a random sample of rows is re-read from the raw file at
     byte_offset and every typed column is compared with a hand-written
     tokenizer's result;
  4. time: ts is recomputed from date/time/tz/eventtime; stuck flags are
     compared with the frozen eventtime value over the whole table.

usage: python tools/audit_parse.py RAW_LOG PARSED_DIR [SAMPLE] [OUT_JSON]
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from killchain.parser.fortigate import FIELDS  # column names only, not the tokenizer

INT_RE = re.compile(r"^-?\d+$")
INT64_MAX = 2**63 - 1
STUCK_ET = 1793350105999999000


def tokenize(line: bytes) -> tuple[dict, int, int]:
    """Hand-written key=value scanner. Returns (pairs, stray_tokens, duplicate_keys)."""
    out: dict = {}
    stray = dups = 0
    i, n = 0, len(line)
    while i < n:
        while i < n and line[i] == 0x20:
            i += 1
        if i >= n:
            break
        j = i
        while j < n and line[j] not in (0x20, 0x3D):
            j += 1
        if j >= n or line[j] != 0x3D:
            stray += 1
            while j < n and line[j] != 0x20:
                j += 1
            i = j
            continue
        key = line[i:j].decode("ascii", "replace")
        j += 1
        if j < n and line[j] == 0x22:
            k = j + 1
            buf = bytearray()
            while k < n:
                c = line[k]
                if c == 0x5C and k + 1 < n and line[k + 1] == 0x22:
                    buf += b'"'
                    k += 2
                    continue
                if c == 0x22:
                    break
                buf.append(c)
                k += 1
            val = bytes(buf)
            i = k + 1
        else:
            k = j
            while k < n and line[k] != 0x20:
                k += 1
            val = line[j:k]
            i = k
        if key in out:
            dups += 1
        out[key] = val.decode("utf-8", "replace")
    return out, stray, dups


def expected_int(v):
    if v is None or not INT_RE.match(v):
        return None
    x = int(v)
    return x if abs(x) <= INT64_MAX else None


def scan_file(path: str) -> dict:
    """One pass: newlines, lines starting with date=, first non-text byte region."""
    t0 = time.perf_counter()
    newlines = date_lines = 0
    size = 0
    last = b""
    first_date = None
    with open(path, "rb", buffering=0) as f:
        head = f.read(5)
        date_lines += head == b"date="
        f.seek(0)
        prev_tail = b""
        while True:
            block = f.read(64 << 20)
            if not block:
                break
            size += len(block)
            newlines += block.count(b"\n")
            joined = prev_tail + block
            date_lines += joined.count(b"\ndate=")
            prev_tail = block[-5:]
            last = block[-1:]
    lines = newlines + (1 if last and last != b"\n" else 0)
    return {"bytes": size, "lines": lines, "ends_with_newline": last == b"\n",
            "lines_starting_date": date_lines, "secs": round(time.perf_counter() - t0, 1)}


def main() -> None:
    raw, parsed = sys.argv[1], Path(sys.argv[2])
    n_sample = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
    out_json = Path(sys.argv[4]) if len(sys.argv) > 4 else parsed / "_audit.json"
    stats = json.loads((parsed / "_stats.json").read_text(encoding="utf-8"))
    lf = pl.scan_parquet(str(parsed / "firewall" / "*.parquet"))
    report: dict = {}

    # 1. completeness
    scan = scan_file(raw)
    cls = stats["lines_by_class"]
    report["completeness"] = {
        "independent_scan": scan,
        "parser_lines_total": stats["lines"],
        "parser_firewall_rows": cls.get("firewall", 0),
        "lines_total_match": scan["lines"] == stats["lines"],
        "date_lines_match": scan["lines_starting_date"] == cls.get("firewall", 0),
        "accounted": sum(cls.values()),
    }
    print("1 completeness:", report["completeness"])

    # 2. positions over the whole table
    pos = (lf.select("line", "byte_offset", "line_hash").sort("line")
           .select(pl.len().alias("rows"), pl.col("line").n_unique().alias("unique_lines"),
                   pl.col("line").min().alias("min_line"), pl.col("line").max().alias("max_line"),
                   (pl.col("line").diff() != 1).sum().alias("line_gaps"),
                   (pl.col("byte_offset").diff() <= 0).sum().alias("offset_not_increasing"),
                   pl.col("byte_offset").diff().min().alias("min_step"),
                   pl.col("byte_offset").diff().max().alias("max_step"),
                   pl.col("line_hash").n_unique().alias("unique_hashes"))).collect().to_dicts()[0]
    report["positions"] = pos
    print("2 positions:", pos)

    # 4a. time flags over the whole table
    tq = (lf.group_by((pl.col("event_time_raw") == STUCK_ET).alias("frozen_eventtime"), "ts_quality")
          .agg(pl.len().alias("rows")).sort("rows").collect().to_dicts())
    ok = lf.filter(pl.col("ts_quality") == "ok").sort("line")
    order = ok.select((pl.col("ts").diff().dt.total_seconds() < -300).sum().alias("jumps_back_over_5min"),
                      (pl.col("ts").diff().dt.total_seconds() < 0).sum().alias("any_step_back"),
                      pl.col("ts").min().alias("first"), pl.col("ts").max().alias("last")).collect().to_dicts()[0]
    report["time_flags"] = {"by_flag": tq, "ok_region_order": {k: str(v) for k, v in order.items()}}
    print("4a time flags:", report["time_flags"])

    # 5. rows the parser flagged, and the junk range against the file size
    flagged = (lf.filter(pl.col("parse_issue").is_not_null())
               .select("line", "byte_offset", "ts_quality", "parse_issue", "extra").collect().to_dicts())
    junk_end = max((j["end"] for j in stats.get("junk_ranges", [])), default=None)
    report["flags"] = {"flagged_rows": flagged[:50], "flagged_count": len(flagged),
                       "junk_end": junk_end, "junk_end_within_file": junk_end is None or junk_end <= scan["bytes"]}
    print("5 flags:", {k: v for k, v in report["flags"].items() if k != "flagged_rows"}, flagged[:3])

    # 3 + 4b. sample re-read
    rows_total = pos["rows"]
    random.seed(11)
    lines = set(random.sample(range(pos["min_line"], pos["max_line"] + 1), min(n_sample, rows_total)))
    sample = lf.filter(pl.col("line").is_in(list(lines))).collect().to_dicts()
    src = {Path(i["path"]).name: i["path"] for i in stats["inputs"]}
    cols = [(k, name, kind) for k, name, kind in FIELDS]
    field_checks = field_bad = 0
    per_col_bad: Counter = Counter()
    bad_examples: list = []
    hash_bad = start_bad = ts_bad = sub_bad = 0
    present: Counter = Counter()
    lost_numeric = stray_total = dup_total = unknown_keys = 0
    t0 = time.perf_counter()
    handles = {}
    for r in sample:
        fh = handles.setdefault(r["source"], open(src[r["source"]], "rb"))
        fh.seek(max(r["byte_offset"] - 1, 0))
        prev = fh.read(1) if r["byte_offset"] else b"\n"
        rawline = fh.readline().rstrip(b"\r\n")
        if prev != b"\n":
            start_bad += 1
        if int.from_bytes(hashlib.blake2b(rawline, digest_size=8).digest(), "little", signed=True) != r["line_hash"]:
            hash_bad += 1
        if r.get("parse_issue"):  # damaged lines are checked in section 5, not field by field
            continue
        d, stray, dups = tokenize(rawline)
        stray_total += stray
        dup_total += dups
        known = {k for k, _, _ in cols} | {"date", "time", "tz", "eventtime"}
        unknown_keys += len(set(d) - known)
        for key, name, kind in cols:
            v = d.get(key)
            if v is not None:
                present[name] += 1
            exp = expected_int(v) if kind == "int" else v
            if kind == "int" and v not in (None, "") and exp is None:
                lost_numeric += 1
            got = r[name]
            field_checks += 1
            if got != exp:
                field_bad += 1
                per_col_bad[name] += 1
                if len(bad_examples) < 10:
                    bad_examples.append({"line": r["line"], "column": name, "parsed": got, "raw": v})
        # time
        try:
            local = datetime.strptime(d["date"] + " " + d["time"], "%Y-%m-%d %H:%M:%S")
            tz = d.get("tz", "+0000")
            off = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (1 if tz[0] == "+" else -1)
            exp_sec = (local - off).replace(tzinfo=timezone.utc)
            got_ts = r["ts"]
            if got_ts is None or got_ts.replace(microsecond=0) != exp_sec:
                ts_bad += 1
            et = int(d["eventtime"])
            if got_ts is not None and got_ts.microsecond != (et // 1000) % 1_000_000:
                sub_bad += 1
        except (KeyError, ValueError):
            ts_bad += 1
    for fh in handles.values():
        fh.close()
    n = len(sample)
    report["sample"] = {
        "rows": n, "secs": round(time.perf_counter() - t0, 1),
        "line_start_wrong": start_bad, "hash_mismatch": hash_bad,
        "field_checks": field_checks, "field_mismatches": field_bad,
        "field_accuracy_pct": round(100 * (field_checks - field_bad) / max(field_checks, 1), 4),
        "mismatches_by_column": dict(per_col_bad.most_common()), "mismatch_examples": bad_examples,
        "ts_second_mismatch": ts_bad, "ts_subsecond_mismatch": sub_bad,
        "numeric_values_not_numbers": lost_numeric, "stray_tokens": stray_total,
        "duplicate_keys": dup_total, "keys_without_a_column": unknown_keys,
    }
    print("3 sample:", {k: v for k, v in report["sample"].items() if k != "mismatch_examples"})
    if bad_examples:
        print("   examples:", bad_examples[:5])

    # analysis of what was parsed (ok region)
    okc = lf.filter(pl.col("ts_quality") == "ok")
    nn = okc.select([pl.col(c).is_not_null().sum().alias(c) for _, c, _ in cols] + [pl.len().alias("_rows")]).collect().to_dicts()[0]
    nu = okc.select([pl.col(c).approx_n_unique().alias(c) for _, c, _ in cols]).collect().to_dicts()[0]
    report["columns_ok_region"] = {c: {"filled": nn[c], "filled_pct": round(100 * nn[c] / nn["_rows"], 2), "distinct_approx": nu[c]}
                                   for _, c, _ in cols}
    mix = okc.group_by("log_type", "log_subtype", "log_id").agg(pl.len().alias("rows")).sort("rows", descending=True).collect()
    report["event_mix_ok_region"] = mix.to_dicts()
    per_day = (okc.group_by(pl.col("ts").dt.offset_by("5h30m").dt.date().alias("ist_day")).agg(pl.len().alias("rows"))
               .sort("ist_day").collect())
    report["rows_per_ist_day"] = [{"day": str(r["ist_day"]), "rows": r["rows"]} for r in per_day.to_dicts()]
    report["performance"] = {"wall_secs": stats["wall_secs"], "peak_rss_mb": stats["peak_rss_mb"],
                             "mb_per_sec": stats["mb_per_sec"], "workers": stats["workers"]}
    out_json.write_text(json.dumps(report, indent=1, default=str, ensure_ascii=False), encoding="utf-8")
    print("written", out_json)


if __name__ == "__main__":
    main()
