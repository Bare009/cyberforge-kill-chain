"""Spot-check parser output against the source file.

For a random sample of rows: seek to byte_offset, read the line, and check that
(1) the line's hash matches line_hash, (2) the number of newlines before
byte_offset is line - 1, and (3) the typed columns match a naive re-parse.

usage: python tools/verify_parse.py PARSED_DIR [STREAM] [N]
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from pathlib import Path

import polars as pl

KV = re.compile(rb'([A-Za-z0-9_\-]+)=("(?:[^"\\]|\\.)*"|[^ ]*)')
FW_CHECK = {"srcip": "src_ip", "dstip": "dst_ip", "dstport": "dst_port", "action": "action", "type": "log_type",
            "subtype": "log_subtype", "user": "user", "url": "url", "msg": "msg", "sentbyte": "sent_bytes"}


def h(raw: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "little", signed=True)


def newlines_before(path: str, offset: int) -> int:
    n, pos = 0, 0
    with open(path, "rb") as f:
        while pos < offset:
            block = f.read(min(64 << 20, offset - pos))
            if not block:
                break
            n += block.count(b"\n")
            pos += len(block)
    return n


def main() -> None:
    out = Path(sys.argv[1])
    stream = sys.argv[2] if len(sys.argv) > 2 else "firewall"
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    stats = json.loads((out / "_stats.json").read_text(encoding="utf-8"))
    src = {Path(i["path"]).name: i["path"] for i in stats["inputs"]}
    df = pl.scan_parquet(str(out / stream / "part-*.parquet")).collect()
    rows = df.sample(min(n, df.height), seed=7).to_dicts()
    bad = 0
    with_lines = 0
    for r in rows:
        path = src[r["source"]]
        with open(path, "rb") as f:
            f.seek(r["byte_offset"])
            raw = f.readline().rstrip(b"\r\n")
        problems = []
        if h(raw) != r["line_hash"]:
            problems.append("hash")
        if stream == "firewall":
            d = {k.decode(): v.decode("utf-8", "replace").strip('"') for k, v in KV.findall(raw)}
            for k, col in FW_CHECK.items():
                want = d.get(k)
                got = r.get(col)
                if want is None and got is None:
                    continue
                if str(got) != (want.replace('\\"', '"') if want is not None else None):
                    problems.append(f"{col}: {got!r} != {want!r}")
        if with_lines < 5:  # newline counting reads the file prefix, so only a few
            with_lines += 1
            if newlines_before(path, r["byte_offset"]) != r["line"] - 1:
                problems.append("line number")
        if problems:
            bad += 1
            print("MISMATCH", r["line"], r["byte_offset"], problems[:3])
    print(f"checked {len(rows)} {stream} rows ({with_lines} with line-number recount): {bad} mismatches")


if __name__ == "__main__":
    main()
