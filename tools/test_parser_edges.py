"""Parse a small hand-made file with every edge case and check the results.

usage: python tools/test_parser_edges.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
HEAD = (b'date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" '
        b'devname="FGT" devid="FGT" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" ')

LINES = [
    HEAD + b'srcip=10.0.0.1 dstport=443 action="accept"',                         # 1 clean
    HEAD + b'srcip=10.0.0.2 dstport=abc action="accept"',                         # 2 bad number
    HEAD + b'srcip=10.0.0.3 srcip=10.0.0.9 action="accept"',                      # 3 duplicate key
    HEAD + b'srcip=10.0.0.4 garbage action="accept"',                             # 4 stray text
    HEAD + b'srcip=10.0.0.5 srccountry="T\xc3\xbcrkiye" action="accept"',          # 5 valid UTF-8, no issue
    HEAD + b'srcip=10.0.0.6  action="accept"',                                    # 6 double space, no issue
    HEAD + b'srcip=10.0.0.7 srcintfrole="lan" \xd9\x81\xde\xd1wW\x050\xd1\x9f',    # 7 cut off by binary bytes
    b"\xba\xf7\x14\xbcn\x9c\xec",                                                 # 8 binary line, rejected
    b"",                                                                          # 9 blank
    b"\x01\x02junk",                                                              # 10 binary, last line, no newline
]
EXPECT = {
    1: (None, {"src_ip": "10.0.0.1", "dst_port": 443}),
    2: ("bad_number", {"src_ip": "10.0.0.2", "dst_port": None}),
    3: ("duplicate_key", {"src_ip": "10.0.0.9"}),
    4: ("stray_text", {"src_ip": "10.0.0.4", "action": "accept"}),
    5: (None, {"src_country": "Türkiye"}),
    6: (None, {"src_ip": "10.0.0.6", "action": "accept"}),
    7: ("truncated_binary_tail", {"src_ip": "10.0.0.7", "src_intf_role": "lan"}),
}
EXTRA = {2: "_bad_dst_port", 3: "_dup_srcip", 4: "_stray", 7: "_dropped_bytes"}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "edges.log"
        log.write_bytes(b"\n".join(LINES))
        out = Path(tmp) / "out"
        subprocess.run([sys.executable, "-m", "killchain.parser", str(log), "--out", str(out), "--workers", "1",
                        "--no-summary"], cwd=ROOT, check=True, capture_output=True)
        stats = json.loads((out / "_stats.json").read_text(encoding="utf-8"))
        rows = {r["line"]: r for r in pl.read_parquet(str(out / "firewall" / "*.parquet")).to_dicts()}
        fails = []
        for line, (issue, cols) in EXPECT.items():
            r = rows.get(line)
            if r is None:
                fails.append(f"line {line}: missing")
                continue
            if r["parse_issue"] != issue:
                fails.append(f"line {line}: parse_issue {r['parse_issue']!r} != {issue!r}")
            for c, v in cols.items():
                if r[c] != v:
                    fails.append(f"line {line}: {c} {r[c]!r} != {v!r}")
            if line in EXTRA and EXTRA[line] not in json.loads(r["extra"] or "{}"):
                fails.append(f"line {line}: extra lacks {EXTRA[line]}")
        if set(rows) != set(EXPECT):
            fails.append(f"rows {sorted(rows)} != {sorted(EXPECT)}")
        # Lines 8-10 are one junk run that ends at the end of the file (no trailing newline).
        size = log.stat().st_size
        junk_start = sum(len(x) + 1 for x in LINES[:7])
        small = stats["junk_small"]
        if small != {"ranges": 1, "bytes": size - junk_start}:
            fails.append(f"junk {small} != one range of {size - junk_start} bytes ending at file size {size}")
        if stats["lines"] != len(LINES):
            fails.append(f"lines {stats['lines']} != {len(LINES)}")
        print("FAIL\n  " + "\n  ".join(fails) if fails else f"all {len(EXPECT)} row checks and the file checks passed")
        sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
