"""Query a parsed run from the command line, for writing and tuning rules.

Examples (PowerShell):
  python tools\\explore.py data\\parsed\\firex-10G --where "log_desc = 'Admin login successful'" --cols ts_ist,src_ip,user,src_country
  python tools\\explore.py data\\parsed\\firex-10G --where "log_desc = 'Admin login failed'" --group src_ip --top 10
  python tools\\explore.py data\\parsed\\firex-10G --around "2026-10-29 01:51:00" --minutes 5 --where "src_ip = '32.127.48.11'"
  python tools\\explore.py data\\parsed\\firex-10G --distinct log_desc
  python tools\\explore.py data\\parsed\\firex-10G --sql "SELECT src_zone, count(*) FROM events WHERE ts_valid GROUP BY 1"
  python tools\\explore.py data\\parsed\\firex-10G --where "src_ip = '15.199.16.197'" --raw 3

`--around` takes an IST time. Only ts_valid rows are used unless --all is given.
`--raw N` prints the raw log text of the first N matching rows (read at byte_offset).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from killchain import db  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parsed", help="parsed run folder")
    ap.add_argument("--table", default="events", help="events (default), firewall_events or windows_events")
    ap.add_argument("--where", help="SQL condition")
    ap.add_argument("--cols", help="comma-separated columns (default: a useful set)")
    ap.add_argument("--group", help="comma-separated columns to group by; prints counts")
    ap.add_argument("--top", type=int, default=20, help="rows to print (default 20)")
    ap.add_argument("--distinct", help="print distinct values of one column with counts")
    ap.add_argument("--around", help="IST time 'YYYY-MM-DD HH:MM:SS' to centre on")
    ap.add_argument("--minutes", type=float, default=10, help="window half-width for --around")
    ap.add_argument("--sql", help="run raw SQL instead")
    ap.add_argument("--raw", type=int, default=0, help="print raw lines of the first N matches")
    ap.add_argument("--all", action="store_true", help="include rows that are not ts_valid")
    ap.add_argument("--json", action="store_true", help="print rows as JSON lines")
    a = ap.parse_args()

    t0 = time.perf_counter()
    con = db.open_run(a.parsed)
    if a.sql:
        rel = con.sql(a.sql)
    else:
        conds = [] if a.all else ["ts_valid"]
        if a.where:
            conds.append(f"({a.where})")
        if a.around:
            conds.append(f"ts_ist BETWEEN TIMESTAMP '{a.around}' - INTERVAL {int(a.minutes * 60)} SECOND "
                         f"AND TIMESTAMP '{a.around}' + INTERVAL {int(a.minutes * 60)} SECOND")
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        if a.distinct:
            sql = f"SELECT {a.distinct}, count(*) AS n FROM {a.table}{where} GROUP BY 1 ORDER BY n DESC"
        elif a.group:
            sql = (f"SELECT {a.group}, count(*) AS n, min(ts_ist) AS first_ist, max(ts_ist) AS last_ist "
                   f"FROM {a.table}{where} GROUP BY {a.group} ORDER BY n DESC")
        else:
            cols = a.cols or ("line, ts_ist, log_type, log_subtype, action, src_ip, src_port, dst_ip, dst_port, "
                              "user, log_desc, attack, url, sent_bytes, rcvd_bytes")
            if a.raw:
                cols += ", source, byte_offset"
            sql = f"SELECT {cols} FROM {a.table}{where} ORDER BY line"
        rel = con.sql(sql)
    if a.json:
        names = rel.columns
        for row in rel.limit(a.top).fetchall():
            print(json.dumps(dict(zip(names, row)), default=str, ensure_ascii=False))
    else:
        rel.limit(a.top).show(max_width=250, max_rows=a.top)
    if a.raw and not a.sql and not a.group and not a.distinct:
        stats = json.loads((Path(a.parsed) / "_stats.json").read_text(encoding="utf-8"))
        paths = {Path(i["path"]).name: i["path"] for i in stats["inputs"]}
        for source, off in rel.limit(a.raw).select("source, byte_offset").fetchall():
            with open(paths[source], "rb") as f:
                f.seek(off)
                print(f.readline().rstrip(b"\r\n").decode("utf-8", "replace"))
    print(f"({time.perf_counter() - t0:.2f} s)", file=sys.stderr)


if __name__ == "__main__":
    main()
