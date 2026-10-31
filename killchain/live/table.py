"""The live window: an in-memory DuckDB holding the last `window_hours` of events.

The tables have exactly the columns of a prepared events.duckdb (parser columns, src_ip_int /
dst_ip_int and every derived column of db.py), so every rule runs unchanged. New rows get their
derived columns once, on insert, through db.derived_select; rules then read a plain table, which
is about 5x faster than the parquet views.

Retention is by event time, not wall time (a replayed log carries its own timestamps): rows with a
valid ts older than the newest valid ts minus the window go, and so do rows without a valid ts
whose line comes before the first line still kept. max_rows then caps the table by dropping the
lowest line numbers.

Every statement is fetched to the end: DuckDB refuses register() and sql() on a connection that
still has an unfinished result.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

import duckdb
import pyarrow as pa

from .. import db
from ..parser.fortigate import SCHEMA as FW_SCHEMA
from ..parser.jsonlog import SCHEMA as WIN_SCHEMA

STREAMS = {"firewall": ("firewall_events", FW_SCHEMA), "windows": ("windows_events", WIN_SCHEMA)}


class LiveTable:
    def __init__(self, net: Optional[Dict[str, Any]] = None, memory_limit: Optional[str] = None,
                 threads: Optional[int] = None) -> None:
        self.net = net or db.load_network()
        self.con = duckdb.connect(":memory:")
        db.configure(self.con, memory_limit=memory_limit, threads=threads)
        for stream, (table, schema) in STREAMS.items():
            self.con.register("_empty", schema.empty_table())
            self._run(f"CREATE TABLE {table} AS {db.derived_select('_empty', self.net)}")
            self.con.unregister("_empty")
        self._run("CREATE VIEW events AS SELECT * FROM firewall_events")

    def _run(self, sql: str, params: Optional[Sequence[Any]] = None) -> List[tuple]:
        return self.con.execute(sql, params or []).fetchall()

    def _one(self, sql: str, params: Optional[Sequence[Any]] = None) -> Optional[tuple]:
        rows = self._run(sql, params)
        return rows[0] if rows else None

    def _union(self, cols: str) -> str:
        return " UNION ALL ".join(f"SELECT {cols} FROM {t}" for t, _ in STREAMS.values())

    def append(self, tables: Dict[str, pa.Table]) -> Dict[str, int]:
        added: Dict[str, int] = {}
        for stream, t in tables.items():
            if t is None or not t.num_rows:
                continue
            table = STREAMS[stream][0]
            self.con.register("_new", t)
            try:
                self._run(f"INSERT INTO {table} BY NAME {db.derived_select('_new', self.net)}")
            finally:
                self.con.unregister("_new")
            added[stream] = t.num_rows
        return added

    def trim(self, window_s: int, max_rows: int) -> int:
        """Drop rows outside the window (event time) and over the cap; returns rows dropped."""
        before = self.rows()
        if not before:
            return 0
        newest = self._one(f"SELECT max(ts_utc) FROM ({self._union('ts_utc, ts_valid')}) WHERE ts_valid")[0]
        if newest is not None:
            for table, _ in STREAMS.values():
                self._run(f"DELETE FROM {table} WHERE ts_valid AND ts_utc < "
                          f"CAST(? AS TIMESTAMP) - INTERVAL {int(window_s)} SECOND", [newest])
            first_kept = self._one(f"SELECT min(line) FROM ({self._union('line, ts_valid')}) WHERE ts_valid")[0]
            if first_kept is not None:
                for table, _ in STREAMS.values():
                    self._run(f"DELETE FROM {table} WHERE NOT ts_valid AND line < ?", [first_kept])
        if self.rows() > max_rows:
            cut = self._one(f"SELECT line FROM ({self._union('line')}) ORDER BY line DESC "
                            f"LIMIT 1 OFFSET {int(max_rows) - 1}")
            if cut is not None:
                for table, _ in STREAMS.values():
                    self._run(f"DELETE FROM {table} WHERE line < ?", [cut[0]])
        return before - self.rows()

    def clear(self) -> None:
        for table, _ in STREAMS.values():
            self._run(f"DELETE FROM {table}")

    def rows(self) -> int:
        return int(self._one(f"SELECT count(*) FROM ({self._union('line')})")[0])

    def oldest(self) -> Optional[Tuple[int, int]]:
        """(line, byte_offset) of the first row kept, or None when empty."""
        r = self._one(f"SELECT line, byte_offset FROM ({self._union('line, byte_offset')}) ORDER BY line LIMIT 1")
        return (int(r[0]), int(r[1])) if r else None

    def info(self) -> Dict[str, Any]:
        by = {s: int(self._one(f"SELECT count(*) FROM {t}")[0]) for s, (t, _) in STREAMS.items()}
        first, last = self._one(f"SELECT min(ts_utc), max(ts_utc) FROM ({self._union('ts_utc, ts_valid')}) "
                                "WHERE ts_valid")
        iso = (lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ") if t is not None else None)
        return {"rows": sum(by.values()), "first_ts": iso(first), "last_ts": iso(last), "by_stream": by}
