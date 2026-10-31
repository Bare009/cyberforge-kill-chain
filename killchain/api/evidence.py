"""Evidence lines of an incident, with the raw log text (P11: GET /incidents/{id}/events).

Where the lines come from, first found wins:
  1. alert_evidence.parquet in the run folder (every member line of every alert,
     written by the detection engine);
  2. evidence_sample.json (the committed sample run);
  3. the `line_sample` of each chain step in the incident (up to 20 per step).

The raw text is read by seeking to `byte_offset` in the log named by `source`,
under the raw folder (KILLCHAIN_RAW_DIR, else data/raw). When the log is not
there, the lines are still listed with their line numbers and `raw_available`
is false.

Safety: `source` comes from a data file, so only a plain file name inside the
raw folder is opened (no paths, no ".."), and at most MAX_LINE_BYTES are read
per line.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

import duckdb
import orjson
import pyarrow as pa

log = logging.getLogger(__name__)

MAX_LINE_BYTES = 8192
MAX_LIMIT = 200
IST = timedelta(hours=5, minutes=30)

_EVIDENCE_SCHEMA = pa.schema([
    ("alert_id", pa.string()), ("source", pa.string()), ("line", pa.int64()),
    ("byte_offset", pa.int64()), ("ts", pa.string()), ("technique", pa.string()), ("role", pa.string()),
])


def _iso_z(value: Any) -> Optional[str]:
    """A timestamp from parquet (datetime) or JSON (string) as contract time: ISO UTC ending in Z."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)


def _ist(iso: Optional[str]) -> Optional[str]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt.astimezone(timezone.utc) + IST).strftime("%Y-%m-%d %H:%M:%S")


class RawReader:
    """Reads one line at a byte offset from the raw logs; keeps the files open."""

    def __init__(self, raw_dir: Path):
        self.raw_dir = Path(raw_dir).resolve()
        self._files: Dict[str, Optional[BinaryIO]] = {}
        self._lock = threading.Lock()

    def path_for(self, source: str) -> Optional[Path]:
        """The file for a source name, or None if the name is unsafe or the file is missing."""
        if not source or Path(source).name != source or source in (".", ".."):
            return None
        p = (self.raw_dir / source).resolve()
        if p.parent != self.raw_dir or not p.is_file():
            return None
        return p

    def available(self, source: str) -> bool:
        return self.path_for(source) is not None

    def read(self, source: str, byte_offset: int) -> Optional[str]:
        with self._lock:                       # one seek+read at a time per file handle
            if source not in self._files:
                p = self.path_for(source)
                self._files[source] = open(p, "rb") if p else None  # noqa: SIM115 (kept open on purpose)
            f = self._files[source]
            if f is None or byte_offset < 0:
                return None
            f.seek(byte_offset)
            data = f.readline(MAX_LINE_BYTES)
        text = data.decode("utf-8", errors="replace").rstrip("\r\n")
        return text if len(data) < MAX_LINE_BYTES else text + " …"

    def close(self) -> None:
        with self._lock:
            for f in self._files.values():
                if f:
                    f.close()
            self._files.clear()


class EvidenceStore:
    """Evidence rows of a run, queried per incident step."""

    def __init__(self, run_dir: Path, incidents: Dict[int, Dict[str, Any]], raw_dir: Path):
        self.raw = RawReader(raw_dir)
        self.incidents = incidents
        self._con = duckdb.connect(":memory:")
        self._con.execute("SET TimeZone = 'UTC'")
        parquet = Path(run_dir) / "alert_evidence.parquet"
        sample = Path(run_dir) / "evidence_sample.json"
        if parquet.is_file():
            path = str(parquet).replace("'", "''")
            self._con.execute(f"CREATE VIEW evidence AS SELECT alert_id, source, line, byte_offset, ts, technique, role "
                              f"FROM read_parquet('{path}')")
            self.origin = "alert_evidence.parquet"
        else:
            rows = orjson.loads(sample.read_bytes()) if sample.is_file() else self._from_chains(incidents)
            self.origin = "evidence_sample.json" if sample.is_file() else "incident line samples"
            table = pa.Table.from_pylist(
                [{k: r.get(k) for k in _EVIDENCE_SCHEMA.names} for r in rows], schema=_EVIDENCE_SCHEMA)
            self._con.register("evidence_arrow", table)
            self._con.execute("CREATE TABLE evidence AS SELECT * FROM evidence_arrow")
            self._con.unregister("evidence_arrow")
        log.info("evidence from %s; raw logs in %s", self.origin, self.raw.raw_dir)

    @staticmethod
    def _from_chains(incidents: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows = []
        for inc in incidents.values():
            for s in inc.get("chain") or []:
                for ln in s.get("line_sample") or []:
                    rows.append({**ln, "alert_id": s.get("alert_id"), "technique": s.get("technique"), "role": "sample"})
        return rows

    def lines(self, incident_number: int, step: Optional[int], offset: int, limit: int) -> Dict[str, Any]:
        inc = self.incidents[incident_number]
        chain = inc.get("chain") or []
        if step is not None and not any(s.get("n") == step for s in chain):
            raise KeyError(f"incident {incident_number} has no step {step}")
        steps = [s for s in chain if step is None or s.get("n") == step]
        step_of = {s["alert_id"]: s["n"] for s in steps if s.get("alert_id")}
        limit = max(1, min(limit, MAX_LIMIT))
        if not step_of:
            return self._result(incident_number, step, 0, offset, limit, [])

        ids = list(step_of)
        marks = ", ".join("?" * len(ids))
        cur = self._con.cursor()
        try:
            total = cur.execute(f"SELECT count(*) FROM evidence WHERE alert_id IN ({marks})", ids).fetchone()[0]
            rows = cur.execute(
                f"SELECT alert_id, source, line, byte_offset, ts, technique, role FROM evidence "
                f"WHERE alert_id IN ({marks}) ORDER BY ts, line LIMIT ? OFFSET ?",
                ids + [limit, offset]).fetchall()
        finally:
            cur.close()

        out = []
        for alert_id, source, line, byte_offset, ts, technique, role in rows:
            iso = _iso_z(ts)
            out.append({
                "step": step_of.get(alert_id), "alert_id": alert_id, "technique": technique, "role": role,
                "source": source, "line": line, "byte_offset": byte_offset,
                "ts": iso, "ts_ist": _ist(iso),
                "raw": self.raw.read(source, int(byte_offset)) if source is not None and byte_offset is not None else None,
            })
        return self._result(incident_number, step, int(total), offset, limit, out)

    def _result(self, n: int, step: Optional[int], total: int, offset: int, limit: int,
                rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        sources = sorted({r["source"] for r in rows if r["source"]})
        return {
            "incident_number": n, "step": step, "total": total, "offset": offset, "limit": limit,
            "origin": self.origin,
            "raw_available": bool(sources) and all(self.raw.available(s) for s in sources),
            "lines": rows,
        }

    def counts_by_step(self, incident_number: int) -> List[Tuple[int, int]]:
        """(step, evidence line count) for the step selector."""
        chain = self.incidents[incident_number].get("chain") or []
        step_of = {s["alert_id"]: s["n"] for s in chain if s.get("alert_id")}
        if not step_of:
            return []
        ids = list(step_of)
        cur = self._con.cursor()
        try:
            rows = cur.execute(
                f"SELECT alert_id, count(*) FROM evidence WHERE alert_id IN ({', '.join('?' * len(ids))}) GROUP BY 1",
                ids).fetchall()
        finally:
            cur.close()
        found = {step_of[a]: int(c) for a, c in rows}
        return [(s["n"], found.get(s["n"], 0)) for s in chain]
