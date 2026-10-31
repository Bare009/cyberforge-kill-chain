"""SQLite cache of provider answers, plus a per-provider daily request counter.

data/cache/ti.sqlite (git-ignored). Only answers are cached (a provider that
failed is asked again next time). A second run within the TTL makes no
network calls.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

import orjson


class TiCache:
    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL") if str(path) != ":memory:" else None
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS answers (
                provider TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
                fetched_at REAL NOT NULL, expires_at REAL NOT NULL, result TEXT NOT NULL,
                PRIMARY KEY (provider, kind, value));
            CREATE TABLE IF NOT EXISTS usage (
                provider TEXT NOT NULL, day TEXT NOT NULL, requests INTEGER NOT NULL,
                PRIMARY KEY (provider, day));
            """
        )
        self._db.commit()

    def get(self, provider: str, kind: str, value: str, *, allow_expired: bool = False) -> Optional[Dict[str, Any]]:
        """A cached answer, or None. `allow_expired` serves stale answers (offline mode)."""
        with self._lock:
            row = self._db.execute(
                "SELECT expires_at, result FROM answers WHERE provider=? AND kind=? AND value=?",
                (provider, kind, value)).fetchone()
        if row is None or (not allow_expired and row[0] < time.time()):
            return None
        return orjson.loads(row[1])

    def put(self, provider: str, kind: str, value: str, result: Dict[str, Any], ttl_s: float) -> None:
        now = time.time()
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO answers VALUES (?, ?, ?, ?, ?, ?)",
                (provider, kind, value, now, now + ttl_s, orjson.dumps(result).decode()))
            self._db.commit()

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def requests_today(self, provider: str) -> int:
        with self._lock:
            row = self._db.execute("SELECT requests FROM usage WHERE provider=? AND day=?",
                                   (provider, self._today())).fetchone()
        return int(row[0]) if row else 0

    def count_request(self, provider: str) -> int:
        """Add one request to today's count; returns the new count."""
        day = self._today()
        with self._lock:
            self._db.execute(
                "INSERT INTO usage VALUES (?, ?, 1) ON CONFLICT(provider, day) DO UPDATE SET requests = requests + 1",
                (provider, day))
            self._db.commit()
            row = self._db.execute("SELECT requests FROM usage WHERE provider=? AND day=?", (provider, day)).fetchone()
        return int(row[0])

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            rows = self._db.execute(
                "SELECT provider, count(*), sum(expires_at >= ?) FROM answers GROUP BY provider", (time.time(),)).fetchall()
        return {p: {"answers": int(n), "fresh": int(f or 0)} for p, n, f in rows}

    def close(self) -> None:
        with self._lock:
            self._db.close()
