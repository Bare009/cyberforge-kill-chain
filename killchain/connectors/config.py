# Copied from AI-SOC: backend/services/collectors/config.py
# killchain changes: Mongo, metrics, reconciler, health-monitor and TLS-syslog
# settings removed; data paths (<KILLCHAIN_DATA_DIR>/connectors and /ingest) and
# the KILLCHAIN_CONNECTORS / KILLCHAIN_SYSLOG / INGEST_PUBLIC_BASE_URL /
# COLLECTOR_ALLOW_* switches added. Everything is read lazily so tests can point
# KILLCHAIN_DATA_DIR at a temp folder.
"""Collector settings, read from the environment.

Plain `os.getenv` rather than pydantic-settings so the collector has no hard
dependency on a `.env` file being present.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == '':
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


# ── killchain paths and switches ─────────────────────────────────────────────

def data_dir() -> Path:
    """KILLCHAIN_DATA_DIR (relative to the repo root), else <repo>/data. Same rule as api/bundle.py."""
    d = Path(os.environ.get('KILLCHAIN_DATA_DIR') or REPO_ROOT / 'data')
    return d if d.is_absolute() else REPO_ROOT / d


def connectors_dir() -> Path:
    return data_dir() / 'connectors'


def ingest_dir() -> Path:
    return data_dir() / 'ingest'


def live_log_path() -> Path:
    """The one file every connector's raw lines are appended to (tail it with live mode)."""
    return ingest_dir() / 'live.log'


def connectors_enabled() -> bool:
    """KILLCHAIN_CONNECTORS (default on): the API-pull poller runs inside the API process."""
    return _bool('KILLCHAIN_CONNECTORS', True)


def syslog_enabled() -> bool:
    """KILLCHAIN_SYSLOG (default off): the UDP/TCP syslog listener runs inside the API process."""
    return _bool('KILLCHAIN_SYSLOG', False)


def collector_allow_http() -> bool:
    return _bool('COLLECTOR_ALLOW_HTTP', False)


def collector_allow_private_targets() -> bool:
    return _bool('COLLECTOR_ALLOW_PRIVATE_TARGETS', False)


def ingest_public_base_url(request_base: Optional[str] = None) -> str:
    """INGEST_PUBLIC_BASE_URL, else the address the request came in on, else localhost:<API_PORT>."""
    env = (os.getenv('INGEST_PUBLIC_BASE_URL') or '').strip()
    if env:
        return env.rstrip('/')
    if request_base:
        return request_base.rstrip('/')
    return f"http://localhost:{os.getenv('API_PORT') or '8000'}"


@dataclass
class CollectorSettings:
    instance_id: str = field(
        default_factory=lambda: os.getenv('COLLECTOR_INSTANCE_ID')
        or f'{socket.gethostname()}-{os.getpid()}'
    )

    # ── API pull ────────────────────────────────────────────────────────────
    poll_tick_seconds: int = field(default_factory=lambda: max(1, _int('POLLER_TICK_SECONDS', 5)))
    poll_concurrency: int = field(default_factory=lambda: max(1, _int('POLLER_CONCURRENCY', 4)))
    poll_max_pages_per_run: int = field(default_factory=lambda: max(1, _int('POLLER_MAX_PAGES_PER_RUN', 10)))
    poll_run_timeout_seconds: int = field(default_factory=lambda: max(30, _int('POLLER_RUN_TIMEOUT_SECONDS', 300)))
    poll_http_timeout_seconds: int = field(default_factory=lambda: max(5, _int('POLLER_HTTP_TIMEOUT_SECONDS', 30)))
    poll_min_interval_seconds: int = field(default_factory=lambda: max(30, _int('POLLER_MIN_INTERVAL_SECONDS', 60)))
    poll_max_backoff_seconds: int = field(default_factory=lambda: max(60, _int('POLLER_MAX_BACKOFF_SECONDS', 3600)))

    # ── Syslog (plain UDP/TCP only; no TLS listener in killchain) ───────────
    syslog_bind: str = field(default_factory=lambda: os.getenv('SYSLOG_BIND', '0.0.0.0'))
    syslog_udp_port: int = field(default_factory=lambda: _int('SYSLOG_UDP_PORT', 5514))
    syslog_tcp_port: int = field(default_factory=lambda: _int('SYSLOG_TCP_PORT', 5514))
    syslog_max_message_bytes: int = field(default_factory=lambda: max(1024, _int('SYSLOG_MAX_MESSAGE_BYTES', 65536)))
    syslog_queue_size: int = field(default_factory=lambda: max(100, _int('SYSLOG_QUEUE_SIZE', 10000)))
    syslog_workers: int = field(default_factory=lambda: max(1, _int('SYSLOG_WORKERS', 2)))
    syslog_max_tcp_connections: int = field(default_factory=lambda: max(1, _int('SYSLOG_MAX_TCP_CONNECTIONS', 512)))
    syslog_tcp_idle_timeout_seconds: int = field(default_factory=lambda: max(10, _int('SYSLOG_TCP_IDLE_TIMEOUT_SECONDS', 300)))
    syslog_router_refresh_seconds: int = field(default_factory=lambda: max(1, _int('SYSLOG_ROUTER_REFRESH_SECONDS', 10)))
