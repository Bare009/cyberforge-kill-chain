"""DuckDB over a parsed run: the `events` view every rule and query uses.

    con = open_run("data/parsed/firex-10G")
    con.sql("SELECT count(*) FROM events WHERE ts_valid").fetchone()

Views:
  firewall_events   the parser's firewall table plus derived columns (below)
  windows_events    the parser's windows table plus the same time columns
  events            = firewall_events (rules default to it)

Derived columns:
  ts_valid          ts is usable for time windows (ts_quality ok or tz_assumed,
                    and no parse_issue)
  ts_utc            ts as a plain UTC timestamp (no time zone)
  ts_ist            the same instant in IST (+05:30), for display and hour rules
  ist_hour          hour of ts_ist, 0-23
  src_internal, dst_internal   address is in a private range
  src_zone, dst_zone           zone from config/network.yaml (internet if none)
  src_role, dst_role           role from config/network.yaml
  src_importance, dst_importance
  src_net24, dst_net24         the /24 of an IPv4 address, e.g. 10.10.20.0/24

The session time zone is pinned to UTC so results never depend on the laptop's
own zone.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import duckdb
import yaml

ROOT = Path(__file__).resolve().parents[1]
NETWORK_YAML = ROOT / "config" / "network.yaml"
IST_MINUTES = 330
VALID_QUALITY = ("ok", "tz_assumed")


def load_network(path: Union[str, Path] = NETWORK_YAML) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        net = yaml.safe_load(f)
    for z in net["zones"]:
        n = ipaddress.ip_network(z["cidr"])
        z["_lo"], z["_hi"] = int(n.network_address), int(n.broadcast_address)
    net["_private"] = [(int(n.network_address), int(n.broadcast_address))
                       for n in map(ipaddress.ip_network, net["private_ranges"])]
    return net


def _ip_int(col: str) -> str:
    """SQL for the 32-bit integer of a dotted IPv4 string; NULL for anything else."""
    parts = [f"TRY_CAST(split_part({col}, '.', {i}) AS BIGINT)" for i in range(1, 5)]
    check = f"regexp_full_match({col}, '\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}')"
    return f"(CASE WHEN {check} THEN {parts[0]}*16777216 + {parts[1]}*65536 + {parts[2]}*256 + {parts[3]} END)"


def _zone_case(ip_int: str, field: str, net: Dict[str, Any], default: str) -> str:
    whens = " ".join(f"WHEN {ip_int} BETWEEN {z['_lo']} AND {z['_hi']} THEN {_lit(z[field])}" for z in net["zones"])
    return f"(CASE WHEN {ip_int} IS NULL THEN NULL {whens} ELSE {default} END)"


def _lit(v: Any) -> str:
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"


def _private_case(ip_int: str, net: Dict[str, Any]) -> str:
    ors = " OR ".join(f"{ip_int} BETWEEN {lo} AND {hi}" for lo, hi in net["_private"])
    return f"(CASE WHEN {ip_int} IS NULL THEN NULL ELSE ({ors}) END)"


def _time_cols() -> str:
    q = ", ".join(_lit(x) for x in VALID_QUALITY)
    return (f"(ts IS NOT NULL AND ts_quality IN ({q}) AND parse_issue IS NULL) AS ts_valid, "
            f"CAST(ts AS TIMESTAMP) AS ts_utc, "
            f"CAST(ts AS TIMESTAMP) + INTERVAL {IST_MINUTES} MINUTE AS ts_ist, "
            f"hour(CAST(ts AS TIMESTAMP) + INTERVAL {IST_MINUTES} MINUTE) AS ist_hour")


def _ip_cols(net: Dict[str, Any]) -> str:
    out: List[str] = []
    for side in ("src", "dst"):
        ipi = _ip_int(f"{side}_ip")
        out += [
            f"{_private_case(ipi, net)} AS {side}_internal",
            f"{_zone_case(ipi, 'zone', net, _lit('internet'))} AS {side}_zone",
            f"{_zone_case(ipi, 'role', net, _lit('internet'))} AS {side}_role",
            f"{_zone_case(ipi, 'importance', net, '0.25')} AS {side}_importance",
            f"(CASE WHEN {ipi} IS NOT NULL THEN regexp_replace({side}_ip, '\\.\\d+$', '.0') || '/24' END) AS {side}_net24",
        ]
    return ", ".join(out)


def _parquet(parsed: Path, stream: str) -> Optional[str]:
    d = parsed / stream
    if not any(d.glob("part-*.parquet")):
        return None
    glob = (d / "part-*.parquet").as_posix().replace("'", "''")
    return f"read_parquet('{glob}', union_by_name = true)"


def configure(con: duckdb.DuckDBPyConnection, memory_limit: Optional[str] = None,
              threads: Optional[int] = None, temp_dir: Optional[Union[str, Path]] = None) -> None:
    con.execute("SET TimeZone = 'UTC'")
    con.execute(f"SET memory_limit = {_lit(memory_limit or os.environ.get('KILLCHAIN_DUCKDB_MEMORY', '6GB'))}")
    con.execute(f"SET threads = {int(threads or max(1, (os.cpu_count() or 2) - 2))}")
    tmp = Path(temp_dir or ROOT / "data" / "tmp")
    tmp.mkdir(parents=True, exist_ok=True)
    con.execute(f"SET temp_directory = {_lit(tmp.as_posix())}")
    con.execute("SET preserve_insertion_order = false")


def create_views(con: duckdb.DuckDBPyConnection, parsed_dir: Union[str, Path],
                 network: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """Create firewall_events, windows_events and events. Returns which streams exist."""
    parsed = Path(parsed_dir)
    net = network or load_network()
    have: Dict[str, bool] = {}
    for stream, view in (("firewall", "firewall_events"), ("windows", "windows_events")):
        src = _parquet(parsed, stream)
        have[stream] = src is not None
        if src is None:
            continue
        # Both tables have src_ip and dst_ip, so both get the same derived columns.
        con.execute(f"CREATE OR REPLACE VIEW {view} AS SELECT *, {_time_cols()}, {_ip_cols(net)} FROM {src}")
    if have.get("firewall"):
        con.execute("CREATE OR REPLACE VIEW events AS SELECT * FROM firewall_events")
    elif have.get("windows"):
        con.execute("CREATE OR REPLACE VIEW events AS SELECT * FROM windows_events")
    else:
        raise FileNotFoundError(f"no parsed Parquet under {parsed}/firewall or {parsed}/windows")
    return have


def open_run(parsed_dir: Union[str, Path], database: Union[str, Path] = ":memory:",
             memory_limit: Optional[str] = None, threads: Optional[int] = None,
             network: Optional[Dict[str, Any]] = None) -> duckdb.DuckDBPyConnection:
    """A configured DuckDB connection with the event views over one parsed run."""
    con = duckdb.connect(str(database))
    configure(con, memory_limit, threads)
    create_views(con, parsed_dir, network)
    return con


def summary(con: duckdb.DuckDBPyConnection) -> Dict[str, Any]:
    """Counts used by `python -m killchain db` and the tests."""
    rows, valid, first, last = con.execute(
        "SELECT count(*), count(*) FILTER (WHERE ts_valid), min(ts_utc) FILTER (WHERE ts_valid), "
        "max(ts_utc) FILTER (WHERE ts_valid) FROM events").fetchone()
    by_q = dict(con.execute("SELECT ts_quality, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC").fetchall())
    zones = dict(con.execute("SELECT coalesce(src_zone, 'none'), count(*) FROM events WHERE ts_valid "
                             "GROUP BY 1 ORDER BY 2 DESC").fetchall())
    return {"rows": rows, "ts_valid": valid, "first_valid_utc": str(first), "last_valid_utc": str(last),
            "ts_quality": by_q, "src_zone_valid": zones}
