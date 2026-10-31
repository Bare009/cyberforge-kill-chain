"""The access graph of a run (docs/build-plan.md P8), built once from the DuckDB `events` view.

One row per (src, dst, kind) in access_graph.parquet:
  controls      account -> firewall from successful admin logins (strength 1.0: the firewall controls
                every zone)
  admin_port    allowed internal -> internal session on an admin port (22, 135, 445, 3389, 5985, 5986)
  allowed_flow  allowed internal -> internal session on any other port
"Internal" means a private address whose network.yaml zone is not internet or public, so documentation
ranges such as 198.51.100.0/24 do not count as internal hosts.

zone_neighbour edges (hosts in the same server or DMZ /24 as a foothold) are not stored: an all-pairs table
would grow with the square of each subnet. reach.py draws them per incident from access_hosts.parquet,
which lists every internal IP seen in the logs with its zone, role, /24, importance and event count.

Windows edges (logs_on, admin_on, member_of) are not built: there is no Windows log in this data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple, Union

import duckdb
import polars as pl
import yaml

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_YAML = ROOT / "config" / "reach.yaml"
NOT_INTERNAL_ZONES = ("internet", "public")
EDGE_KINDS = ("controls", "admin_port", "allowed_flow", "zone_neighbour")

LINE_STRUCT = pl.Struct({"source": pl.Utf8, "line": pl.Int64, "byte_offset": pl.Int64,
                         "ts": pl.Datetime("us", "UTC")})
EDGE_SCHEMA = {"src": pl.Utf8, "dst": pl.Utf8, "kind": pl.Utf8, "strength": pl.Float64, "count": pl.Int64,
               "first_ts": pl.Datetime("us", "UTC"), "last_ts": pl.Datetime("us", "UTC"),
               "ports": pl.List(pl.Int64), "lines": pl.List(LINE_STRUCT)}
HOST_SCHEMA = {"ip": pl.Utf8, "zone": pl.Utf8, "role": pl.Utf8, "net24": pl.Utf8, "importance": pl.Float64,
               "events": pl.Int64}


def load_settings(path: Union[str, Path] = SETTINGS_YAML) -> Dict[str, Any]:
    s = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    s["hop_factor"] = {int(k): float(v) for k, v in s["hop_factor"].items()}
    return s


def _lit(v: Any) -> str:
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"


def _list(xs) -> str:
    return "(" + ", ".join(_lit(x) for x in xs) + ")"


def _internal(side: str) -> str:
    return f"({side}_internal AND {side}_zone NOT IN {_list(NOT_INTERNAL_ZONES)})"


def _agg(n_lines: int) -> str:
    return (f"count(*) AS count, min(ts) AS first_ts, max(ts) AS last_ts, "
            f"coalesce(list_sort(list_distinct(list(CAST(dst_port AS BIGINT)) FILTER (WHERE dst_port IS NOT NULL))), "
            f"CAST([] AS BIGINT[])) AS ports, "
            f"list({{'source': source, 'line': CAST(line AS BIGINT), 'byte_offset': CAST(byte_offset AS BIGINT), "
            f"'ts': ts}} ORDER BY ts, line)[1:{int(n_lines)}] AS lines")


def build_access(con: duckdb.DuckDBPyConnection, settings: Dict[str, Any]) -> Tuple[pl.DataFrame, pl.DataFrame]:
    """(edges, hosts) per the module docstring."""
    st = settings["strengths"]
    n = settings["lines_per_edge"]
    admin = _list(int(p) for p in settings["admin_ports"])
    denied = _list(str(a).lower() for a in settings["denied_actions"])
    logins = _list(settings["login_success_desc"])
    controls = (f"SELECT user AS src, dst_ip AS dst, 'controls' AS kind, {float(st['controls'])} AS strength, {_agg(n)} "
                f"FROM events WHERE ts_valid AND log_desc IN {logins} AND user IS NOT NULL AND user <> '' "
                f"AND dst_ip IS NOT NULL GROUP BY user, dst_ip")
    flows = (f"SELECT src_ip AS src, dst_ip AS dst, "
             f"CASE WHEN dst_port IN {admin} THEN 'admin_port' ELSE 'allowed_flow' END AS kind, "
             f"CASE WHEN dst_port IN {admin} THEN {float(st['admin_port'])} ELSE {float(st['allowed_flow'])} END AS strength, "
             f"{_agg(n)} FROM events WHERE ts_valid AND log_type = 'traffic' "
             f"AND lower(coalesce(action, '')) NOT IN {denied} AND {_internal('src')} AND {_internal('dst')} "
             f"AND src_ip <> dst_ip GROUP BY 1, 2, 3, 4")
    edges = con.sql(f"SELECT * FROM ({controls}) UNION ALL SELECT * FROM ({flows}) ORDER BY kind, src, dst").pl()
    hosts = con.sql(
        "SELECT ip, zone, role, net24, CAST(importance AS DOUBLE) AS importance, count(*) AS events FROM ("
        f"SELECT src_ip AS ip, src_zone AS zone, src_role AS role, src_net24 AS net24, src_importance AS importance "
        f"FROM events WHERE ts_valid AND {_internal('src')} UNION ALL "
        f"SELECT dst_ip, dst_zone, dst_role, dst_net24, dst_importance "
        f"FROM events WHERE ts_valid AND {_internal('dst')}) GROUP BY ALL ORDER BY ip").pl()
    return _cast(edges, EDGE_SCHEMA), _cast(hosts, HOST_SCHEMA)


def _cast(df: pl.DataFrame, schema: Dict[str, Any]) -> pl.DataFrame:
    if not df.height:
        return pl.DataFrame(schema=schema)
    return df.select([pl.col(k).cast(v) for k, v in schema.items()])
