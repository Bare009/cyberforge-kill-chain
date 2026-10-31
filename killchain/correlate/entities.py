"""Settings, entity rows and hub entities for correlation (docs/build-plan.md P6)."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple, Union

import polars as pl
import yaml

from ..detect.rules import duration

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_YAML = ROOT / "config" / "correlate.yaml"

# alert column -> (entity kind, role)
ENTITY_COLS = {"src_ip": ("ip", "src"), "dst_ip": ("ip", "dst"), "user": ("user", "user"),
               "host": ("host", "host"), "domain": ("domain", "domain")}
ROW_SCHEMA = {"alert_id": pl.Utf8, "kind": pl.Utf8, "value": pl.Utf8, "display": pl.Utf8, "role": pl.Utf8,
              "internal": pl.Boolean, "zone": pl.Utf8, "net_role": pl.Utf8}


def load_settings(path: Union[str, Path] = SETTINGS_YAML) -> Dict[str, Any]:
    """The YAML settings with durations turned into seconds."""
    p = Path(path)
    s = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    s["time"] = {k: duration(v, f"{p.name} time.{k}") for k, v in s["time"].items()}
    s["anomaly"]["within"] = duration(s["anomaly"]["within"], f"{p.name} anomaly.within")
    return s


def classify_ip(value: Optional[str], net: Dict[str, Any]) -> Tuple[Optional[bool], str, Optional[str]]:
    """(internal, zone, role) for an IP or CIDR string, using config/network.yaml; (None, 'unknown', None) otherwise."""
    if value is None:
        return None, "unknown", None
    try:
        ip = int(ipaddress.ip_network(str(value).strip(), strict=False).network_address)
    except ValueError:
        return None, "unknown", None
    internal = any(lo <= ip <= hi for lo, hi in net["_private"])
    for z in net["zones"]:
        if z["_lo"] <= ip <= z["_hi"]:
            return internal, z["zone"], z["role"]
    return internal, "internet", "internet"


def normalise(kind: str, value: str) -> str:
    v = str(value).strip()
    return v.lower() if kind in ("user", "domain") else v


def entity_rows(alerts: pl.DataFrame, net: Dict[str, Any]) -> pl.DataFrame:
    """One row per (alert, entity) from the alert columns src_ip, dst_ip, user, host, domain."""
    rows = []
    cols = [c for c in ENTITY_COLS if c in alerts.columns]
    for a in alerts.select("alert_id", *cols).iter_rows(named=True):
        for col in cols:
            v = a[col]
            if v is None or str(v).strip() == "":
                continue
            kind, role = ENTITY_COLS[col]
            internal, zone, net_role = classify_ip(v, net) if kind == "ip" else (None, None, None)
            rows.append({"alert_id": a["alert_id"], "kind": kind, "value": normalise(kind, v),
                         "display": str(v).strip(), "role": role, "internal": internal, "zone": zone,
                         "net_role": net_role})
    return pl.DataFrame(rows, schema=ROW_SCHEMA)


def find_hubs(rows: pl.DataFrame, net: Dict[str, Any], settings: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """(kind, value) of hub entities: the fixed list in network.yaml, plus any entity that is in more than
    `hubs.share` of all alerts and appears alongside at least `hubs.min_sources` other source IPs."""
    fixed = net.get("hubs") or {}
    hubs = {("ip", normalise("ip", v)) for v in fixed.get("ips") or []}
    hubs |= {("user", normalise("user", v)) for v in fixed.get("users") or []}
    hubs |= {("domain", normalise("domain", v)) for v in fixed.get("domains") or []}
    n_alerts = rows["alert_id"].n_unique()
    if not n_alerts:
        return hubs
    srcs = rows.filter(pl.col("role") == "src").select("alert_id", pl.col("value").alias("src"))
    per = (rows.select("alert_id", "kind", "value").unique()
           .join(srcs, on="alert_id", how="left")
           .group_by("kind", "value")
           .agg(pl.col("alert_id").n_unique().alias("alerts"),
                pl.col("src").filter(pl.col("src").is_not_null() & (pl.col("src") != pl.col("value")))
                .n_unique().alias("others")))
    share, min_src = settings["hubs"]["share"], settings["hubs"]["min_sources"]
    dyn = per.filter((pl.col("alerts") / n_alerts > share) & (pl.col("others") >= min_src))
    return hubs | {(k, v) for k, v in dyn.select("kind", "value").iter_rows()}
