"""Network zones for a run: config/network.yaml when the run's addresses fit it, else zones inferred from the run.

    info = netzones.decide(parsed_dir, run_dir)     # before `db --prepare`; writes <run>/network_zones.json
    net = db.run_network(run_dir)                    # <run>/network.inferred.yaml when written, else the config

config/network.yaml describes the firex network (10.10.x zones, the firewall 10.10.99.1, the portal
10.10.20.20, the fixed hub list). A log from another network would get its catch-all `lan` zone for every
address and the firex hubs. So, after the parse:

1. Internal addresses are the RFC 1918 and loopback ones in src_ip, dst_ip and host_ip. When at least
   CONFIGURED_SHARE of them (distinct addresses) fall in a specific configured zone (one that is not a
   catch-all `internal` range), the run uses config/network.yaml unchanged (firex: 99.6%).
2. Otherwise zones are inferred and written to <run>/network.inferred.yaml:
   - a host whose name (host column, with its host_ip) reads dc / domain controller is zone server, role
     domain-controller; srv / server / sql / db / web / mail names are zone server, role server (/32 each);
   - a /24 whose hosts take connections on SERVER_PORTS from at least MIN_SOURCES other internal sources
     is zone server;
   - every other internal address is zone desktop.
   The inferred network has no fixed hubs (the firex ones would be wrong there; correlate still finds hubs
   from the alerts), and only RFC 1918, loopback and link-local count as internal: the documentation
   ranges config/network.yaml lists as private (so threat intel never looks them up) are outside
   addresses in another network.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

INFERRED_NAME = "network.inferred.yaml"
DECISION_NAME = "network_zones.json"
SERVER_PORTS = (22, 25, 53, 80, 88, 135, 139, 389, 443, 445, 1433, 3306, 3389, 5432, 5985)
MIN_SOURCES = 3
CONFIGURED_SHARE = 0.5
INTERNAL = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
PRIVATE = INTERNAL + ("169.254.0.0/16",)
IMPORTANCE = {"domain-controller": 1.0, "server": 0.75, "user-desktop": 0.25}
DC_RE = re.compile(r"^(dc|addc|domaincontroller)$")
SERVER_PREFIXES = ("srv", "server", "sql", "db", "web", "mail")
MAX_LISTED = 200

_RANGES = [ipaddress.ip_network(c) for c in INTERNAL]


def _int(ip: Any) -> Optional[int]:
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    return int(a) if a.version == 4 else None


def is_internal(ip: Any) -> bool:
    n = _int(ip)
    return n is not None and any(int(r.network_address) <= n <= int(r.broadcast_address) for r in _RANGES)


def net24(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def host_role(name: Any) -> Optional[str]:
    """'SRV-DC-01' -> domain-controller, 'web-01' / 'SQLPROD' -> server, 'WS-FIN-012' -> None."""
    if not name:
        return None
    tokens = [t for t in re.split(r"[^a-z]+", str(name).lower().split(".")[0]) if t]
    if any(DC_RE.match(t) for t in tokens) or "domaincontroller" in str(name).lower().replace("-", "").replace("_", ""):
        return "domain-controller"
    if any(t.startswith(SERVER_PREFIXES) for t in tokens):
        return "server"
    return None


def specific_zones(net: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Configured zones that describe a real part of the network (not the catch-all private ranges)."""
    return [z for z in net["zones"] if z.get("role") != "internal"]


def _in_zones(n: int, zones: List[Dict[str, Any]]) -> bool:
    return any(z["_lo"] <= n <= z["_hi"] for z in zones)


# ── reading the run ─────────────────────────────────────────────────────────

def _source(parsed: Path) -> Optional[str]:
    from . import db

    src = db._parquet(parsed, "firewall") or db._parquet(parsed, "windows")
    return None if src is None else db.with_optional(src)


def _maybe_internal(col: str) -> str:
    """SQL prefilter for INTERNAL (exact check in Python on the few rows left): a log with millions of
    outside addresses (firex-10G: 7.3 million distinct) is reduced to its internal ones in DuckDB."""
    return f"({col} LIKE '10.%' OR {col} LIKE '172.%' OR {col} LIKE '192.168.%' OR {col} LIKE '127.%')"


def internal_ips(con: Any, src: str) -> Counter:
    """{internal IPv4 address: rows} over src_ip, dst_ip and host_ip."""
    rows = con.execute(
        f"SELECT ip, count(*) FROM (SELECT src_ip AS ip FROM {src} UNION ALL SELECT dst_ip FROM {src} "
        f"UNION ALL SELECT host_ip FROM {src}) WHERE {_maybe_internal('ip')} GROUP BY 1").fetchall()
    return Counter({ip: n for ip, n in rows if is_internal(ip)})


def server_nets(con: Any, src: str) -> Dict[str, Dict[str, int]]:
    """{/24: {sources, hosts, rows}} for internal /24s whose hosts take connections on SERVER_PORTS from at
    least MIN_SOURCES other internal addresses."""
    ports = ", ".join(str(p) for p in SERVER_PORTS)
    rows = con.execute(
        f"SELECT src_ip, dst_ip, count(*) FROM {src} WHERE dst_port IN ({ports}) AND {_maybe_internal('src_ip')} "
        f"AND {_maybe_internal('dst_ip')} AND src_ip <> dst_ip GROUP BY 1, 2").fetchall()
    srcs: Dict[str, set] = defaultdict(set)
    hosts: Dict[str, set] = defaultdict(set)
    count: Counter = Counter()
    for s, d, n in rows:
        if not (is_internal(s) and is_internal(d)):
            continue
        k = net24(d)
        srcs[k].add(s)
        hosts[k].add(d)
        count[k] += n
    return {k: {"sources": len(v), "hosts": len(hosts[k]), "rows": count[k]}
            for k, v in sorted(srcs.items()) if len(v) >= MIN_SOURCES}


def named_hosts(con: Any, src: str) -> Dict[str, Tuple[str, str]]:
    """{host_ip: (host name, role)} for internal hosts whose name says server or domain controller."""
    rows = con.execute(f"SELECT host, host_ip, count(*) n FROM {src} WHERE host IS NOT NULL AND host_ip IS NOT NULL "
                       f"GROUP BY 1, 2 ORDER BY n DESC").fetchall()
    out: Dict[str, Tuple[str, str]] = {}
    for name, ip, _ in rows:
        ip = str(ip).strip()
        role = host_role(name)
        if role and is_internal(ip) and ip not in out:
            out[ip] = (str(name), role)
    return out


# ── the decision ────────────────────────────────────────────────────────────

def infer(servers: Dict[str, Dict[str, int]], named: Dict[str, Tuple[str, str]]) -> Dict[str, Any]:
    """The inferred network document (network.yaml layout)."""
    zones: List[Dict[str, Any]] = []
    for ip, (name, role) in sorted(named.items(), key=lambda kv: _int(kv[0]) or 0):
        zones.append({"cidr": f"{ip}/32", "zone": "server", "role": role, "importance": IMPORTANCE[role],
                      "host": name})
    for k, v in servers.items():
        zones.append({"cidr": k, "zone": "server", "role": "server", "importance": IMPORTANCE["server"],
                      "sources": v["sources"]})
    for c in INTERNAL:
        zones.append({"cidr": c, "zone": "desktop", "role": "user-desktop", "importance": IMPORTANCE["user-desktop"]})
    return {"inferred": True, "zones": zones, "hubs": {"ips": [], "users": [], "domains": []},
            "private_ranges": list(PRIVATE)}


def _zone_counts(ips: Counter, zones: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for ip in ips:
        n = _int(ip)
        z = next((z for z in zones if z["_lo"] <= n <= z["_hi"]), None)
        key = f"{z['zone']}/{z['role']}" if z else "internet"
        e = out.setdefault(key, {"ips": 0, "rows": 0})
        e["ips"] += 1
        e["rows"] += ips[ip]
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["ips"]))


def _desktop_nets(ips: Counter, taken: List[Dict[str, Any]]) -> Dict[str, int]:
    nets: Counter = Counter()
    for ip in ips:
        if not _in_zones(_int(ip), taken):
            nets[net24(ip)] += 1
    return dict(nets.most_common(MAX_LISTED))


def _with_bounds(net: Dict[str, Any]) -> Dict[str, Any]:
    for z in net["zones"]:
        n = ipaddress.ip_network(z["cidr"])
        z["_lo"], z["_hi"] = int(n.network_address), int(n.broadcast_address)
    return net


def _public(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {k: ([{kk: vv for kk, vv in z.items() if not kk.startswith("_")} for z in v] if k == "zones" else v)
            for k, v in doc.items() if not k.startswith("_")}


def decide(parsed_dir: Union[str, Path], run_dir: Union[str, Path],
           configured: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Pick the run's network (module docstring) and record it. Writes <run>/network_zones.json, and
    <run>/network.inferred.yaml when the zones are inferred (an older one is removed otherwise)."""
    import duckdb

    from . import db

    t0 = time.perf_counter()
    parsed, run = Path(parsed_dir), Path(run_dir)
    run.mkdir(parents=True, exist_ok=True)
    configured = configured or db.load_network()
    inferred_path = run / INFERRED_NAME
    src = _source(parsed)
    con = duckdb.connect()
    db.configure(con)
    try:
        ips = internal_ips(con, src) if src else Counter()
        spec = specific_zones(configured)
        inside = sum(1 for ip in ips if _in_zones(_int(ip), spec))
        share = inside / len(ips) if ips else 0.0
        info: Dict[str, Any] = {"internal_ips": len(ips), "in_configured_zones": inside,
                                "configured_share": round(share, 4), "threshold": CONFIGURED_SHARE}
        if ips and share >= CONFIGURED_SHARE:
            if inferred_path.exists():
                inferred_path.unlink()
            info.update(source="configured", file="config/network.yaml",
                        reason=f"{share:.1%} of {len(ips):,} internal addresses are in the configured zones",
                        zones=_zone_counts(ips, configured["zones"]))
        else:
            servers = server_nets(con, src) if src else {}
            named = named_hosts(con, src) if src else {}
            doc = infer(servers, named)
            why = (f"only {share:.1%} of {len(ips):,} internal addresses are in the configured zones" if ips
                   else "no internal addresses in src_ip, dst_ip or host_ip")
            header = (f"# Network zones inferred for this run by killchain/netzones.py ({why}).\n"
                      "# Used instead of config/network.yaml by db --prepare, correlate, chain, reach and score.\n"
                      "# Edit and re-run from prepare (python -m killchain run ... --from prepare) to change them.\n")
            inferred_path.write_text(header + yaml.safe_dump(doc, sort_keys=False, width=120), encoding="utf-8")
            net = _with_bounds(json.loads(json.dumps(doc)))
            taken = [z for z in net["zones"] if z["zone"] == "server"]
            info.update(source="inferred", file=INFERRED_NAME, reason=why,
                        servers={k: v for k, v in list(servers.items())[:MAX_LISTED]},
                        named_hosts={ip: {"host": n, "role": r} for ip, (n, r) in list(named.items())[:MAX_LISTED]},
                        desktop_nets=_desktop_nets(ips, taken), zones=_zone_counts(ips, net["zones"]))
    finally:
        con.close()
    info["secs"] = round(time.perf_counter() - t0, 2)
    (run / DECISION_NAME).write_text(json.dumps(info, indent=1), encoding="utf-8")
    return info
