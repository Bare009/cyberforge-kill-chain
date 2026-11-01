"""Network zones per run (killchain/netzones.py): config/network.yaml when the run fits it, else inferred."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from killchain import db, netzones
from killchain.correlate.entities import classify_ip, find_hubs, entity_rows, load_settings
import polars as pl

T0 = datetime(2026, 10, 28, 1, 0, tzinfo=timezone.utc)


def parsed(tmp: Path, rows):
    """A parsed run with the columns the zone choice reads (others are added as NULL by db.with_optional)."""
    out = tmp / "parsed"
    (out / "firewall").mkdir(parents=True)
    cols = {"ts": pa.timestamp("us", "UTC"), "ts_quality": pa.string(), "parse_issue": pa.string(),
            "source": pa.string(), "line": pa.int64(), "byte_offset": pa.int64(), "src_ip": pa.string(),
            "dst_ip": pa.string(), "dst_port": pa.int32(), "host": pa.string(), "host_ip": pa.string()}
    data = {k: [] for k in cols}
    for i, r in enumerate(rows):
        base = {"ts": T0 + timedelta(seconds=i), "ts_quality": "ok", "parse_issue": None, "source": "x.log",
                "line": i + 1, "byte_offset": i * 100, "src_ip": None, "dst_ip": None, "dst_port": None,
                "host": None, "host_ip": None, **r}
        for k in cols:
            data[k].append(base[k])
    pq.write_table(pa.table({k: pa.array(v, cols[k]) for k, v in data.items()}), out / "firewall" / "part-00000.parquet")
    return out


def flow(s, d, port):
    return {"src_ip": s, "dst_ip": d, "dst_port": port}


def test_host_roles_from_names():
    assert netzones.host_role("SRV-DC-01") == "domain-controller"
    assert netzones.host_role("dc02.corp.local") == "domain-controller"
    assert netzones.host_role("Domain-Controller") == "domain-controller"
    for n in ("web-01", "SQLPROD", "db-replica", "mail.corp.local", "SRV-FILE-01", "app-server"):
        assert netzones.host_role(n) == "server", n
    for n in ("WS-FIN-012", "laptop-7", "desktop", None, ""):
        assert netzones.host_role(n) is None, n


def test_firex_addresses_keep_the_configured_network(tmp_path):
    rows = [flow(f"10.10.10.{i}", "10.10.20.20", 443) for i in range(1, 30)]
    rows += [flow("10.10.30.5", "8.8.8.8", 53), flow("10.10.99.1", "10.10.40.3", 22)]
    info = netzones.decide(parsed(tmp_path, rows), tmp_path / "run")
    assert info["source"] == "configured" and info["configured_share"] == 1.0
    assert not (tmp_path / "run" / netzones.INFERRED_NAME).exists()
    assert db.run_network(tmp_path / "run")["hubs"]["ips"] == db.load_network()["hubs"]["ips"]
    assert json.loads((tmp_path / "run" / netzones.DECISION_NAME).read_text())["source"] == "configured"


def test_another_network_gets_inferred_zones(tmp_path):
    rows = []
    for i in range(1, 9):                                  # 8 desktops use two servers of 192.168.5.0/24
        rows += [flow(f"192.168.1.{i}", "192.168.5.10", 445), flow(f"192.168.1.{i}", "192.168.5.11", 3389)]
    rows += [flow("192.168.1.1", "192.168.2.7", 8080), flow("192.168.1.2", "192.168.2.7", 8080),
             flow("192.168.1.3", "192.168.2.7", 8080)]    # many sources, but not a server port
    rows += [flow("192.168.1.4", "203.0.113.50", 443)]     # documentation range: outside here
    rows += [{"host": "SRV-DC-01", "host_ip": "172.16.0.10"}, {"host": "web-01", "host_ip": "172.16.0.31"},
             {"host": "WS-FIN-012", "host_ip": "172.16.1.12"}]
    run = tmp_path / "run"
    info = netzones.decide(parsed(tmp_path, rows), run)
    assert info["source"] == "inferred" and info["configured_share"] == 0.0
    assert list(info["servers"]) == ["192.168.5.0/24"] and info["servers"]["192.168.5.0/24"]["sources"] == 8
    assert info["named_hosts"] == {"172.16.0.10": {"host": "SRV-DC-01", "role": "domain-controller"},
                                   "172.16.0.31": {"host": "web-01", "role": "server"}}
    doc = yaml.safe_load((run / netzones.INFERRED_NAME).read_text(encoding="utf-8"))
    assert doc["hubs"] == {"ips": [], "users": [], "domains": []}
    net = db.run_network(run)
    assert classify_ip("172.16.0.10", net) == (True, "server", "domain-controller")
    assert classify_ip("192.168.5.77", net) == (True, "server", "server")
    assert classify_ip("192.168.1.3", net) == (True, "desktop", "user-desktop")
    assert classify_ip("192.168.2.7", net) == (True, "desktop", "user-desktop")
    assert classify_ip("203.0.113.50", net) == (False, "internet", "internet")
    assert classify_ip("203.0.113.50", db.load_network())[0] is True      # firex: documentation ranges are private
    # the firex hubs (10.10.20.20, admin, portal.corp.local) do not apply to this network
    alerts = pl.DataFrame({"alert_id": ["a", "b"], "src_ip": ["10.10.20.20", "1.2.3.4"], "dst_ip": [None, None],
                           "user": ["admin", None], "host": [None, None], "domain": [None, None]})
    assert find_hubs(entity_rows(alerts, net), net, load_settings()) == set()
    assert ("user", "admin") in find_hubs(entity_rows(alerts, db.load_network()), db.load_network(), load_settings())


def test_prepare_uses_the_inferred_zones_and_a_later_firex_run_removes_them(tmp_path):
    from killchain.__main__ import main

    rows = [flow(f"192.168.1.{i}", "192.168.5.10", 445) for i in range(1, 6)]
    p, run = parsed(tmp_path, rows), tmp_path / "run"
    assert main(["db", "--prepare", "--parsed", str(p), "--run", str(run)]) == 0
    con = db.connect(None, run)
    assert con.execute("SELECT DISTINCT dst_zone, dst_role FROM events").fetchall() == [("server", "server")]
    con.close()
    p2 = parsed(tmp_path / "b", [flow("10.10.10.5", "10.10.20.20", 443)])
    netzones.decide(p2, run)
    assert not (run / netzones.INFERRED_NAME).exists() and db.run_network(run)["zones"] == db.load_network()["zones"]


def test_no_internal_addresses_infers_an_empty_network(tmp_path):
    info = netzones.decide(parsed(tmp_path, [flow("8.8.8.8", "1.1.1.1", 53)]), tmp_path / "run")
    assert info["source"] == "inferred" and info["internal_ips"] == 0
    assert db.run_network(tmp_path / "run")["hubs"]["ips"] == []
