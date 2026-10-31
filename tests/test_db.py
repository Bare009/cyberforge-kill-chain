"""The DuckDB views: derived columns on a small parsed fixture, and counts on the real run if present."""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from killchain import db

ROOT = Path(__file__).resolve().parents[1]
REAL = ROOT / "data" / "parsed" / "firex-10G"

def head(local: str) -> str:
    """A FortiGate header for a local (+0530) time; eventtime is the wall clock written as UTC, as in the data."""
    d, t = local.split()
    et = int(datetime.strptime(local, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()) * 10**9
    return (f'date={d} time={t} eventtime={et} tz="+0530" devname="FGT" devid="FGT" logid="0000000013" '
            f'type="traffic" subtype="forward" level="notice" vd="root" ')


LINES = [
    # 2026-10-29 03:17:00 IST = 2026-10-28 21:47:00 UTC
    head("2026-10-29 03:17:00") + 'srcip=171.104.84.193 dstip=10.10.99.1 dstport=443 action="accept"',
    head("2026-10-29 03:17:01") + 'srcip=10.10.10.44 dstip=10.10.20.31 dstport=445 action="accept"',
    head("2026-10-29 03:17:02") + 'srcip=10.10.40.72 dstip=154.35.54.115 dstport=23 action="dropped"',
    head("2026-10-29 03:17:03") + 'srcip=10.10.20.20 dstip=203.0.113.5 dstport=53 action="accept"',
    head("2026-10-29 03:17:04") + 'srcip=10.10.99.187 srcintfrole="lan" \x01\x02broken',
]


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dbfix")
    log = tmp / "fix.log"
    log.write_bytes("\n".join(LINES).encode() + b"\n")
    out = tmp / "parsed"
    subprocess.run([sys.executable, "-m", "killchain", "parse", str(log), "--out", str(out), "--workers", "1",
                    "--no-summary"], cwd=ROOT, check=True, capture_output=True)
    return db.open_run(out)


def rows(con, sql):
    rel = con.sql(sql)
    return [dict(zip(rel.columns, r)) for r in rel.fetchall()]


def test_time_columns(con):
    r = rows(con, "SELECT ts_utc, ts_ist, ist_hour, ts_valid, ts_quality FROM events ORDER BY line")
    assert [x["ts_quality"] for x in r] == ["ok"] * 5
    assert str(r[0]["ts_utc"]) == "2026-10-28 21:47:00"
    assert str(r[0]["ts_ist"]) == "2026-10-29 03:17:00"
    assert r[0]["ist_hour"] == 3
    assert [x["ts_valid"] for x in r] == [True, True, True, True, False]  # last line has a parse_issue


def test_zones(con):
    r = rows(con, "SELECT src_ip, src_internal, src_zone, src_role, src_importance, src_net24, "
                  "dst_zone, dst_role FROM events ORDER BY line")
    got = {x["src_ip"]: x for x in r}
    assert got["171.104.84.193"]["src_internal"] is False and got["171.104.84.193"]["src_zone"] == "internet"
    assert got["10.10.10.44"]["src_zone"] == "desktop" and got["10.10.10.44"]["src_net24"] == "10.10.10.0/24"
    assert got["10.10.40.72"]["src_zone"] == "iot"
    assert got["10.10.20.20"]["src_role"] == "web-portal" and got["10.10.20.20"]["dst_role"] == "firewall-public-ip"
    assert got["10.10.99.187"]["src_zone"] == "mgmt" and got["10.10.99.187"]["src_importance"] == 1.0
    assert {x["src_ip"]: x["dst_role"] for x in r}["171.104.84.193"] == "firewall-management"


def test_session_is_utc(con):
    assert con.execute("SELECT current_setting('TimeZone')").fetchone()[0] == "UTC"


def test_cli_lists_stages():
    out = subprocess.run([sys.executable, "-m", "killchain"], cwd=ROOT, capture_output=True, text=True, check=True)
    assert "parse      ready" in out.stdout and "correlate  ready" in out.stdout
    assert "chain      ready" in out.stdout and "reach      planned (P8)" in out.stdout
    bad = subprocess.run([sys.executable, "-m", "killchain", "reach"], cwd=ROOT, capture_output=True, text=True)
    assert bad.returncode == 2 and "P8" in bad.stderr


@pytest.mark.skipif(not (REAL / "_stats.json").exists(), reason="real parsed run not present")
def test_real_run_counts():
    s = db.summary(db.open_run(REAL))
    assert s["rows"] == 9_125_383
    assert s["ts_valid"] == 3_848_247
    assert s["first_valid_utc"].startswith("2026-10-23 03:18:26")
    assert s["ts_quality"] == {"stuck": 5_277_136, "ok": 3_848_247}
