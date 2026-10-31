"""Anomaly layer: rule loading, labels from a config file, and every detector in
rules/anomaly on a small parsed log with one planted case each."""

from __future__ import annotations

import random
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from killchain import attack, db
from killchain.contracts import validate_alert
from killchain.detect import engine
from killchain.detect.rules import RuleError, load_rules, parse_rule

ROOT = Path(__file__).resolve().parents[1]
ANOMALY = ROOT / "rules" / "anomaly"
T0 = datetime(2026, 10, 23, 0, 0, 0)
DAYS = 4


def line(t: datetime, kv: str, sub: str = "system", typ: str = "event") -> str:
    et = int(t.replace(tzinfo=timezone.utc).timestamp()) * 10**9
    return (f'date={t:%Y-%m-%d} time={t:%H:%M:%S} eventtime={et} tz="+0530" devname="FGT" devid="FGT" '
            f'logid="1" type="{typ}" subtype="{sub}" level="notice" vd="root" {kv}')


def traffic(t, src, dst, port, action="accept", sent=500, rcvd=5000):
    return (t, line(t, f'srcip={src} dstip={dst} dstport={port} action="{action}" proto=6 '
                       f'sentbyte={sent} rcvdbyte={rcvd}', "forward", "traffic"))


def build_lines():
    rnd = random.Random(7)
    L = []
    hours = DAYS * 24
    # background: 30 LAN hosts, 10 accepted web sessions an hour each at random minutes
    for k in range(1, 31):
        for h in range(hours):
            for _ in range(10):
                L.append(traffic(T0 + timedelta(hours=h, seconds=rnd.randrange(3600)), f"10.10.30.{k}", f"8.8.8.{k}", 443))
    # 10.10.10.63: one SMB session an hour, then one hour (day 1) with 150 sessions to 40 servers
    for h in range(hours):
        L.append(traffic(T0 + timedelta(hours=h, minutes=5), "10.10.10.63", "10.10.20.5", 445))
    # (wall clock is +0530, so hh:31-hh:56 local is one UTC hour)
    for i in range(150):
        L.append(traffic(T0 + timedelta(hours=30, minutes=31, seconds=10 * i), "10.10.10.63",
                         f"10.10.20.{100 + i % 40}", 80))
    # 10.10.10.44: 12 servers on SMB it never used, on day 3
    for i in range(12):
        L.append(traffic(T0 + timedelta(days=3, hours=2, minutes=i), "10.10.10.44", f"10.10.20.{60 + i}", 445))
    # bob logs in from India on day 1, from Ireland on day 3
    for d, country, ip in ((1, "India", "49.36.1.1"), (3, "Ireland", "52.18.1.1")):
        L.append((T0 + timedelta(days=d, hours=4),
                  line(T0 + timedelta(days=d, hours=4), f'logdesc="Admin login successful" user="bob" srcip={ip} '
                       f'srccountry="{country}" dstip=10.10.99.1 action="login" status="success"')))
    # Rakes changes an object twice: a rare event, labelled from config/rare_events.yaml
    for m in (0, 12):
        t = T0 + timedelta(days=3, hours=6, minutes=m)
        L.append((t, line(t, 'logdesc="Object attribute configured" user="Rakes" srcip=203.228.177.117 '
                             'dstip=10.10.99.1 action="Edit"')))
    # one-way transfer: 20 sessions of 100 kB out, 1 kB back
    for i in range(20):
        L.append(traffic(T0 + timedelta(days=2, minutes=rnd.randrange(600)), "10.10.20.31", "7.93.184.183", 443,
                         sent=100_000, rcvd=1_000))
    # beacon: 40 sessions exactly 300 s apart
    for i in range(40):
        L.append(traffic(T0 + timedelta(days=1, hours=10, seconds=300 * i), "10.10.10.112", "198.79.124.52", 443,
                         sent=200, rcvd=200))
    # 60 denies, then 5 accepts to the portal
    for i in range(60):
        L.append(traffic(T0 + timedelta(days=2, hours=20, seconds=5 * i), "5.5.5.5", "10.10.20.20", 80, "deny", 0, 0))
    for i in range(5):
        L.append(traffic(T0 + timedelta(days=2, hours=20, minutes=10 + i), "5.5.5.5", "10.10.20.20", 80))
    return [s for _, s in sorted(L, key=lambda x: x[0])]


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("anomaly")
    lines = build_lines()
    (tmp / "t.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, "-m", "killchain", "parse", str(tmp / "t.log"), "--out", str(tmp / "p"),
                    "--workers", "1", "--no-summary"], cwd=ROOT, check=True, capture_output=True)
    c = db.open_run(tmp / "p")
    assert c.execute("SELECT count(*) FROM events WHERE ts_valid").fetchone()[0] == len(lines)
    return c


@pytest.fixture(scope="module")
def result(con):
    rules, errors = load_rules(ANOMALY)
    assert errors == []
    return engine.run_rules(con, rules)


def alerts_of(result, rule_id):
    return result[0].filter(result[0]["rule_id"] == rule_id)


# ── loading ──────────────────────────────────────────────────────────────────

def test_anomaly_rules_load_as_anomaly_layer():
    rules, errors = load_rules(ANOMALY)
    assert errors == [] and len(rules) == 11
    for r in rules:
        assert r.path.stem == r.id and r.id.startswith("A")
        assert r.layer == "anomaly" and r.promote is False and r.kind == "sql"
        assert 0.3 <= r.confidence <= 0.5 and r.severity <= 3
        assert "{all_events}" not in r.sql
        d = yaml.safe_load(r.path.read_text(encoding="utf-8"))
        assert d.get("tuning") and d.get("layer") == "anomaly"


def test_rare_event_labels_come_from_config():
    rules, _ = load_rules(ANOMALY, ["A01-rare-event"])
    r = rules[0]
    assert r.label["technique"] == "unknown"
    assert r.technique_by["log_desc"]["Object attribute configured"] == "T1098"
    assert r.technique_tactic["T1098"] == "persistence" and r.technique_tactic["T1078"] == "initial-access"


def rare_rule(tmp_path, mapping, **attack_extra):
    f = tmp_path / "labels.yaml"
    f.write_text(yaml.safe_dump(mapping), encoding="utf-8")
    d = dict(id="t-rare", title="rare", kind="match", where="log_desc = 'Object attribute configured'",
             group_by=["user"], entities={"user": "user", "src_ip": "src_ip"},
             attack={"technique": "unknown", "technique_by_file": str(f), **attack_extra})
    return parse_rule(d, Path("t-rare.yaml"), "anomaly")


def test_technique_by_file_bad_id_is_refused(tmp_path):
    with pytest.raises(RuleError, match="labels.yaml"):
        rare_rule(tmp_path, {"log_desc": {"Object attribute configured": {"technique": "T9999"}}})
    with pytest.raises(RuleError, match="several tactics"):
        rare_rule(tmp_path, {"log_desc": {"Object attribute configured": "T1078"}})
    with pytest.raises(RuleError, match="technique_by_file"):
        parse_rule(dict(id="x", title="x", kind="match", where="TRUE",
                        attack={"technique": "unknown", "technique_by_file": str(tmp_path / "missing.yaml")}),
                   Path("x.yaml"))


def test_inline_technique_by_wins(tmp_path):
    r = rare_rule(tmp_path, {"log_desc": {"Object attribute configured": {"technique": "T1098", "tactic": "persistence"}}},
                  technique_by={"log_desc": {"Object attribute configured": "T1562"}})
    assert r.technique_by["log_desc"]["Object attribute configured"] == "T1562"


def test_unknown_rule_takes_label_from_evidence(con, tmp_path):
    r = rare_rule(tmp_path, {"log_desc": {"Object attribute configured": {"technique": "T1098", "tactic": "persistence"}}})
    assert engine.check_rule(con, r) is None
    alerts, ev, _ = engine.run_rule(con, r)
    assert alerts.height == 1 and set(ev["technique"]) == {"T1098"}
    a = alerts.row(0, named=True)
    want = attack.label("T1098", "persistence")
    assert (a["technique"], a["tactic"], a["stage_no"]) == (want["technique"], want["tactic"], want["stage_no"])
    assert a["layer"] == "anomaly"
    for j in engine.alerts_json(alerts):
        assert validate_alert(j) == []


# ── detectors ────────────────────────────────────────────────────────────────

def test_every_alert_is_low_trust_and_valid(result):
    alerts = result[0]
    assert alerts.height > 0
    assert set(alerts["layer"]) == {"anomaly"} and not any(alerts["promote"])
    assert alerts["confidence"].max() <= 0.5
    for j in engine.alerts_json(alerts):
        assert validate_alert(j) == [], validate_alert(j)


@pytest.mark.parametrize("rule_id,field,value", [
    ("A01-rare-event", "user", "Rakes"),
    ("A02-first-seen-admin-pair", "src_ip", "10.10.10.44"),
    ("A03-first-seen-user-country", "user", "bob"),
    ("A04-outlier-sessions", "src_ip", "10.10.10.63"),
    ("A05-outlier-destinations", "src_ip", "10.10.10.63"),
    ("A09-denied-then-allowed", "src_ip", "5.5.5.5"),
    ("A10-lopsided-pair", "src_ip", "10.10.20.31"),
    ("A11-too-regular", "src_ip", "10.10.10.112"),
])
def test_planted_case_found(result, rule_id, field, value):
    a = alerts_of(result, rule_id)
    assert value in a[field].to_list(), f"{rule_id}: {a.select('src_ip', 'user').to_dicts()}"


def test_rare_event_label(result):
    a = alerts_of(result, "A01-rare-event").filter(alerts_of(result, "A01-rare-event")["user"] == "Rakes")
    assert a.height == 1 and a["technique"][0] == "T1098" and a["tactic"][0] == "persistence"


def test_first_seen_country_only_flags_the_new_one(result):
    a = alerts_of(result, "A03-first-seen-user-country")
    assert a.height == 1 and a["src_ip"][0] == "52.18.1.1"


def test_first_seen_pair_ignores_old_pairs(result):
    assert alerts_of(result, "A02-first-seen-admin-pair")["src_ip"].to_list() == ["10.10.10.44"]


def test_denied_then_allowed_evidence_has_one_accept(con, result):
    a = alerts_of(result, "A09-denied-then-allowed")
    ev = result[1].filter(result[1]["alert_id"] == a["alert_id"][0])
    accepts = con.execute(
        f"SELECT count(*) FROM firewall_events WHERE action = 'accept' AND line IN ({','.join(map(str, ev['line']))})"
    ).fetchone()[0]
    assert ev.height == 61 and accepts == 1


def test_background_raises_nothing(result):
    alerts = result[0]
    bg = alerts.filter(alerts["src_ip"].str.starts_with("10.10.30."))
    assert bg.height == 0, bg.select("rule_id", "src_ip").to_dicts()


def test_quiet_detectors_stay_quiet(result):
    for rid in ("A06-outlier-ports", "A07-outlier-failed-logins"):
        assert alerts_of(result, rid).height == 0
