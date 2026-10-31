"""Rule engine: every kind on a small parsed log whose answer is known."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from killchain import db
from killchain.contracts import validate_alert
from killchain.detect import engine
from killchain.detect.rules import RuleError, load_rules, parse_rule

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 27, 12, 0, 0)   # local (+0530) wall clock


def line(t: datetime, kv: str, sub: str = "system", typ: str = "event") -> str:
    et = int(t.replace(tzinfo=timezone.utc).timestamp()) * 10**9
    return (f'date={t:%Y-%m-%d} time={t:%H:%M:%S} eventtime={et} tz="+0530" devname="FGT" devid="FGT" '
            f'logid="1" type="{typ}" subtype="{sub}" level="notice" vd="root" {kv}')


def build_lines():
    L = []
    fail = 'logdesc="Admin login failed" user="admin" srcip={ip} dstip=10.10.99.1 action="login" status="failed"'
    # burst: 120 failures from 1.1.1.1 within 4 min (line numbers 1-120)
    for i in range(120):
        L.append(line(T0 + timedelta(seconds=2 * i), fail.format(ip="1.1.1.1")))
    # background: 30 failures from 2.2.2.2 spread over an hour (121-150)
    for i in range(30):
        L.append(line(T0 + timedelta(minutes=2 * i), fail.format(ip="2.2.2.2")))
    # port scan: 300 ports from 3.3.3.3 to the portal in 2 min (151-450)
    for i in range(300):
        L.append(line(T0 + timedelta(hours=2, seconds=0.4 * i),
                      f'srcip=3.3.3.3 srcport=40000 dstip=10.10.20.20 dstport={i + 1} action="deny" proto=6',
                      "forward", "traffic"))
    # sequence: /24 9.9.9.0 fails 25 times then one success (451-476)
    for i in range(25):
        L.append(line(T0 + timedelta(hours=3, seconds=10 * i), fail.format(ip=f"9.9.9.{i + 1}")))
    L.append(line(T0 + timedelta(hours=3, minutes=5),
                  'logdesc="Admin login successful" user="bob" srcip=9.9.9.77 dstip=10.10.99.1 action="login" status="success"'))
    # sequence negative: success with no failures before it (477)
    L.append(line(T0 + timedelta(hours=5),
                  'logdesc="Admin login successful" user="eve" srcip=8.8.8.8 dstip=10.10.99.1 action="login" status="success"'))
    # match with two bursts of the same key, 3 h apart (478-481)
    for h in (6, 6, 9, 9):
        L.append(line(T0 + timedelta(hours=h, minutes=len(L) % 7),
                      'srcip=4.4.4.4 dstip=10.10.20.20 dstport=443 action="dropped" attack="HTTP.URI.SQL.Injection"',
                      "ips", "utm"))
    return L


RULES = {
    "count": dict(id="t-count", title="burst", kind="count", attack={"technique": "T1110.001"}, severity=4,
                  where="log_desc = 'Admin login failed'", group_by=["src_ip"], window="10m", having={"gte": 100},
                  entities={"src_ip": "src_ip", "user": "user"}, action_text="{src_ip} tried {event_count} in {minutes} min"),
    "distinct": dict(id="t-distinct", title="scan", kind="distinct", attack={"technique": "T1046"}, field="dst_port",
                     where="log_type = 'traffic'", group_by=["src_ip", "dst_ip"], window="5m", having={"gte": 200},
                     entities={"src_ip": "src_ip", "dst_ip": "dst_ip"}, action_text="{src_ip} probed {distinct_count} ports"),
    "sequence": dict(id="t-seq", title="success after failures", kind="sequence", attack={"technique": "T1110.001",
                     "technique_by": {"log_desc": {"Admin login successful": "T1078"}}},
                     group_by=["src_net24"], within="15m",
                     steps=[{"name": "failures", "where": "log_desc = 'Admin login failed'", "min": 20},
                            {"name": "success", "where": "log_desc = 'Admin login successful'"}],
                     entities={"src_ip": "src_ip", "user": "user"}),
    "match": dict(id="t-match", title="sqli", kind="match", attack={"technique": "T1190"}, split_gap="1h",
                  where="log_subtype = 'ips'", group_by=["src_ip"], having={"gte": 2}, entities={"src_ip": "src_ip"}),
    "sql": dict(id="t-sql", title="raw sql", kind="sql", attack={"technique": "T1046"},
                sql="SELECT src_ip AS alert_key, source, line FROM {events} WHERE dst_port BETWEEN 1 AND 10",
                entities={"src_ip": "src_ip"}),
}


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("detect")
    log = tmp / "t.log"
    log.write_text("\n".join(build_lines()) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, "-m", "killchain", "parse", str(log), "--out", str(tmp / "p"), "--workers", "1",
                    "--no-summary"], cwd=ROOT, check=True, capture_output=True)
    c = db.open_run(tmp / "p")
    assert c.execute("SELECT count(*) FROM events WHERE ts_valid").fetchone()[0] == len(build_lines())
    return c


def run(con, kind, **override):
    d = {**RULES[kind], **override}
    r = parse_rule(d, Path(f"{d['id']}.yaml"))
    assert engine.check_rule(con, r) is None
    alerts, ev, stats = engine.run_rule(con, r)
    for a in engine.alerts_json(alerts):
        assert validate_alert(a) == [], validate_alert(a)
    return alerts, ev


def test_count_finds_burst_only(con):
    alerts, ev = run(con, "count")
    assert alerts.height == 1
    a = alerts.row(0, named=True)
    assert a["src_ip"] == "1.1.1.1" and a["event_count"] == 120 and a["technique"] == "T1110.001"
    assert sorted(ev["line"].to_list()) == list(range(1, 121))
    assert a["stage_no"] == 8 and a["tactic"] == "credential-access" and "1.1.1.1 tried 120" in a["action_text"]
    assert set(ev["role"].unique()) == {"trigger", "window"}


def test_count_threshold_respected(con):
    alerts, _ = run(con, "count", having={"gte": 121})
    assert alerts.height == 0


def test_distinct(con):
    alerts, ev = run(con, "distinct")
    assert alerts.height == 1 and alerts["distinct_count"][0] == 300 and ev.height == 300
    assert alerts["blocked_share"][0] == 1.0 and alerts["success"][0] is False


def test_sequence_and_per_line_technique(con):
    alerts, ev = run(con, "sequence")
    assert alerts.height == 1
    assert ev.height == 26
    tech = dict(zip(ev["line"].to_list(), ev["technique"].to_list()))
    assert tech[476] == "T1078" and tech[451] == "T1110.001"
    assert alerts["success"][0] is True


def test_sequence_needs_enough_failures(con):
    alerts, _ = run(con, "sequence", steps=[{"name": "f", "where": "log_desc = 'Admin login failed'", "min": 26},
                                             {"name": "s", "where": "log_desc = 'Admin login successful'"}])
    assert alerts.height == 0


def test_match_splits_bursts(con):
    alerts, ev = run(con, "match")
    assert alerts.height == 2 and sorted(alerts["event_count"].to_list()) == [2, 2]
    assert len(set(alerts["alert_id"].to_list())) == 2


def test_sql_kind(con):
    alerts, ev = run(con, "sql")
    assert alerts.height == 1 and ev.height == 10


def test_alert_ids_are_stable(con):
    a1, _ = run(con, "count")
    a2, _ = run(con, "count")
    assert a1["alert_id"].to_list() == a2["alert_id"].to_list()


@pytest.mark.parametrize("change,msg", [
    ({"kind": "magic"}, "kind 'magic'"),
    ({"attack": {"technique": "T9999"}}, "not in the ATT&CK catalogue"),
    ({"attack": {"technique": "T1078"}}, "several tactics"),
    ({"attack": {"technique": "T1110.001", "tactic": "impact"}}, "is not in tactic"),
    ({"window": "ten minutes"}, "not a duration"),
    ({"having": None}, "needs 'having'"),
    ({"severity": 9}, "severity"),
    ({"entities": {"attacker": "src_ip"}}, "not contract fields"),
])
def test_validation_errors(change, msg):
    with pytest.raises(RuleError, match=msg):
        parse_rule({**RULES["count"], **change}, Path("x.yaml"))


def test_bad_sql_is_reported(con):
    r = parse_rule({**RULES["count"], "where": "no_such_column = 1"}, Path("x.yaml"))
    assert "does not compile" in engine.check_rule(con, r)


def test_repo_rules_load():
    rules, errors = load_rules(ROOT / "rules")
    assert errors == [] and len(rules) >= 2
    for r in rules:
        assert r.path.stem == r.id, f"{r.path.name}: file name should match id {r.id}"
        d = yaml.safe_load(r.path.read_text(encoding="utf-8"))
        assert d.get("tuning"), f"{r.path.name}: add a tuning note"


def test_duplicate_ids(tmp_path):
    for n in ("a", "b"):
        (tmp_path / f"{n}.yaml").write_text(yaml.safe_dump(RULES["count"]), encoding="utf-8")
    _, errors = load_rules(tmp_path)
    assert any("also used by" in e for e in errors)
