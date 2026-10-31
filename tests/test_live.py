"""Live mode (P15): line parser, tailer, live window, rebuild and publish, engine, CLI and replay."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from killchain import db
from killchain.contracts import validate_alert, validate_bundle
from killchain.detect import engine as det
from killchain.detect.rules import load_rules
from killchain.live import feed, publish as pub, replay
from killchain.live.cli import main as live_main
from killchain.live.engine import GuardError, LiveEngine
from killchain.live.pipeline import StagePipeline
from killchain.live.settings import load_settings, select_rules
from killchain.live.table import LiveTable
from killchain.live.tailer import FileTailer
from killchain.parser.lines import LineParser

ROOT = Path(__file__).resolve().parents[1]
ATTACKER, PORTAL = "32.127.48.11", "10.10.20.20"
T0 = datetime(2026, 10, 29, 1, 51, 0)     # local (+0530) wall clock
CHAIN = ["R02-port-scan", "R16-web-sql-injection", "R20-web-shell", "R12-large-lopsided-transfer"]


def line(t: datetime, kv: str, sub: str = "forward", typ: str = "traffic") -> str:
    """A FortiGate line for a local (+0530) time (copy of tests/test_run.py::line)."""
    et = int(t.replace(tzinfo=timezone.utc).timestamp()) * 10**9
    return (f'date={t:%Y-%m-%d} time={t:%H:%M:%S} eventtime={et} tz="+0530" devname="FGT" devid="FGT" '
            f'logid="1" type="{typ}" subtype="{sub}" level="notice" vd="root" {kv}')


def background(start: datetime, minutes: float, n: int, seed: int) -> list:
    out = []
    for i in range(n):
        t = start + timedelta(seconds=minutes * 60 * i / max(n, 1))
        out.append((t, line(t, f'srcip=10.10.10.{(seed + i) % 50 + 10} srcport={30000 + i} dstip=142.250.{seed}.{i % 9 + 1} '
                               f'dstport=443 action="accept" proto=6 sentbyte=900 rcvdbyte=7000')))
    return out


def chain_a_steps() -> list:
    """Chain A in four steps (R02 > R16 > R20 > R12), each with some benign background, in time order."""
    s1 = [(T0 + timedelta(seconds=63 * i / 239),
           line(T0 + timedelta(seconds=63 * i / 239),
                f'srcip={ATTACKER} srcport=40000 dstip={PORTAL} dstport={i + 1} action="deny" proto=6'))
          for i in range(240)] + background(T0, 5, 50, 1)
    t2 = T0 + timedelta(minutes=15)
    s2 = [(t2 + timedelta(seconds=4 * i),
           line(t2 + timedelta(seconds=4 * i),
                f'srcip={ATTACKER} dstip={PORTAL} dstport=443 action="detected" attack="HTTP.URI.SQL.Injection" '
                f'hostname="portal.corp.local" url="/login.php?id=1%27%20or%201=1"', "ips", "utm"))
          for i in range(60)] + background(t2, 5, 50, 2)
    t3 = t2 + timedelta(minutes=34)
    s3 = [(t3 + timedelta(seconds=6 * i),
           line(t3 + timedelta(seconds=6 * i),
                f'srcip={ATTACKER} dstip={PORTAL} dstport=443 action="passthrough" hostname="portal.corp.local" '
                f'url="/uploads/s.php"', "webfilter", "utm"))
          for i in range(40)] + background(t3, 5, 50, 3)
    t4 = t3 + timedelta(hours=7)
    s4 = [(t4 + timedelta(seconds=15 * i),
           line(t4 + timedelta(seconds=15 * i),
                f'srcip={PORTAL} srcport=443 dstip={ATTACKER} dstport=51000 action="accept" proto=6 '
                f'sentbyte=20500 rcvdbyte=300'))
          for i in range(600)] + background(t4, 150, 50, 4)
    return [[x for _, x in sorted(s, key=lambda p: p[0])] for s in (s1, s2, s3, s4)]


def quiet_lines() -> list:
    """Benign lines after chain A (no rule fires)."""
    return [x for _, x in background(T0 + timedelta(hours=11), 10, 40, 5)]


def append(path: Path, lines: list) -> None:
    with open(path, "ab") as f:
        f.write(("\n".join(lines) + "\n").encode())


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def incidents(run: Path) -> list:
    return [load(p) for p in sorted((run / "incidents").glob("*.json"))]


def chain_a(run: Path):
    for inc in incidents(run):
        if ATTACKER in inc["entities"]["ips"]:
            return inc
    return None


def rule_steps(inc) -> list:
    return [s["rule_id"] for s in inc["chain"] if s.get("layer", "rule") == "rule"] if inc else []


def check_bundle(run: Path) -> None:
    index, alerts = load(run / "index.json"), load(run / "alerts.json")
    for i, a in enumerate(alerts):
        assert validate_alert(a, f"alert[{i}]") == []
    for inc in incidents(run):
        assert validate_bundle(inc, index, alerts) == [], inc["incident_number"]
    assert len(index["incidents"]) == len(incidents(run))


def parse_batch(log: Path, out: Path) -> Path:
    subprocess.run([sys.executable, "-m", "killchain", "parse", str(log), "--out", str(out), "--workers", "1",
                    "--no-summary"], cwd=ROOT, check=True, capture_output=True)
    return out


def numbered(path: Path):
    """(raw, line, offset) for every line of a file, as the batch parser numbers them."""
    out, off = [], 0
    for i, raw in enumerate(path.read_bytes().split(b"\n")[:-1], 1):
        out.append((raw, i, off))
        off += len(raw) + 1
    return out


def fast_settings(**kw):
    s = load_settings()
    s.update(kw)
    return s


# ── parser line entry point ─────────────────────────────────────────────────

def test_line_parser_matches_batch_parser(tmp_path):
    lines = [line(T0 + timedelta(seconds=i), f'srcip=1.2.3.{i} dstip=10.10.20.20 dstport={80 + i} action="deny" '
                                             f'foo="bar {i}"') for i in range(5)]
    raw = ("\n".join(lines[:2]) + "\n" + '{"@timestamp": "2026-10-29T01:00:00Z", "event": {"code": 4625}, '
           '"source": {"ip": "9.9.9.9"}}\n\n\x00\x01\x02binary\n' + lines[2] + "\r\n" + "\n".join(lines[3:])
           + "\n{bad json\nhello\n")
    log = tmp_path / "mix.log"
    log.write_bytes(raw.encode("latin-1"))
    parsed = parse_batch(log, tmp_path / "parsed")
    lp = LineParser("mix.log")
    got = lp.parse(numbered(log))
    import polars as pl
    for stream in ("firewall", "windows"):
        batch = pl.read_parquet(parsed / stream / "*.parquet").sort("line")
        live = pl.from_arrow(got[stream]).sort("line")
        cols = [c for c in ("line", "byte_offset", "line_hash", "ts", "ts_quality", "src_ip", "dst_port", "extra")
                if c in batch.columns]
        assert live.select(cols).equals(batch.select(cols)), stream
    stats = load(parsed / "_stats.json")["lines_by_class"]
    assert dict(lp.counts) == stats


def test_line_parser_reset_clears_time_state():
    late = [(line(T0 + timedelta(hours=2), 'srcip=1.1.1.1 dstip=10.10.20.20').encode(), 1, 0)]
    early = [(line(T0, 'srcip=1.1.1.1 dstip=10.10.20.20').encode(), 2, 100)]
    lp = LineParser("x.log")
    lp.parse(late)
    assert lp.parse(early)["firewall"]["ts_quality"].to_pylist() == ["backwards"]
    lp.reset()
    assert lp.parse(early)["firewall"]["ts_quality"].to_pylist() == ["ok"]


# ── tailer ──────────────────────────────────────────────────────────────────

def test_tailer_append_and_partial_line(tmp_path):
    log = tmp_path / "a.log"
    log.write_bytes(b"one\r\ntwo\nthr")
    t = FileTailer(log)
    assert t.start(None)["mode"] == "start"
    r = t.poll()
    assert [(x[0], x[1], x[2]) for x in r.lines] == [(b"one\r", 1, 0), (b"two", 2, 5)]
    assert t.offset == 9
    with open(log, "ab") as f:
        f.write(b"ee\nfour\n")
    r = t.poll()
    assert [(x[0], x[1], x[2]) for x in r.lines] == [(b"three", 3, 9), (b"four", 4, 15)]
    assert not r.reset
    assert t.poll().lines == []
    # the parser strips the \r, as the batch parser does
    assert LineParser("a.log").parse([(line(T0, "srcip=1.1.1.1").encode() + b"\r", 1, 0)])["firewall"].num_rows == 1


def test_tailer_rotation(tmp_path):
    log = tmp_path / "r.log"
    log.write_bytes(b"a1\na2\n")
    t = FileTailer(log)
    t.start(None)
    assert len(t.poll().lines) == 2
    os.replace(log, log.with_suffix(".1"))
    log.write_bytes(b"b1\nb2\nb3\n")
    r = t.poll()
    assert r.reset and r.reason == "rotated"
    assert [(x[0], x[1]) for x in r.lines] == [(b"b1", 1), (b"b2", 2), (b"b3", 3)]


def test_tailer_truncation(tmp_path):
    log = tmp_path / "t.log"
    log.write_bytes(b"line one\nline two\n")
    t = FileTailer(log)
    t.start(None)
    t.poll()
    with open(log, "r+b") as f:       # same file, shorter: truncation (inode unchanged)
        f.truncate(0)
        f.write(b"x\n")
    r = t.poll()
    assert r.reset and r.reason == "truncated"
    assert [(x[0], x[1], x[2]) for x in r.lines] == [(b"x", 1, 0)]
    with open(log, "r+b") as f:       # rewritten with other content, longer than the offset: fingerprint
        f.truncate(0)
        f.write(b"other first line\nmore\n")
    r = t.poll()
    assert r.reset
    assert [x[0] for x in r.lines] == [b"other first line", b"more"]


def test_tailer_checkpoint_resume(tmp_path):
    log = tmp_path / "c.log"
    log.write_bytes(b"l1\nl2\nl3\n")
    t = FileTailer(log)
    t.start(None)
    t.poll()
    ck = t.checkpoint()
    append(log, ["l4", "l5"])
    t2 = FileTailer(log)
    assert t2.start(ck)["mode"] == "resume"
    assert [(x[0], x[1], x[2]) for x in t2.poll().lines] == [(b"l4", 4, 9), (b"l5", 5, 12)]
    # the window start is read again on resume (backfill)
    t3 = FileTailer(log)
    t3.start(t.checkpoint(window_offset=3, window_line=2))
    assert [x[1] for x in t3.poll().lines] == [2, 3, 4, 5]
    for bad in ({**ck, "fingerprint": "0" * 16}, {**ck, "inode": (ck["inode"] or 1) + 99}):
        t4 = FileTailer(log)
        if bad.get("inode") and not ck["inode"]:
            continue
        assert t4.start(bad)["mode"] == "start"
        assert t4.poll().lines[0][1] == 1


def test_tailer_large_file_starts_near_end(tmp_path):
    log = tmp_path / "big.log"
    rows = [f"row {i:05d} " + "x" * 40 for i in range(200)]
    log.write_bytes(("\n".join(rows) + "\n").encode())
    t = FileTailer(log, max_backfill_bytes=1024)
    assert t.start(None)["mode"] == "tail"
    got = t.poll().lines
    assert 0 < len(got) < 200
    truth = {i: (r, off) for r, i, off in numbered(log)}
    for raw, n, off in got:
        assert truth[n] == (raw, off)
    assert got[-1][1] == 200


def test_tailer_long_line_truncated(tmp_path):
    log = tmp_path / "long.log"
    log.write_bytes(b"short\n" + b"y" * 5000 + b"\nafter\n")
    t = FileTailer(log, max_line_bytes=100)
    t.start(None)
    got = t.poll().lines
    assert [(len(x[0]), x[1]) for x in got] == [(5, 1), (100, 2), (5, 3)]
    assert got[2] == (b"after", 3, 5007)


def test_tailer_missing_file_waits(tmp_path):
    t = FileTailer(tmp_path / "nope.log")
    t.start(None)
    r = t.poll()
    assert r.status == "waiting" and r.lines == []
    (tmp_path / "nope.log").write_bytes(b"hi\n")
    assert [x[0] for x in t.poll().lines] == [b"hi"]


# ── settings and the live window ────────────────────────────────────────────

def test_select_rules():
    rules, errors = load_rules([str(ROOT / "rules")])
    assert errors == []
    s = load_settings()
    active, skipped, errs = select_rules(rules, 72 * 3600, s["skip_rules"])
    assert errs == []
    assert sorted(x["id"] for x in skipped) == ["A01-rare-event", "A02-first-seen-admin-pair",
                                                "A03-first-seen-user-country", "R13-insider-drift"]
    assert len(active) + len(skipped) == len(rules)
    long = next(r for r in rules if r.kind == "count")
    import copy
    fake = copy.copy(long)
    fake.id, fake.window_s = "X-five-days", 5 * 86400
    a2, sk2, _ = select_rules([fake], 72 * 3600, {})
    assert a2 == [] and sk2[0]["reason"] == "window longer than 72 h"
    assert select_rules(rules, 72 * 3600, {"nope": "x"})[2]


def test_table_matches_views(tmp_path):
    sys.path.insert(0, str(ROOT / "tests"))
    from test_db import LINES
    log = tmp_path / "fix.log"
    log.write_bytes("\n".join(LINES).encode() + b"\n")
    con = db.open_run(parse_batch(log, tmp_path / "parsed"))
    t = LiveTable()
    t.append(LineParser("fix.log").parse(numbered(log)))
    cols = ("line", "ts_valid", "ts_utc", "ts_ist", "ist_hour", "src_ip_int", "src_internal", "dst_internal",
            "src_zone", "dst_zone", "src_role", "dst_role", "src_importance", "dst_importance", "src_net24", "dst_net24")
    q = f"SELECT {', '.join(cols)} FROM events ORDER BY line"
    assert t.con.execute(q).fetchall() == con.execute(q).fetchall()
    assert [c[0] for c in t.con.execute("DESCRIBE firewall_events").fetchall()] == \
        [c[0] for c in con.execute("DESCRIBE firewall_events").fetchall()]


def test_table_retention_by_event_time():
    rows = [(line(T0 + timedelta(hours=h), f'srcip=1.1.1.{h % 250} dstip=10.10.20.20').encode(), h + 1, h * 100)
            for h in range(81)]                         # 0..80 h
    t = LiveTable()
    t.append(LineParser("x.log").parse(rows))
    assert t.rows() == 81
    dropped = t.trim(72 * 3600, 10**6)
    assert dropped == 8 and t.rows() == 73              # 8..80 h kept
    assert t.oldest() == (9, 800)
    assert t.trim(72 * 3600, 10) == 63
    assert t.oldest() == (72, 7100) and t.rows() == 10
    t.clear()
    assert t.rows() == 0 and t.oldest() is None


def test_all_rules_compile_on_empty_table():
    rules, _ = load_rules([str(ROOT / "rules")])
    active, _, _ = select_rules(rules, 72 * 3600, load_settings()["skip_rules"])
    t = LiveTable()
    cur = t.con.cursor()
    assert [m for m in (det.check_rule(cur, r) for r in active) if m] == []


# ── rebuild, diff, publish, feed ────────────────────────────────────────────

def _active_rules():
    rules, _ = load_rules([str(ROOT / "rules")])
    return select_rules(rules, 72 * 3600, load_settings()["skip_rules"])[0]


def test_rebuild_empty_table(tmp_path):
    work = tmp_path / "live" / "work" / "r"
    rb = StagePipeline(work, _active_rules()).rebuild(LiveTable())
    assert rb.ok, (rb.error, rb.log_tail)
    assert load(work / "index.json")["incidents"] == [] and load(work / "alerts.json") == []
    assert load(work / "index.json")["run"] == "r"


def test_rebuild_is_byte_stable(tmp_path):
    t = LiveTable()
    lines = [x for s in chain_a_steps()[:2] for x in s]
    t.append(LineParser("c.log").parse([(x.encode(), i, i * 600) for i, x in enumerate(lines, 1)]))
    p = StagePipeline(tmp_path / "w" / "r", _active_rules())
    assert p.rebuild(t).ok
    first = {f.name: f.read_bytes() for f in (tmp_path / "w" / "r" / "incidents").glob("*.json")}
    assert first
    assert p.rebuild(t).ok
    assert {f.name: f.read_bytes() for f in (tmp_path / "w" / "r" / "incidents").glob("*.json")} == first


def _fake_incident(work: Path, n: int, iid: str, alerts: list) -> None:
    (work / "incidents").mkdir(parents=True, exist_ok=True)
    inc = {"incident_id": iid, "incident_number": n, "title": "t", "risk_score": 1.0, "risk_band": "low",
           "severity": 3, "tactics": [], "entities": {"ips": ["1.1.1.1"]},
           "chain": [{"rule_id": "R", "alert_id": a} for a in alerts]}
    (work / "incidents" / f"{n}.json").write_text(json.dumps(inc), encoding="utf-8")


def test_diff_lineage(tmp_path):
    w1, w2 = tmp_path / "w1", tmp_path / "w2"
    _fake_incident(w1, 1, "id1", ["a"])
    d1 = pub.diff_incidents({}, w1)
    assert [x["incident_id"] for x in d1.new] == ["id1"] and d1.removed == []
    _fake_incident(w2, 1, "id2", ["a", "b"])
    d2 = pub.diff_incidents(pub.published_state(d1.current), w2)
    assert [x["incident_id"] for x in d2.new] == ["id2"]
    assert d2.new[0]["grew_from"] == ["id1"]
    assert d2.removed == [{"incident_id": "id1", "replaced_by": "id2"}]
    assert pub.diff_incidents(pub.published_state(d2.current), w2).empty


def test_publish_order_and_retry(tmp_path, monkeypatch):
    work, run = tmp_path / "work", tmp_path / "run"
    _fake_incident(work, 1, "id1", ["a"])
    for name in ("alerts.parquet", "chains.json", "unexplained.json", "alerts.json", "run_summary.json", "index.json"):
        (work / name).write_text("{}", encoding="utf-8")
    (work / "detect").mkdir()
    (work / "detect" / "_stats.json").write_text("{}", encoding="utf-8")
    run.mkdir()
    (run / "ti.json").write_text("{}", encoding="utf-8")
    calls, fails = [], {"n": 0}
    real = os.replace

    def flaky(src, dst):
        if Path(dst).name == "alerts.json" and fails["n"] < 2:
            fails["n"] += 1
            raise PermissionError("in use")
        calls.append(Path(dst).relative_to(run).as_posix())
        return real(src, dst)

    monkeypatch.setattr(pub.os, "replace", flaky)
    monkeypatch.setattr(pub, "RETRY_WAIT", 0.001)
    pub.publish(work, run)
    assert fails["n"] == 2
    assert calls[-1] == "index.json"
    assert calls.index("incidents") < calls.index("unexplained.json") < calls.index("alerts.json")
    assert calls.index("chains.json") < calls.index("incidents")
    assert (run / "incidents" / "1.json").exists() and not (run / "ti.json").exists()


def test_feed_reads_after_seq_and_skips_partial(tmp_path):
    log = pub.EventLog(tmp_path)
    for k in ("start", "publish", "publish"):
        log.append(k)
    with open(tmp_path / feed.EVENTS_FILE, "ab") as f:
        f.write(b'{"seq": 4, "kind": "pub')
    assert [e["seq"] for e in feed.read_events(tmp_path)] == [1, 2, 3]
    assert [e["seq"] for e in feed.read_events(tmp_path, after_seq=1, limit=1)] == [2]
    log2 = pub.EventLog(tmp_path)          # a restart continues seq and drops the partial line
    assert log2.append("stop")["seq"] == 4
    assert [e["seq"] for e in feed.read_events(tmp_path)] == [1, 2, 3, 4]
    log2.write_status({"state": "running"})
    assert feed.read_status(tmp_path) == {"state": "running"}


# ── engine ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def live(tmp_path):
    log = tmp_path / "raw" / "chain.log"
    log.parent.mkdir()
    log.write_bytes(b"")
    run = tmp_path / "runs" / "live-test"
    eng = LiveEngine(log, run)
    eng.start()
    yield eng, log, run
    eng.close()


def publishes(run: Path) -> list:
    return [e for e in feed.read_events(run) if e["kind"] == "publish"]


def test_incremental_detection_grows_chain_a(live):
    eng, log, run = live
    assert (run / "index.json").exists() and load(run / "index.json")["incidents"] == []
    for k, step in enumerate(chain_a_steps(), 1):
        append(log, step)
        res = eng.tick()
        assert res.published, res.error
        assert rule_steps(chain_a(run)) == CHAIN[:k], k
        check_bundle(run)
    pubs = publishes(run)
    assert len(pubs) == 4
    for p in pubs[1:]:
        grown = [x for x in p["new"] if ATTACKER in x["ips"]]
        assert grown and grown[0]["grew_from"], p["seq"]
        assert any(r["replaced_by"] == grown[0]["incident_id"] for r in p["removed"])
    assert pubs[0]["latency_ms"]["read_to_publish"] is not None
    st = feed.read_status(run)
    for k in ("state", "updated_at", "source", "offset", "size", "lines_total", "lines_per_sec", "last_line_ts",
              "pid", "started_at", "interval_s", "window_hours", "window", "rules", "last_tick", "last_publish_at",
              "events_seq", "resets", "error"):
        assert k in st, k
    assert st["state"] == "running" and st["offset"] == st["size"] == log.stat().st_size
    seq = feed.read_events(run)[-1]["seq"]
    append(log, quiet_lines())
    assert not eng.tick().published
    assert not eng.tick().published
    assert feed.read_events(run)[-1]["seq"] == seq


def test_live_alerts_match_batch_detect(live, tmp_path):
    eng, log, run = live
    for step in chain_a_steps():
        append(log, step)
    eng.tick()
    con = db.open_run(parse_batch(log, tmp_path / "parsed"))
    alerts, _, _ = det.run_rules(con, eng.rules)
    live_ids = {a["alert_id"] for a in load(run / "alerts.json")}
    assert live_ids == set(alerts["alert_id"].to_list()) and live_ids


def test_truncation_resets_and_regrows(live):
    eng, log, run = live
    steps = chain_a_steps()
    for step in steps:
        append(log, step)
    eng.tick()
    assert rule_steps(chain_a(run)) == CHAIN
    log.write_bytes(b"")
    append(log, steps[0])
    res = eng.tick()
    assert res.reset == "truncated" and res.published
    assert any(e["kind"] == "reset" and e["reason"] == "truncated" for e in feed.read_events(run))
    assert rule_steps(chain_a(run)) == CHAIN[:1]
    q = eng.table.con.execute("SELECT count(*) FILTER (WHERE ts_quality = 'backwards'), count(*) FROM events").fetchone()
    assert q[0] == 0 and q[1] == len(steps[0])


def test_restart_resumes_from_checkpoint(tmp_path):
    log = tmp_path / "chain.log"
    log.write_bytes(b"")
    run = tmp_path / "run"
    eng = LiveEngine(log, run)
    eng.start()
    steps = chain_a_steps()
    append(log, steps[0] + steps[1])
    eng.tick()
    eng.close()
    before = load(run / "index.json")
    seq = feed.read_events(run)[-1]["seq"]
    eng2 = LiveEngine(log, run)
    assert eng2.start()["mode"] == "resume"
    assert eng2.table.rows() == len(steps[0]) + len(steps[1])
    evs = feed.read_events(run, after_seq=seq)
    assert [e["kind"] for e in evs] == ["start"] and evs[0]["seq"] == seq + 1
    assert load(run / "index.json") == before
    append(log, steps[2])
    eng2.tick()
    assert rule_steps(chain_a(run)) == CHAIN[:3]
    eng2.close()
    assert feed.read_status(run)["state"] == "stopped"


def test_cli_once_and_guard(tmp_path):
    log = tmp_path / "x.log"
    append(log, chain_a_steps()[0])
    run = tmp_path / "run"
    assert live_main(["--input", str(log), "--run", str(run), "--once"]) == 0
    assert rule_steps(chain_a(run)) == CHAIN[:1]
    batch = tmp_path / "batch"
    batch.mkdir()
    (batch / "index.json").write_text('{"run": "batch", "incidents": []}', encoding="utf-8")
    assert live_main(["--input", str(log), "--run", str(batch), "--once"]) == 2
    assert not (batch / "live").exists()
    with pytest.raises(GuardError):
        LiveEngine(log, batch).start()
    assert live_main(["--input", str(log), "--run", str(batch), "--once", "--overwrite"]) == 0
    out = subprocess.run([sys.executable, "-m", "killchain", "--help"], cwd=ROOT, capture_output=True, text=True)
    assert any(l.split() == ["live", "ready"] for l in out.stdout.splitlines())


# ── replay ──────────────────────────────────────────────────────────────────

def write_slice(path: Path) -> dict:
    steps = chain_a_steps()
    lines, meta_steps = [], []
    for k, s in enumerate(steps, 1):
        own = [i for i, x in enumerate(s) if ATTACKER in x]
        meta_steps.append({"n": k, "rule_id": CHAIN[k - 1], "alert_id": None, "first": len(lines) + own[0] + 1,
                           "last": len(lines) + own[-1] + 1, "count": len(own)})
        lines += s
    path.write_bytes(("\n".join(lines) + "\n").encode())
    meta = {"source": "fixture", "ip": ATTACKER, "lines": len(lines), "steps": meta_steps}
    replay.meta_path(path).write_text(json.dumps(meta), encoding="utf-8")
    return meta


def test_replay_produces_incident_step_by_step(live, tmp_path):
    eng, log, run = live
    sl = tmp_path / "slice.log"
    write_slice(sl)
    seen = []

    def on_step(k):
        eng.tick()
        seen.append(rule_steps(chain_a(run)))

    marks = replay.play(sl, log, rate=100000, step_pause=0, on_step=on_step)
    assert [m["rule_id"] for m in marks] == CHAIN
    assert all(m["first_written_at"] <= m["last_written_at"] for m in marks)
    assert seen[:4] == [CHAIN[:1], CHAIN[:2], CHAIN[:3], CHAIN]


def test_replay_live_threaded_smoke(tmp_path):
    log = tmp_path / "raw" / "t.log"
    log.parent.mkdir()
    log.write_bytes(b"")
    run = tmp_path / "run"
    eng = LiveEngine(log, run, fast_settings(interval_s=0.5))
    eng.start()
    stop = threading.Event()
    th = threading.Thread(target=eng.run, args=(stop,), daemon=True)
    th.start()
    try:
        sl = tmp_path / "slice.log"
        write_slice(sl)
        replay.play(sl, log, rate=5000, step_pause=1.5)
        deadline = time.time() + 30
        while time.time() < deadline and rule_steps(chain_a(run)) != CHAIN:
            time.sleep(0.2)
        assert rule_steps(chain_a(run)) == CHAIN
    finally:
        stop.set()
        th.join(timeout=30)
        eng.close()
    lat = [p["latency_ms"]["read_to_publish"] for p in publishes(run) if p["latency_ms"]["read_to_publish"]]
    print("read_to_publish ms:", lat)
    assert lat and max(lat) < 5000
