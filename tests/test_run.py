"""python -m killchain run: the whole pipeline on small synthetic logs, and its failure modes."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from killchain.run.cli import main as run_main
from killchain.run.pipeline import STAGES, merge_summary

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 27, 12, 0, 0)   # local (+0530) wall clock


def line(t: datetime, kv: str, sub: str = "system", typ: str = "event") -> str:
    et = int(t.replace(tzinfo=timezone.utc).timestamp()) * 10**9
    return (f'date={t:%Y-%m-%d} time={t:%H:%M:%S} eventtime={et} tz="+0530" devname="FGT" devid="FGT" '
            f'logid="1" type="{typ}" subtype="{sub}" level="notice" vd="root" {kv}')


def attack_lines():
    """Brute force, port scan, failures-then-success, IPS and malware, all with good timestamps."""
    L = []
    fail = 'logdesc="Admin login failed" user="admin" srcip={ip} dstip=10.10.99.1 action="login" status="failed"'
    for i in range(120):
        L.append(line(T0 + timedelta(seconds=2 * i), fail.format(ip="1.1.1.1")))
    for i in range(30):
        L.append(line(T0 + timedelta(minutes=2 * i), fail.format(ip="2.2.2.2")))
    for i in range(300):
        L.append(line(T0 + timedelta(hours=2, seconds=0.4 * i),
                      f'srcip=3.3.3.3 srcport=40000 dstip=10.10.20.20 dstport={i + 1} action="deny" proto=6',
                      "forward", "traffic"))
    for i in range(25):
        L.append(line(T0 + timedelta(hours=3, seconds=10 * i), fail.format(ip=f"9.9.9.{i + 1}")))
    L.append(line(T0 + timedelta(hours=3, minutes=5),
                  'logdesc="Admin login successful" user="bob" srcip=9.9.9.77 dstip=10.10.99.1 action="login" status="success"'))
    L.append(line(T0 + timedelta(hours=5),
                  'logdesc="Admin login successful" user="eve" srcip=8.8.8.8 dstip=10.10.99.1 action="login" status="success"'))
    for h in (6, 6, 9, 9):
        L.append(line(T0 + timedelta(hours=h, minutes=len(L) % 7),
                      'srcip=4.4.4.4 dstip=10.10.20.20 dstport=443 action="dropped" attack="HTTP.URI.SQL.Injection"',
                      "ips", "utm"))
    for i in range(3):
        L.append(line(T0 + timedelta(hours=10, minutes=3 * i),
                      'srcip=10.10.10.118 dstip=7.154.5.35 action="detected" virus="JS/Nemucod.A!tr.dldr" '
                      'hostname="kjhsdf.duckdns.org" url="/invoice/a.zip"', "virus", "utm"))
    L.append(line(T0 + timedelta(hours=10, minutes=20),
                  'srcip=10.10.10.50 dstip=7.154.5.35 action="blocked" virus="EICAR_TEST_FILE" '
                  'hostname="kjhsdf.duckdns.org" url="/eicar.com"', "virus", "utm"))
    return L


def args(tmp: Path, inp: Path, name: str, *extra: str):
    return ["--input", str(inp), "--name", name, "--data-dir", str(tmp / "data"),
            "--ti-cache", str(tmp / "ti.sqlite"), "--workers", "1", *extra]


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def by_name(rec):
    return {s["name"]: s for s in rec["stages"]}


@pytest.fixture(scope="module")
def full_run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("run")
    log = tmp / "attack.log"
    log.write_text("\n".join(attack_lines()) + "\n", encoding="utf-8")
    code = run_main(args(tmp, log, "attack", "--offline", "--no-llm"))
    return tmp, log, code


def copy_run(full_run, tmp_path: Path) -> Path:
    src, log, _ = full_run
    shutil.copytree(src / "data", tmp_path / "data")
    shutil.copy(log, tmp_path / "attack.log")
    return tmp_path / "data" / "runs" / "attack"


def test_full_run_merges_run_summary(full_run):
    tmp, _, code = full_run
    assert code == 0
    run = tmp / "data" / "runs" / "attack"
    summary = load(run / "run_summary.json")
    for k in ("counts", "stages", "data_quality", "threat_intel", "llm", "bundled_at", "pipeline"):
        assert k in summary, k
    rec = summary["pipeline"]
    assert [s["name"] for s in rec["stages"]] == STAGES
    for s in rec["stages"]:
        if s["status"] != "skipped":
            assert s["status"] == "ok", s
            assert s["wall_secs"] >= 0 and s["peak_rss_mb"] > 0
    assert by_name(rec)["narrate"]["status"] == "skipped" and by_name(rec)["narrate"]["reason"] == "--no-llm"
    assert load(run / "pipeline.json") == rec
    assert summary["counts"]["incidents"] >= 1
    assert (run / "logs" / "detect.log").exists()


def test_no_stuck_region(full_run):
    tmp, _, _ = full_run
    summary = load(tmp / "data" / "runs" / "attack" / "run_summary.json")
    assert summary["data_quality"]["events_frozen_clock"] == 0
    rec = summary["pipeline"]
    assert by_name(rec)["parse"]["counts"]["rows"]["firewall"] == len(attack_lines())
    assert rec["status"] == "ok" and rec["exit_code"] == 0 and rec["warnings"] == []


def test_offline_enrich(full_run):
    tmp, _, _ = full_run
    summary = load(tmp / "data" / "runs" / "attack" / "run_summary.json")
    enrich = by_name(summary["pipeline"])["enrich"]
    assert enrich["status"] == "ok" and enrich["counts"]["offline"] is True
    assert summary["threat_intel"]["offline"] is True


def test_merge_keeps_existing_fields(tmp_path):
    p = tmp_path / "run_summary.json"
    p.write_text(json.dumps({"counts": {"a": 1}, "x": 1, "pipeline": {"old": 1}}), encoding="utf-8")
    assert merge_summary(tmp_path, {"name": "r", "status": "ok"}) is None
    doc = load(p)
    assert doc["x"] == 1 and doc["counts"] == {"a": 1} and doc["pipeline"] == {"name": "r", "status": "ok"}

    p.write_bytes(b"{not json")
    warn = merge_summary(tmp_path, {"name": "r"})
    assert warn and "not valid JSON" in warn
    assert p.read_bytes() == b"{not json"

    p.unlink()
    assert merge_summary(tmp_path, {"name": "r"}) is None
    assert load(p) == {"run": "r", "pipeline": {"name": "r"}}


def test_rebundle_keeps_pipeline_json(full_run, tmp_path):
    run = copy_run(full_run, tmp_path)
    before = (run / "pipeline.json").read_bytes()
    r = subprocess.run([sys.executable, "-m", "killchain.bundle", "--run", str(run)], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 0, r.stderr
    assert (run / "pipeline.json").read_bytes() == before


def test_empty_file(tmp_path, capsys):
    log = tmp_path / "empty.log"
    log.write_bytes(b"")
    assert run_main(args(tmp_path, log, "empty", "--offline", "--no-llm")) == 3
    assert "the file is empty (0 bytes)" in capsys.readouterr().err
    run = tmp_path / "data" / "runs" / "empty"
    rec = load(run / "pipeline.json")
    assert rec["status"] == "no_events" and rec["exit_code"] == 3
    st = by_name(rec)
    assert st["parse"]["status"] == "ok"
    assert all(st[s]["status"] == "skipped" for s in STAGES[1:])
    assert not (run / "events.duckdb").exists()


def test_binary_only(tmp_path, capsys):
    log = tmp_path / "binary.log"
    log.write_bytes(bytes(range(256)) * 64)
    assert run_main(args(tmp_path, log, "binary", "--offline", "--no-llm")) == 3
    assert "rejected:binary" in capsys.readouterr().err
    assert load(tmp_path / "data" / "runs" / "binary" / "pipeline.json")["status"] == "no_events"


def test_truncated_file(tmp_path):
    lines = attack_lines()
    lines[-1] = lines[-1][: len(lines[-1]) // 2]
    log = tmp_path / "cut.log"
    log.write_text("\n".join(lines), encoding="utf-8")       # no trailing newline
    assert run_main(args(tmp_path, log, "cut", "--offline", "--no-llm")) == 0
    summary = load(tmp_path / "data" / "runs" / "cut" / "run_summary.json")
    assert by_name(summary["pipeline"])["parse"]["counts"]["lines"] == len(lines)
    assert summary["counts"]["incidents"] >= 1


def test_missing_input(tmp_path, capsys):
    assert run_main(args(tmp_path, tmp_path / "nope.log", "nope")) == 2
    assert "run: not a file" in capsys.readouterr().err
    assert not (tmp_path / "data").exists()


def test_bad_name(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text("x\n", encoding="utf-8")
    assert run_main(args(tmp_path, log, "../evil")) == 2
    assert "bad run name" in capsys.readouterr().err
    assert not (tmp_path / "data").exists()


def test_no_llm_key_and_reuse_parsed(full_run, tmp_path, monkeypatch, capsys):
    import killchain.agents.settings as llm_settings

    copy_run(full_run, tmp_path)
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setattr(llm_settings, "endpoints", lambda *a, **k: [])
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    assert run_main(args(tmp_path, full_run[1], "attack", "--reuse-parsed")) == 0   # the file that was parsed
    err = capsys.readouterr().err
    rec = load(tmp_path / "data" / "runs" / "attack" / "pipeline.json")
    st = by_name(rec)
    assert st["parse"]["status"] == "skipped" and st["parse"]["reason"] == "--reuse-parsed"
    assert st["parse"]["counts"]["rows"]["firewall"] == len(attack_lines())
    assert st["prepare"]["status"] == "skipped" and st["prepare"]["reason"] == "--reuse-parsed"
    assert st["narrate"]["status"] == "skipped" and "no LLM key" in st["narrate"]["reason"]
    assert any("no LLM key" in w for w in rec["warnings"]) and "no LLM key" in err
    assert st["bundle"]["status"] == "ok" and rec["exit_code"] == 0 and rec["status"] == "ok_with_warnings"


def test_reuse_parsed_mismatch(full_run, tmp_path, capsys):
    copy_run(full_run, tmp_path)
    other = tmp_path / "other.log"
    other.write_text("\n".join(attack_lines()[:10]) + "\n", encoding="utf-8")
    before = (tmp_path / "data" / "runs" / "attack" / "pipeline.json").read_bytes()
    assert run_main(args(tmp_path, other, "attack", "--reuse-parsed")) == 2
    err = capsys.readouterr().err
    assert "--reuse-parsed" in err and str(full_run[1].resolve()) in err
    assert (tmp_path / "data" / "runs" / "attack" / "pipeline.json").read_bytes() == before


def test_network_down(full_run, tmp_path, monkeypatch):
    copy_run(full_run, tmp_path)
    monkeypatch.setenv("OTX_API_KEY", "dummy")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    a = args(tmp_path, tmp_path / "attack.log", "attack", "--from", "enrich", "--no-llm")
    a[a.index("--ti-cache") + 1] = str(tmp_path / "ti-net.sqlite")      # fresh cache: no hits
    assert run_main(a) == 0
    rec = load(tmp_path / "data" / "runs" / "attack" / "pipeline.json")
    st = by_name(rec)
    assert all(st[s]["reason"] == "--from enrich" for s in STAGES[:STAGES.index("enrich")])
    assert st["enrich"]["status"] == "degraded"
    assert any("lookups failed" in w for w in rec["warnings"])
    assert st["bundle"]["status"] == "ok" and rec["status"] == "ok_with_warnings"


def test_from_reach_after_bundle_keeps_reach(full_run, tmp_path):
    """A rerun from reach after bundle (and score's renumbering) must still match each incident's lines."""
    run = copy_run(full_run, tmp_path)
    before = load(run / "reach.json")
    assert run_main(args(tmp_path, tmp_path / "attack.log", "attack", "--from", "reach", "--offline", "--no-llm")) == 0
    assert load(run / "reach.json") == before


def test_required_stage_failure(full_run, tmp_path, capsys):
    src = full_run[0]
    shutil.copytree(src / "data" / "parsed", tmp_path / "data" / "parsed")
    (tmp_path / "data" / "runs" / "attack").mkdir(parents=True)
    assert run_main(args(tmp_path, full_run[1], "attack", "--from", "correlate")) == 1
    err = capsys.readouterr().err
    assert "correlate" in err and "alerts.parquet" in err
    rec = load(tmp_path / "data" / "runs" / "attack" / "pipeline.json")
    st = by_name(rec)
    assert rec["status"] == "failed" and rec["exit_code"] == 1
    assert st["correlate"]["status"] == "failed" and st["correlate"]["tail"]
    for s in STAGES[STAGES.index("correlate") + 1:]:
        assert st[s]["status"] == "skipped" and st[s]["reason"] == "earlier stage correlate failed"


def test_from_needs_parse(tmp_path, capsys):
    log = tmp_path / "a.log"
    log.write_text("\n".join(attack_lines()[:5]) + "\n", encoding="utf-8")
    assert run_main(args(tmp_path, log, "a", "--from", "detect")) == 2
    assert "needs an earlier parse" in capsys.readouterr().err
    assert not (tmp_path / "data" / "runs" / "a").exists()


def test_help_lists_run_ready(capsys):
    from killchain.__main__ import main

    assert main([]) == 0
    rows = dict(l.split(None, 1) for l in capsys.readouterr().out.splitlines() if l.startswith("  "))
    assert rows["run"].strip() == "ready"
    for n in ("enrich", "agents", "bundle", "serve", "live"):
        assert rows[n].strip() == "ready"
