"""P11 bundle step (track B): merge stage outputs into the files the API serves.

Runs on copies of examples/sample-run; OTX is mocked, nothing reaches the network.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import polars as pl
import pytest

from killchain.api import create_app
from killchain.api.bundle import load_bundle, load_threat_intel
from killchain.bundle.__main__ import main as bundle_main
from killchain.bundle.build import build, data_quality, run_bundle
from killchain.bundle.merge import bind_enrichment
from killchain.contracts import validate_bundle
from killchain.enrich.cache import TiCache
from killchain.enrich.engine import enrich_run

from test_api_ti import Recorder, general

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"
ATTACKER = "32.127.48.11"


def rd(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def wr(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def run(tmp_path: Path) -> Path:
    """The sample laid out like a pipeline run: no threat intel yet, chains.json from the incident."""
    r = tmp_path / "runs" / "demo"
    shutil.copytree(SAMPLE, r)
    (r / "enrichment.json").unlink(missing_ok=True)
    inc = rd(r / "incidents" / "1.json")
    wr(r / "chains.json", {"run": "demo", "incidents": [{
        "incident_id": inc["incident_id"], "incident_number": 1, "chain_text": inc["chain_text"],
        "chain": [{**s, "enrichment_flags": []} for s in inc["chain"]], "gaps": inc["gaps"],
        "tactics": inc["tactics"], "techniques": inc["techniques"], "graph": inc["graph"]}]})
    return r


def enrich(r: Path, tmp_path: Path, pulses: int = 0) -> dict:
    incidents = {1: rd(r / "incidents" / "1.json")}
    cache = TiCache(tmp_path / f"cache-{pulses}.sqlite")
    answers = {ATTACKER: general(pulses, ["Cobalt Strike"] if pulses else [])}
    doc = enrich_run(incidents, rd(r / "alerts.json"), cache, otx_client=Recorder(answers).client())
    cache.close()
    wr(r / "enrichment.json", doc)
    return doc


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")


def test_bundle_without_threat_intel_is_contract_valid(run):
    res = run_bundle(run)
    assert res.errors == [] and res.warnings[:1] == ["no parser _stats.json found (give --parsed); data quality is left empty"]
    inc, index, alerts = rd(run / "incidents" / "1.json"), rd(run / "index.json"), rd(run / "alerts.json")
    assert validate_bundle(inc, index, alerts) == []
    own = {e["verdict"] for e in inc["enrichment"].values()}          # the incident's own (placeholder) results
    assert index["incidents"][0]["ti_verdict"] == (max(own, key=["unknown", "no-reports", "suspicious", "known-malicious"].index) if own else None)
    assert index["incidents"][0]["triage_verdict"] == ((inc["report"].get("triage") or {}).get("verdict"))
    assert not (run / "ti.json").exists()
    assert rd(run / "unexplained.json") == {"run": index["run"], "alerts": []}
    summary = rd(run / "run_summary.json")
    assert summary["sample"] is True                      # carried over from the sample
    assert summary["counts"]["incidents"] == 1 and summary["counts"]["alerts"] == len(alerts)
    assert summary["threat_intel"] is None and summary["llm"]["reports"] == 0
    assert "bundle" in summary["stages"] and rd(run / "bundle" / "_stats.json")["stage"] == "bundle"


def test_threat_intel_is_bound_and_served_from_ti_json(run, tmp_path, key):
    enrich(run, tmp_path, pulses=7)
    res = run_bundle(run)
    assert res.errors == []
    inc = rd(run / "incidents" / "1.json")
    assert inc["enrichment"][ATTACKER]["verdict"] == "known-malicious"
    flagged = [s for s in inc["chain"] if any("OTX" in f for f in s["enrichment_flags"])]
    assert flagged and all(ATTACKER in (s["src"], s["dst"]) for s in flagged)
    assert rd(run / "index.json")["incidents"][0]["ti_verdict"] == "known-malicious"
    ti = rd(run / "ti.json")
    assert ti["entities"][ATTACKER]["incidents"] == [1] and ti["bound"]["not_enriched"] == []
    assert rd(run / "run_summary.json")["threat_intel"]["indicators"] == len(ti["entities"])

    b = load_bundle(run)
    assert b.enrichment_source == "ti.json" and b.errors == []
    from fastapi.testclient import TestClient
    c = TestClient(create_app(run, raw_dir=tmp_path, ti_cache=tmp_path / "api.sqlite", ti_offline=True))
    assert c.get("/ti/status").json()["source"] == "ti.json"
    assert c.get("/incidents").json()["incidents"][0]["ti_verdict"] == "known-malicious"


def test_rebundle_drops_old_flags_and_is_stable(run, tmp_path, key):
    enrich(run, tmp_path, pulses=7)
    run_bundle(run)
    enrich(run, tmp_path, pulses=0)                # the attacker turns out clean
    run_bundle(run)
    inc = rd(run / "incidents" / "1.json")
    assert all(not any("OTX" in f for f in s["enrichment_flags"]) for s in inc["chain"])
    assert inc["enrichment"][ATTACKER]["verdict"] == "no-reports"
    first = {p.name: p.read_bytes() for p in (run / "incidents").iterdir()}
    first["index.json"] = (run / "index.json").read_bytes()
    run_bundle(run)
    again = {p.name: p.read_bytes() for p in (run / "incidents").iterdir()}
    again["index.json"] = (run / "index.json").read_bytes()
    assert again == first


def test_bind_matches_by_value_after_renumbering(run, tmp_path, key):
    doc = enrich(run, tmp_path, pulses=7)
    for e in doc["entities"].values():               # as if the score renumbered incident 1 -> 7 later
        e["incidents"] = [7]
    doc["steps"] = {"7": doc["steps"].get("1", {})}
    doc["entities"]["198.18.0.1"] = {**doc["entities"][ATTACKER]}
    incidents = {1: rd(run / "incidents" / "1.json")}
    bound, missing, dropped = bind_enrichment(doc, incidents, rd(run / "alerts.json"))
    assert bound["entities"][ATTACKER]["incidents"] == [1]
    assert "1" in bound["steps"] and "7" not in bound["steps"]
    assert missing == [] and dropped == ["198.18.0.1"]


def test_newer_enrichment_wins_over_stale_ti_json(run, tmp_path, key):
    enrich(run, tmp_path)
    run_bundle(run)
    doc = rd(run / "enrichment.json")
    doc["generated_at"] = "2099-01-01T00:00:00Z"
    wr(run / "enrichment.json", doc)
    assert load_threat_intel(run)[1] == "enrichment.json"
    (run / "enrichment.json").unlink()
    assert load_threat_intel(run)[1] == "ti.json"
    run_bundle(run)                                   # enrich output gone: the old ti.json goes too
    assert not (run / "ti.json").exists()


def test_report_json_is_merged_by_incident_id(run):
    inc_id = rd(run / "incidents" / "1.json")["incident_id"]
    wr(run / "report.json", {"generated_at": "2026-10-31T00:00:00Z", "model": "test", "incidents": {
        inc_id: {"source": "ai", "markdown": "## Summary\nA web attack.",
                 "triage": {"verdict": "looks_real", "confidence": 0.9, "reasons": ["4 linked steps"]}},
        "not-in-run": {"source": "ai", "markdown": "x", "triage": None}}})
    res = run_bundle(run)
    assert res.errors == []
    inc = rd(run / "incidents" / "1.json")
    assert inc["report_source"] == "ai" and inc["report"]["markdown"].startswith("## Summary")
    assert rd(run / "index.json")["incidents"][0]["triage_verdict"] == "looks_real"
    assert any("not-in-run" in w for w in res.warnings)
    assert rd(run / "run_summary.json")["llm"]["reports"] == 1


def test_contract_error_writes_nothing(run):
    inc = rd(run / "incidents" / "1.json")
    inc["risk_band"] = "extreme"
    wr(run / "incidents" / "1.json", inc)
    before = (run / "index.json").read_bytes()
    assert bundle_main(["--run", str(run)]) == 1
    assert (run / "index.json").read_bytes() == before
    assert not (run / "unexplained.json").exists() and not (run / "bundle").exists()


def test_check_flag_writes_nothing(run):
    assert bundle_main(["--run", str(run), "--check"]) == 0
    assert not (run / "unexplained.json").exists()


def test_alert_membership_and_unexplained(run):
    alerts = rd(run / "alerts.json")
    inc = rd(run / "incidents" / "1.json")
    step_ids = {s["alert_id"] for s in inc["chain"]}
    alerts[0]["incident_number"] = None               # stale value from an older stage
    wr(run / "alerts.json", alerts)
    pl.DataFrame({"alert_id": [alerts[1]["alert_id"]], "rule_id": [alerts[1]["rule_id"]],
                  "group_id": ["g1"], "reason": ["single anomaly detector"]}).write_parquet(run / "unexplained.parquet")
    res = run_bundle(run)
    out = rd(run / "alerts.json")
    assert all((a["incident_number"] == 1) == (a["alert_id"] in step_ids) for a in out)
    assert any("stale incident_number" in w for w in res.warnings)
    un = rd(run / "unexplained.json")["alerts"]
    assert [(a["alert_id"], a["reason"], a["group_id"]) for a in un] == [(alerts[1]["alert_id"], "single anomaly detector", "g1")]


def test_incident_lines_follow_incident_id(run):
    inc = rd(run / "incidents" / "1.json")
    pl.DataFrame({"incident_id": [inc["incident_id"], "gone"], "incident_number": [5, 6], "step": [1, 1],
                  "line": [10, 11]}).write_parquet(run / "incident_lines.parquet")
    res = run_bundle(run)
    lines = pl.read_parquet(run / "incident_lines.parquet")
    assert lines["incident_number"].to_list() == [1]
    assert any("no longer in the run" in w for w in res.warnings)
    assert rd(run / "run_summary.json")["counts"]["evidence_lines"] == 1


def test_run_summary_stages_and_data_quality(run, tmp_path):
    parsed = tmp_path / "parsed" / "demo"
    wr(parsed / "_stats.json", {
        "inputs": [{"path": "C:\\data\\raw\\firex-10G.log"}], "wall_secs": 50.0, "peak_rss_mb": 4000,
        "bytes": 100, "lines": 20, "lines_by_class": {"firewall": 15, "rejected:binary": 4, "blank": 1},
        "streams": {"firewall": {"rows": 15, "ts_quality": {"ok": 10, "stuck": 5},
                                 "first_ok_utc": "2026-10-23T03:18:26+00:00", "last_ok_utc": "2026-10-30T03:18:25+00:00"}},
        "junk_ranges": [{"source": "firex-10G.log", "start": 80, "end": 100, "bytes": 20, "lines": 4}],
        "junk_small": {"ranges": 0, "bytes": 0}, "summary": {"firewall": {"exact_duplicate_rows": 2}}})
    wr(run / "detect" / "_stats.json", {"stage": "detect", "wall_secs": 13.0, "peak_rss_mb": 1000, "alerts": 4})
    wr(run / "detect-only" / "_stats.json", {"stage": "detect", "wall_secs": 999.0, "peak_rss_mb": 99999})
    res = build(run, parsed)
    s = res.summary
    assert s["source"] == "firex-10G.log"
    assert set(s["stages"]) == {"parse", "detect"}
    assert s["totals"] == {"processing_secs": 63.0, "peak_rss_mb": 4000}
    dq = s["data_quality"]
    assert (dq["events"], dq["events_frozen_clock"], dq["rejected_lines"], dq["junk_bytes"], dq["exact_duplicate_rows"]) == (15, 5, 4, 20, 2)
    assert data_quality(None) is None


def test_parsed_folder_is_found_next_to_runs(run, tmp_path):
    wr(tmp_path / "parsed" / "demo" / "_stats.json", {"wall_secs": 1.0, "peak_rss_mb": 10, "streams": {}})
    assert "parse" in build(run).summary["stages"]


def test_missing_required_input(tmp_path):
    (tmp_path / "empty").mkdir()
    assert bundle_main(["--run", str(tmp_path / "empty")]) == 1
