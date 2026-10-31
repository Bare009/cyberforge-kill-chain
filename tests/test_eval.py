"""The scoring harness gives the right numbers on runs whose answer is known."""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl
import pytest

from killchain.eval import score as sc
from killchain.eval import truth as tr

ROOT = Path(__file__).resolve().parents[1]
REAL_RUN = ROOT / "data" / "runs" / "firex-10G"


def make_truth() -> pl.DataFrame:
    """Incident 1: one step, 10 lines. Incident 2: ordered, step 1 lines 100-104, step 2 lines 200-204."""
    rows = []
    for ln in range(1, 11):
        rows.append((1, "brute", "easy", False, 1, "fails", "T1110.001", ["T1110"], "credential-access", ln))
    for n, base, tech in ((1, 100, "T1595.002"), (2, 200, "T1190")):
        for ln in range(base, base + 5):
            rows.append((2, "chain", "insane", True, n, f"s{n}", tech, [], "initial-access", ln))
    df = pl.DataFrame(rows, schema=["incident_id", "incident_name", "class", "ordered", "step_n", "step_name",
                                    "technique", "alt", "tactic", "line"], orient="row")
    return df.with_columns(pl.lit("firewall").alias("stream"), pl.lit("x.log").alias("source"),
                           (pl.col("line") * 100).alias("byte_offset")).select(list(tr.TRUTH_SCHEMA)).cast(tr.TRUTH_SCHEMA)


def write_run(tmp: Path, alerts, incidents, stats=None) -> Path:
    """alerts: list of (alert_id, rule_id, layer, technique, [lines]); incidents: list of (number, [alert_ids])."""
    tmp.mkdir(parents=True, exist_ok=True)
    pl.DataFrame([{"alert_id": a, "rule_id": r, "layer": l, "technique": t} for a, r, l, t, _ in alerts],
                 schema={"alert_id": pl.Utf8, "rule_id": pl.Utf8, "layer": pl.Utf8, "technique": pl.Utf8}
                 ).write_parquet(tmp / "alerts.parquet")
    pl.DataFrame([{"alert_id": a, "source": "x.log", "line": ln, "technique": t} for a, _, _, t, lines in alerts for ln in lines],
                 schema={"alert_id": pl.Utf8, "source": pl.Utf8, "line": pl.Int64, "technique": pl.Utf8}
                 ).write_parquet(tmp / "alert_evidence.parquet")
    (tmp / "incidents").mkdir(exist_ok=True)
    for num, ids in incidents:
        inc = {"incident_number": num, "incident_id": f"inc{num}", "title": f"incident {num}",
               "chain": [{"n": i + 1, "alert_id": a} for i, a in enumerate(ids)]}
        (tmp / "incidents" / f"{num}.json").write_text(json.dumps(inc), encoding="utf-8")
    if stats:
        (tmp / "_stats.json").write_text(json.dumps(stats), encoding="utf-8")
    return tmp


def run_score(tmp, alerts, incidents, reviewed=None, stats=None, opens=None):
    return sc.score(make_truth(), sc.load_run(write_run(tmp, alerts, incidents, stats)), reviewed, None, opens)


def test_empty_run_scores_zero(tmp_path):
    r = run_score(tmp_path, [], [])
    assert r["metrics"]["detection_recall"] == 0 and r["metrics"]["attack_path_rebuilt"] == 0
    assert r["metrics"]["false_alarm_share"] == 0 and r["grades"]["detection_recall"] == "below"


def test_perfect_run(tmp_path):
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 11))),
              ("a2", "R02", "rule", "T1595.002", list(range(100, 105))),
              ("a3", "R16", "rule", "T1190", list(range(200, 205)))]
    r = run_score(tmp_path, alerts, [(1, ["a1"]), (2, ["a2", "a3"])],
                  stats={"wall_secs": 120, "peak_rss_mb": 4500}, opens=[3.0, 4.0, 5.0])
    m = r["metrics"]
    assert m["detection_recall"] == 1 and m["label_accuracy"] == 1 and m["attack_path_rebuilt"] == 1
    assert m["false_alarm_share"] == 0 and m["processing_secs"] == 120 and m["peak_rss_mb"] == 4500
    assert all(g == "great" for g in r["grades"].values())
    assert r["detail"]["multi_step_rebuilt"] == "1/1"


def test_partial_recall_and_labels(tmp_path):
    # half of incident 1 found with the parent technique; incident 2 fully found but step 2 mislabelled
    alerts = [("a1", "R01", "rule", "T1110", list(range(1, 6))),
              ("a2", "R02", "rule", "T1595.002", list(range(100, 105))),
              ("a3", "R16", "rule", "T1059", list(range(200, 205)))]
    r = run_score(tmp_path, alerts, [(1, ["a1"]), (2, ["a2", "a3"])])
    d = r["detail"]
    assert r["metrics"]["detection_recall"] == pytest.approx(15 / 20)
    assert d["label_exact"] == pytest.approx(5 / 15)          # only step 1 of incident 2
    assert d["label_parent"] == pytest.approx(10 / 15)        # + T1110 for T1110.001
    assert d["label_any"] == pytest.approx(10 / 15)           # T1110 is also in alt
    assert d["incidents_found"] == 1                          # incident 1 is at 50%, below 80%


def test_steps_out_of_order(tmp_path):
    alerts = [("a2", "R02", "rule", "T1595.002", list(range(100, 105))),
              ("a3", "R16", "rule", "T1190", list(range(200, 205)))]
    r = run_score(tmp_path, alerts, [(1, ["a3", "a2"])])      # exploit numbered before the scan
    p = {x["incident_id"]: x for x in r["paths"]}
    assert p[2]["rebuilt"] is False and p[2]["reason"] == "steps out of order"


def test_split_incident_is_not_rebuilt(tmp_path):
    alerts = [("a2", "R02", "rule", "T1595.002", list(range(100, 105))),
              ("a3", "R16", "rule", "T1190", list(range(200, 205)))]
    r = run_score(tmp_path, alerts, [(1, ["a2"]), (2, ["a3"])])
    p = {x["incident_id"]: x for x in r["paths"]}
    assert p[2]["rebuilt"] is False and p[2]["reason"] == "steps missing from the incident"


def test_false_alarms_and_review(tmp_path):
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 11))),
              ("n1", "R99", "rule", "T1046", [5000]), ("n2", "R99", "rule", "T1046", [6000]),
              ("n3", "R98", "anomaly", "unknown", [7000])]
    reviewed = {"inc3": {"real": True}}
    r = run_score(tmp_path, alerts, [(1, ["a1"]), (2, ["n1"]), (3, ["n2"]), (4, ["n3"])], reviewed)
    assert r["metrics"]["false_alarm_share"] == pytest.approx(2 / 4)   # inc3 reviewed as real
    assert {x["incident_id"] for x in r["detail"]["unreviewed"]} == {"inc2", "inc4"}
    rules = {x["rule_id"]: x for x in r["per_rule"]}
    assert rules["R99"]["background_alerts"] == 2 and rules["R01"]["truth_lines"] == 10


def test_anomaly_only_lines(tmp_path):
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 6))),
              ("x1", "ML", "anomaly", "unknown", list(range(1, 11)))]
    r = run_score(tmp_path, alerts, [(1, ["a1", "x1"])])
    assert r["detail"]["anomaly_only_lines"] == 5


def test_anomaly_only_false_incident(tmp_path):
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 11))),
              ("x1", "A04", "anomaly", "unknown", [9000])]
    r = run_score(tmp_path, alerts, [(1, ["a1"]), (2, ["x1"])])
    d = r["detail"]
    assert d["anomaly_only_incidents"] == 1 and d["anomaly_only_false"] == 1
    assert d["anomaly_alerts"] == 1 and d["anomaly_background_alerts"] == 1
    assert {x["rule_id"]: x["layer"] for x in r["per_rule"]} == {"R01": "rule", "A04": "anomaly"}


def test_anomaly_labels_do_not_lower_rule_metrics(tmp_path):
    # the anomaly alert covers the same lines with a wrong label, plus 5 lines no rule covers
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 11))),
              ("x1", "A01", "anomaly", "T1046", list(range(1, 11))),
              ("x2", "A02", "anomaly", "T1190", list(range(200, 205)))]
    r = run_score(tmp_path, alerts, [(1, ["a1", "x1"]), (2, ["x2"])])
    d = r["detail"]
    assert d["rule_layer_recall"] == pytest.approx(10 / 20)
    assert r["metrics"]["detection_recall"] == pytest.approx(15 / 20)
    assert d["rule_layer_label_accuracy"] == 1.0 and r["metrics"]["label_accuracy"] == 1.0
    assert d["anomaly_only_by_incident"] == [{"incident_id": 2, "incident_name": "chain", "lines": 5}]
    assert d["anomaly_only_incidents"] == 1 and d["anomaly_only_false"] == 0


def test_incidents_from_correlate_parquet(tmp_path):
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 11))),
              ("a2", "R02", "rule", "T1595.002", list(range(100, 105))),
              ("a3", "R16", "rule", "T1190", list(range(200, 205)))]
    run = write_run(tmp_path, alerts, [])                     # no incidents/*.json
    pl.DataFrame({"incident_number": [1, 2], "incident_id": ["i1", "i2"], "title": ["one", "two"]}
                 ).write_parquet(run / "incidents.parquet")
    pl.DataFrame({"incident_id": ["i2", "i1", "i2"], "alert_id": ["a3", "a1", "a2"], "step_n": [2, 1, 1]}
                 ).write_parquet(run / "incident_alerts.parquet")
    loaded = sc.load_run(run)
    assert [i["incident_id"] for i in loaded["incidents"]] == ["i1", "i2"]
    assert loaded["incidents"][1]["chain"] == [{"n": 1, "alert_id": "a2"}, {"n": 2, "alert_id": "a3"}]
    r = sc.score(make_truth(), loaded)
    assert r["metrics"]["attack_path_rebuilt"] == 1 and r["detail"]["our_incidents"] == 2
    assert r["detail"]["incidents_spanning_truth"] == []


def test_dominant_alert_sets_step_order(tmp_path):
    # an anomaly alert covers all of step 1 and one line of step 2 and comes first in the chain;
    # the step-2 rule alert is the dominant alert of step 2, so the order still holds
    alerts = [("x1", "A10", "anomaly", "unknown", list(range(100, 105)) + [200]),
              ("a2", "R02", "rule", "T1595.002", list(range(100, 105))),
              ("a3", "R16", "rule", "T1190", list(range(200, 205)))]
    r = run_score(tmp_path, alerts, [(1, ["x1", "a2", "a3"])])
    p = {x["incident_id"]: x for x in r["paths"]}
    assert p[2]["rebuilt"] is True


def test_incident_spanning_two_truth_incidents(tmp_path):
    alerts = [("a1", "R01", "rule", "T1110.001", list(range(1, 11))),
              ("a2", "R02", "rule", "T1595.002", list(range(100, 105)))]
    r = run_score(tmp_path, alerts, [(7, ["a1", "a2"])])
    assert r["detail"]["incidents_spanning_truth"] == [7]
    assert "wrong merges" in sc.render(r)


def test_manifest_for_another_file_is_refused(tmp_path):
    log = tmp_path / "x.log"
    log.write_bytes(b"line one\nline two\nline three\n")
    man = tmp_path / "m.json"
    man.write_text(json.dumps({"streams": {"0": "firewall"}, "incidents": [
        {"id": "1", "name": "n", "class": "easy", "attack": "T1110.001", "tactic": "Credential Access",
         "at": [[2, 3, 0], [3, 12, 0]]}]}), encoding="utf-8")
    with pytest.raises(tr.TruthError):
        tr.load_manifest(man, {"firewall": log})
    man.write_text(json.dumps({"streams": {"0": "firewall"}, "incidents": [
        {"id": "1", "name": "n", "class": "easy", "attack": "T1110.001, T1078", "tactic": "Credential Access",
         "at": [[2, 9, 0], [3, 18, 0]]}]}), encoding="utf-8")
    t = tr.load_manifest(man, {"firewall": log})
    assert t["line"].to_list() == [2, 3] and t["technique"][0] == "T1110.001" and t["alt"][0].to_list() == ["T1078"]


@pytest.mark.skipif(not (REAL_RUN / "truth.parquet").exists(), reason="real silver truth not built")
def test_real_truth_perfect_run(tmp_path):
    truth = pl.read_parquet(REAL_RUN / "truth.parquet")
    assert truth.height == 32_200 and truth["incident_id"].n_unique() == 25
    alerts, incidents = [], []
    for (iid,), g in truth.group_by("incident_id", maintain_order=True):
        ids = []
        for (n,), s in g.sort("step_n").group_by("step_n", maintain_order=True):
            aid = f"i{iid}s{n}"
            ids.append(aid)
            alerts.append((aid, "R", "rule", s["technique"][0], s["line"].to_list()))
        incidents.append((int(iid), ids))
    run = write_run(tmp_path, alerts, incidents)
    # evidence must use the real source name
    ev = pl.read_parquet(run / "alert_evidence.parquet").with_columns(pl.lit("firex-10G.log").alias("source"))
    ev.write_parquet(run / "alert_evidence.parquet")
    r = sc.score(truth, sc.load_run(run))
    assert r["metrics"]["detection_recall"] == 1 and r["metrics"]["label_accuracy"] == 1
    assert r["metrics"]["attack_path_rebuilt"] == 1 and r["metrics"]["false_alarm_share"] == 0
