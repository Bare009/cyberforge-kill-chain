"""The sample run must match the contracts, and the validator must catch broken files."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from killchain.contracts import validate_alert, validate_bundle, validate_incident

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-run"


def load(name):
    return json.loads((SAMPLE / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def bundle():
    return load("incidents/1.json"), load("index.json"), load("alerts.json")


def test_sample_matches_contracts(bundle):
    assert validate_bundle(*bundle) == []


def test_sample_values(bundle):
    inc, index, alerts = bundle
    assert [s["n"] for s in inc["chain"]] == list(range(1, len(inc["chain"]) + 1))
    assert inc["merged"]["events"] == sum(s["event_count"] for s in inc["chain"]) == 940
    assert inc["merged"]["alerts"] == len(alerts) == 4
    assert index["incidents"][0]["incident_number"] == 1
    assert all(s["line_sample"] for s in inc["chain"])


@pytest.mark.parametrize("path,value,expect", [
    (("chain", 0, "n"), 2, "numbered 1..N"),
    (("risk_score",), 12.0, "not the sum"),
    (("graph", "edges", 0, "target"), "10.9.9.9", "not a node id"),
    (("chain", 1, "tactic"), "hacking", "not one of"),
    (("ts_start",), "2026-10-29 01:51:23", "ISO 8601"),
    (("report", "triage", "verdict"), "maybe", "not one of"),
])
def test_validator_catches(bundle, path, value, expect):
    inc = copy.deepcopy(bundle[0])
    target = inc
    for p in path[:-1]:
        target = target[p]
    target[path[-1]] = value
    errors = validate_incident(inc)
    assert any(expect in e for e in errors), errors


def test_validator_catches_missing_field(bundle):
    inc = copy.deepcopy(bundle[0])
    del inc["next"]
    assert any("next: missing" in e for e in validate_incident(inc))


def test_alert_ranges(bundle):
    a = copy.deepcopy(bundle[2][0])
    a["severity"], a["confidence"], a["technique"] = 9, 1.5, "1110"
    errors = " ".join(validate_alert(a))
    assert "severity" in errors and "confidence" in errors and "technique" in errors


def test_evidence_points_at_real_lines(bundle):
    """Each sampled line must be the attacker's line in the raw log (skipped if the log is absent)."""
    raw = Path(__file__).resolve().parents[1] / "data" / "raw" / "firex-10G.log"
    if not raw.exists():
        raw = Path(__file__).resolve().parents[2] / "logs" / "firex-10G.log"
    if not raw.exists():
        pytest.skip("raw log not available")
    with open(raw, "rb") as f:
        for s in bundle[0]["chain"]:
            for ln in s["line_sample"][:3]:
                f.seek(ln["byte_offset"])
                line = f.readline()
                assert b"srcip=32.127.48.11 " in line and b"dstip=10.10.20.20 " in line, line[:200]
