from pathlib import Path

import pytest
import yaml

from killchain import attack
from killchain.attack import AttackError

ROOT = Path(__file__).resolve().parents[1]


def test_label_single_tactic():
    assert attack.label("T1110.001") == {"technique": "T1110.001", "technique_name": "Brute Force: Password Guessing",
                                         "tactic": "credential-access", "stage_no": 8,
                                         "kill_chain_stage": "Actions on Objectives"}


def test_label_needs_tactic_when_several():
    with pytest.raises(AttackError, match="several tactics"):
        attack.label("T1078")
    assert attack.label("T1078", "Initial Access")["stage_no"] == 3
    with pytest.raises(AttackError, match="is not in tactic"):
        attack.label("T1078", "exfiltration")


@pytest.mark.parametrize("name", ["Credential Access", "credential-access", "credential_access", "TA0006", " ta0006 "])
def test_tactic_forms(name):
    assert attack.tactic(name) == "credential-access"


def test_bad_ids():
    for bad in ("T999", "1110", "T9999", "T1110.999"):
        with pytest.raises(AttackError):
            attack.technique(bad)
    with pytest.raises(AttackError):
        attack.tactic("hacking")


def test_stage_order_and_phases():
    t = attack.all_tactics()
    assert [x["stage_no"] for x in t] == list(range(1, 15))
    assert t[0]["shortname"] == "reconnaissance" and t[-1]["shortname"] == "impact"
    assert attack.kill_chain_stage("persistence") == "Installation"


def test_silver_truth_labels_are_valid():
    """Every technique, alternate and tactic in the silver truth exists, and the tactic fits the technique."""
    spec = yaml.safe_load((ROOT / "eval" / "silver_truth.yaml").read_text(encoding="utf-8"))
    for inc in spec["incidents"]:
        for s in inc["steps"]:
            attack.label(s["technique"], s["tactic"])
            attack.check_alternates(s.get("alt", []))


def test_unknown_label():
    assert attack.unknown_label("impact")["stage_no"] == 14 and attack.unknown_label()["technique"] == "unknown"
