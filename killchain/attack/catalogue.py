"""ATT&CK lookups and kill chain stages (P5).

    from killchain.attack import technique, label
    technique("T1110.001")      -> Technique(id, name, tactics, parent)
    label("T1110.001")          -> {technique, technique_name, tactic, stage_no, kill_chain_stage}
    label("T1078", "initial-access")   # a technique with several tactics needs one chosen

Tactic names are accepted in any common form: "Credential Access",
"credential-access", "credential_access", "TA0006".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

HERE = Path(__file__).resolve().parent
CATALOGUE = HERE / "data" / "attack_catalogue.json"
KILLCHAIN = HERE.parents[1] / "config" / "killchain.yml"
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class AttackError(ValueError):
    pass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: Tuple[str, ...]          # shortnames, e.g. ("credential-access",)
    parent: Optional[str]

    @property
    def full_name(self) -> str:
        """'Brute Force: Password Guessing' for a sub-technique, the name otherwise."""
        if self.parent:
            return f"{_techniques()[self.parent].name}: {self.name}"
        return self.name


@lru_cache(maxsize=1)
def _catalogue() -> dict:
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _tactics() -> Dict[str, dict]:
    """shortname -> {id, shortname, name, stage_no, phase}, from config/killchain.yml."""
    rows = yaml.safe_load(KILLCHAIN.read_text(encoding="utf-8"))["tactics"]
    out = {r["tactic"]: {"id": r["id"], "shortname": r["tactic"], "name": r["name"],
                         "stage_no": int(r["stage_no"]), "phase": r["phase"]} for r in rows}
    cat_ids = {t["id"] for t in _catalogue()["tactics"]}
    missing = {v["id"] for v in out.values()} - cat_ids
    if missing:
        raise AttackError(f"config/killchain.yml has tactics not in the catalogue: {sorted(missing)}")
    return out


@lru_cache(maxsize=1)
def _alias() -> Dict[str, str]:
    a: Dict[str, str] = {}
    for short, t in _tactics().items():
        for k in (short, t["id"], t["name"], short.replace("-", "_"), short.replace("-", " ")):
            a[k.lower()] = short
    return a


@lru_cache(maxsize=1)
def _techniques() -> Dict[str, Technique]:
    by_id = {t["id"]: t["shortname"] for t in _catalogue()["tactics"]}
    return {t["id"]: Technique(t["id"], t["name"], tuple(by_id[x] for x in t["tactics"] if x in by_id), t.get("parent"))
            for t in _catalogue()["techniques"]}


def tactic(name: str) -> str:
    """Normalise a tactic name to its ATT&CK shortname."""
    key = str(name).strip().lower()
    if key in _alias():
        return _alias()[key]
    raise AttackError(f"unknown tactic {name!r}")


def tactic_info(name: str) -> dict:
    return dict(_tactics()[tactic(name)])


def stage_no(name: str) -> int:
    return _tactics()[tactic(name)]["stage_no"]


def kill_chain_stage(name: str) -> str:
    return _tactics()[tactic(name)]["phase"]


def technique(tid: str) -> Technique:
    t = str(tid).strip().upper()
    if not TECHNIQUE_RE.match(t):
        raise AttackError(f"{tid!r} is not a technique id (T1234 or T1234.001)")
    try:
        return _techniques()[t]
    except KeyError:
        raise AttackError(f"{tid!r} is not in the ATT&CK catalogue") from None


def is_technique(tid: str) -> bool:
    try:
        technique(tid)
        return True
    except AttackError:
        return False


def parent(tid: str) -> str:
    return str(tid).split(".")[0]


def label(tid: str, tactic_name: Optional[str] = None) -> dict:
    """Full label for a technique. The tactic must be one of the technique's tactics;
    when the technique has only one, it may be left out."""
    t = technique(tid)
    if tactic_name is None:
        if len(t.tactics) != 1:
            raise AttackError(f"{t.id} has several tactics {list(t.tactics)}; choose one")
        tac = t.tactics[0]
    else:
        tac = tactic(tactic_name)
        if tac not in t.tactics:
            raise AttackError(f"{t.id} ({t.name}) is not in tactic {tac}; its tactics are {list(t.tactics)}")
    info = _tactics()[tac]
    return {"technique": t.id, "technique_name": t.full_name, "tactic": tac,
            "stage_no": info["stage_no"], "kill_chain_stage": info["phase"]}


def unknown_label(tactic_name: Optional[str] = None) -> dict:
    """Label for an anomaly alert without a technique; uses the tactic's stage if one is given."""
    if tactic_name is None:
        return {"technique": "unknown", "technique_name": None, "tactic": "discovery",
                "stage_no": stage_no("discovery"), "kill_chain_stage": kill_chain_stage("discovery")}
    tac = tactic(tactic_name)
    return {"technique": "unknown", "technique_name": None, "tactic": tac,
            "stage_no": stage_no(tac), "kill_chain_stage": kill_chain_stage(tac)}


def check_alternates(alts: List[str]) -> List[str]:
    """Normalised list; raises on an id not in the catalogue."""
    return [technique(a).id for a in alts]


def all_tactics() -> List[dict]:
    """The 14 tactics in kill chain order."""
    return sorted((dict(v) for v in _tactics().values()), key=lambda t: t["stage_no"])
