"""Provisional contract-C bundle files: incidents/<n>.json, index.json and alerts.json.

The P11 `bundle` step (track B) is the final writer of these files. Until it exists, `chain` (and `reach`
in P8) write them so the API and `eval score` can read a real run. Fields owned by later phases get
contract-valid placeholders: risk parts with zero points (P10), empty enrichment (P9), a template report
marked provisional (P10) and, from `chain`, an empty reach next (P8).

Writing is all-or-nothing: everything is checked against the contracts first, and on success each file is
written under a temporary name and renamed into place. The incidents/ folder is swapped as a whole, so
stale <n>.json files from an earlier run never survive.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import polars as pl

from ..contracts import validate_bundle
from .chain import ist, iso_z

RISK_WEIGHTS = {"severity": 0.25, "stage": 0.20, "breadth": 0.10, "success": 0.15, "asset": 0.15,
                "reach": 0.10, "threat_intel": 0.05}
NEXT_PLACEHOLDER = {"reachable": [], "sentence": "Reach next has not been computed for this run yet.",
                    "likely_tactics": []}
PROVISIONAL = "Provisional: the full template report arrives in P10."


def _report(chain_part: Dict[str, Any]) -> str:
    lines = ["**Chain**"]
    for s in chain_part["chain"]:
        lines.append(f"{s['n']}. {s['ts_start_ist']} IST: {s['action']} ({s['technique']}, {s['tactic']})")
    if chain_part["gaps"]:
        lines += ["", "**Gaps**"] + [f"- {g}" for g in chain_part["gaps"]]
    lines += ["", PROVISIONAL]
    return "\n".join(lines)


def assemble(inc_row: Dict[str, Any], chain_part: Dict[str, Any],
             next_part: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A full contract-C incident from an incidents.parquet row and its chain (chain.build_chains)."""
    ents = inc_row.get("entities") or {}
    return {
        "incident_number": int(inc_row["incident_number"]), "incident_id": inc_row["incident_id"],
        "title": inc_row["title"], "risk_score": 0.0, "risk_band": "low",
        "risk_parts": {k: {"value": 0.0, "weight": w, "points": 0.0} for k, w in RISK_WEIGHTS.items()},
        "severity": int(inc_row["severity"]),
        "ts_start": iso_z(inc_row["ts_start"]), "ts_end": iso_z(inc_row["ts_end"]),
        "ts_start_ist": ist(inc_row["ts_start"]), "ts_end_ist": ist(inc_row["ts_end"]),
        "merged": {"alerts": int(inc_row["merged"]["alerts"]), "events": int(inc_row["merged"]["events"])},
        "entities": {k: list(ents.get(k) or []) for k in ("ips", "hosts", "users", "domains")},
        "tactics": chain_part["tactics"], "techniques": chain_part["techniques"],
        "chain_text": chain_part["chain_text"], "chain": chain_part["chain"], "gaps": chain_part["gaps"],
        "graph": chain_part["graph"], "enrichment": {},
        "next": next_part if next_part is not None else dict(NEXT_PLACEHOLDER),
        "report": {"source": "template", "markdown": _report(chain_part), "triage": None},
        "report_source": "template", "layers": list(inc_row.get("layers") or ["rule"]),
    }


def index_rows(incidents: List[Dict[str, Any]], run: str) -> Dict[str, Any]:
    keys = ("incident_number", "incident_id", "title", "risk_score", "risk_band", "severity", "ts_start",
            "ts_end", "ts_start_ist", "ts_end_ist", "merged", "tactics", "techniques")
    rows = [{**{k: i[k] for k in keys}, "triage_verdict": None, "ti_verdict": None}
            for i in sorted(incidents, key=lambda i: i["incident_number"])]
    return {"run": run, "incidents": rows}


def alerts_with_incidents(alerts_json: List[Dict[str, Any]], members: pl.DataFrame) -> List[Dict[str, Any]]:
    """alerts.json with incident_number set from the incident membership (null when in no incident)."""
    num = dict(members.select("alert_id", "incident_number").iter_rows())
    return [{**a, "incident_number": int(num[a["alert_id"]]) if a.get("alert_id") in num else None}
            for a in alerts_json]


def check(incidents: List[Dict[str, Any]], index: Dict[str, Any], alerts: List[Dict[str, Any]]) -> List[str]:
    """validate_bundle for every incident; the alert and index errors are reported once."""
    errors: List[str] = []
    seen = set()
    for inc in incidents:
        for e in validate_bundle(inc, index, alerts):
            if e not in seen:
                seen.add(e)
                errors.append(e)
    return errors


def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=1, ensure_ascii=False, default=str)


def _write_file(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if isinstance(obj, pl.DataFrame):
        obj.write_parquet(tmp)
    else:
        tmp.write_text(_dump(obj), encoding="utf-8")
    os.replace(tmp, path)


def write(run: Path, incidents: List[Dict[str, Any]], index: Dict[str, Any], alerts: List[Dict[str, Any]],
          extra_files: Optional[Dict[str, Any]] = None) -> None:
    """Write the bundle files atomically. Call only after check() returned no errors.
    extra_files: relative name -> JSON object or polars frame (written as parquet)."""
    run = Path(run)
    run.mkdir(parents=True, exist_ok=True)
    new, cur, old = run / "incidents.tmp", run / "incidents", run / "incidents.old"
    for p in (new, old):
        if p.exists():
            shutil.rmtree(p)
    new.mkdir()
    for inc in incidents:
        (new / f"{inc['incident_number']}.json").write_text(_dump(inc), encoding="utf-8")
    if cur.exists():
        os.replace(cur, old)
    os.replace(new, cur)
    if old.exists():
        shutil.rmtree(old)
    _write_file(run / "index.json", index)
    _write_file(run / "alerts.json", alerts)
    for name, obj in (extra_files or {}).items():
        _write_file(run / name, obj)
