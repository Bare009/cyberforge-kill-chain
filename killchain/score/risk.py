"""Risk score (docs/build-plan.md P10, B-1): a fixed weighted sum of seven parts, 0-100.

Each part is {value 0-1 (4 dp), weight, points = round(value x weight x 100, 2), detail}; risk_score is the
sum of the points (1 dp). Weights are incident_files.RISK_WEIGHTS. "Steps" are the numbered `chain[]`
steps (rule steps, or the anomaly steps of an anomaly-only incident); supporting anomalies do not raise
stage, breadth or success.

  severity      incident severity / 5 (highest alert severity)
  stage         highest step stage_no / 14
  breadth       1 at 3 or more distinct step tactics, else tactics / 6
  success       1 when any step got through
  asset         highest importance among path-graph nodes of kind internal_host, server or firewall that are
                not reach nodes (no `reach` key); 0 when none
  reach         important reachable hosts (importance >= 0.75: server, DMZ, management) / 3, capped at 1;
                observed count 1, inferred 0.5
  threat_intel  highest reputation among enrichment.json entities whose value is in the incident (entities,
                step and supporting src/dst) and whose verdict is not `unknown` (nobody outside answered);
                0 when none match or the file is missing

Ranking: (-risk_score, ts_start, incident_id), numbered 1..N.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..graph.chain import tactic_name
from ..graph.incident_files import RISK_WEIGHTS
from ..graph.path import node_for

PART_NAMES = {"severity": "Severity", "stage": "Stage reached", "breadth": "Breadth", "success": "Success",
              "asset": "Asset importance", "reach": "Reach next", "threat_intel": "Threat intel"}
IMPORTANT = 0.75
BREADTH_PER_TACTIC = 6
BREADTH_FULL = 3
REACH_FULL = 3
ASSET_KINDS = ("internal_host", "server", "firewall")
OFFLINE_NOTE = " (offline: cache and local context only)"
NO_TI_FILE = "no threat-intel data for this run (enrichment.json not found)"


def band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def load_enrichment(run: Path) -> Optional[Dict[str, Any]]:
    """The parsed <run>/enrichment.json, or None when the file is missing."""
    p = Path(run) / "enrichment.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _k(v: Any) -> str:
    return str(v).strip().lower()


def incident_values(inc: Dict[str, Any]) -> Set[str]:
    """Lower-cased entity values of the incident: its entities and every step and supporting src/dst."""
    ents = inc.get("entities") or {}
    out = {_k(v) for k in ("ips", "hosts", "users", "domains") for v in ents.get(k) or [] if v}
    for s in inc.get("chain") or []:
        for x in [s] + list(s.get("supporting") or []):
            out |= {_k(x[k]) for k in ("src", "dst") if x.get(k)}
    return out


def ti_matches(inc: Dict[str, Any], enrichment: Optional[Dict[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    """(value, entity) pairs of enrichment.json whose value is in the incident, sorted by (-reputation, value)."""
    if not enrichment:
        return []
    vals = incident_values(inc)
    hits = [(v, e) for v, e in (enrichment.get("entities") or {}).items() if isinstance(e, dict) and _k(v) in vals]
    return sorted(hits, key=lambda x: (-float(x[1].get("reputation") or 0), x[0]))


def _part(name: str, value: float, detail: str) -> Dict[str, Any]:
    v = round(min(max(float(value), 0.0), 1.0), 4)
    w = RISK_WEIGHTS[name]
    return {"value": v, "weight": w, "points": round(v * w * 100, 2), "detail": detail}


def risk_parts(inc: Dict[str, Any], net: Dict[str, Any], enrichment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The seven parts of one incident (module docstring), in RISK_WEIGHTS order."""
    steps = inc.get("chain") or []
    parts: Dict[str, Any] = {}

    sev = int(inc["severity"])
    parts["severity"] = _part("severity", sev / 5, f"highest alert severity {sev} of 5")

    if steps:
        top = max(steps, key=lambda s: int(s["stage_no"]))     # first step with the highest stage
        k = int(top["stage_no"])
        parts["stage"] = _part("stage", k / 14, f"furthest stage {tactic_name(top['tactic'])} ({k} of 14)")
    else:
        parts["stage"] = _part("stage", 0, "no numbered step")

    n_tac = len({s["tactic"] for s in steps})
    if n_tac >= BREADTH_FULL:
        parts["breadth"] = _part("breadth", 1.0, f"{n_tac} distinct tactics (full marks at {BREADTH_FULL} or more)")
    else:
        parts["breadth"] = _part("breadth", n_tac / BREADTH_PER_TACTIC,
                                 f"{n_tac} distinct tactic{'s' if n_tac != 1 else ''} "
                                 f"(one sixth each; full marks at {BREADTH_FULL} or more)")

    ok = [s for s in steps if s.get("success")]
    parts["success"] = _part("success", 1.0 if ok else 0.0,
                             f"step {ok[0]['n']} got through" if ok else "every step was blocked")

    nodes = [n for n in (inc.get("graph") or {}).get("nodes") or []
             if n.get("kind") in ASSET_KINDS and "reach" not in n]
    if nodes:
        best = max(nodes, key=lambda n: float(n["importance"]))      # first node with the highest importance
        imp = float(best["importance"])
        parts["asset"] = _part("asset", imp, f"{best['label']} ({best['zone']}, importance {imp:g})")
    else:
        parts["asset"] = _part("asset", 0, "no internal host or firewall touched")

    obs = inf = 0
    for r in (inc.get("next") or {}).get("reachable") or []:
        if float(node_for(r["host"], "ip", net)["importance"]) >= IMPORTANT:
            if r.get("kind") == "observed":
                obs += 1
            else:
                inf += 1
    c = obs + 0.5 * inf
    parts["reach"] = _part("reach", min(c / REACH_FULL, 1.0),
                           f"{obs} observed and {inf} inferred important hosts reachable next "
                           f"(server, DMZ, management)" if c else "no important host reachable next")

    if enrichment is None:
        parts["threat_intel"] = _part("threat_intel", 0, NO_TI_FILE)
    else:
        # verdict "unknown" means no outside provider answered, so there is no reputation to use
        hits = [(v, e) for v, e in ti_matches(inc, enrichment)
                if e.get("reputation") is not None and e.get("verdict") != "unknown"]
        if hits:
            v, e = hits[0]
            r = float(e["reputation"])
            detail = f"highest reputation {r:.2f} ({v}, {e.get('verdict') or 'unknown'})"
            parts["threat_intel"] = _part("threat_intel", r, detail)
        else:
            parts["threat_intel"] = _part("threat_intel", 0, "no entity of this incident has a reputation score")
        if enrichment.get("offline"):
            parts["threat_intel"]["detail"] += OFFLINE_NOTE
    return {k: parts[k] for k in RISK_WEIGHTS}


def apply_risk(inc: Dict[str, Any], parts: Dict[str, Any]) -> Dict[str, Any]:
    """Set risk_parts, risk_score and risk_band on the incident (in place); returns it."""
    score = round(sum(p["points"] for p in parts.values()), 1)
    inc["risk_parts"] = parts
    inc["risk_score"] = score
    inc["risk_band"] = band(score)
    return inc


def rank(incidents: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[int, int]]:
    """Incidents sorted by (-risk_score, ts_start, incident_id) and renumbered 1..N (in place), plus
    {old number: new number}."""
    ordered = sorted(incidents, key=lambda i: (-float(i["risk_score"]), i["ts_start"], i["incident_id"]))
    mapping: Dict[int, int] = {}
    for n, inc in enumerate(ordered, 1):
        mapping[int(inc["incident_number"])] = n
        inc["incident_number"] = n
    return ordered, mapping
