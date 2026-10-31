"""The template report (docs/build-plan.md P10, B-2): Markdown built only from one incident's facts.

Deterministic (no clock, no randomness), offline, and the fallback for the P10b narrator. Sections, in
order: Summary (one sentence), Risk (the seven parts and why), Attack chain (numbered steps with times and
their supporting anomalies), Gaps, Reach next, Entities, Threat intel, Evidence (5 lines per step),
Recommended actions (one per tactic, in chain order).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..graph.chain import ist, tactic_name
from ..score.risk import PART_NAMES, ti_matches

EVIDENCE_LINES = 5
REACH_LINES = 5
TI_LINES = 10
FOOTER = "_Template report: built only from this incident's facts, without AI._"
NO_TI_FILE = ("No threat-intel data for this run (enrichment.json not found); the threat-intel part of the "
              "risk score is 0.")

ACTIONS = {
    "reconnaissance": "Block or rate-limit {src} at the perimeter and check which services it probed on {dst}.",
    "resource-development": "Track the infrastructure behind {src} and add it to the block lists.",
    "initial-access": "Patch or take offline the exposed service on {dst}, reset any account used from {src}, "
                      "and review {dst}'s logs from this step on.",
    "execution": "Isolate {src}, collect the malicious file, and scan the host before reconnecting it.",
    "persistence": "Remove the planted file or account on {dst} and audit it for other changes since the first step.",
    "privilege-escalation": "Revoke the raised rights, rotate admin credentials, and review admin group changes.",
    "defense-evasion": "Turn logging back on, keep a backup of the current configuration, and review every change "
                       "made while logs were off.",
    "credential-access": "Lock or reset the targeted accounts, enforce MFA, and block {src}.",
    "discovery": "Block {src} and check whether any probed service on {dst} answered.",
    "lateral-movement": "Isolate {src}, block admin ports (SMB, RDP, SSH, WinRM) between internal hosts, and check "
                        "every host it reached.",
    "collection": "Find what data was gathered on {dst} and restrict access to it.",
    "command-and-control": "Block {dst} at the firewall and DNS, isolate {src}, and look for other hosts talking "
                           "to {dst}.",
    "exfiltration": "Block traffic between {src} and {dst}, estimate how much data left from the evidence, and "
                    "start the data-breach process.",
    "impact": "Apply rate limits or upstream filtering for {dst} and confirm the service is back to normal.",
}


def _labels(inc: Dict[str, Any]) -> Dict[str, str]:
    return {n["id"]: n["label"] for n in (inc.get("graph") or {}).get("nodes") or []}


def _actor(inc: Dict[str, Any], labels: Dict[str, str]) -> str:
    for s in inc["chain"]:
        if s.get("src"):
            return labels.get(s["src"], s["src"])
    for e in (inc.get("graph") or {}).get("edges") or []:
        if e.get("step") == 1 and e.get("kind") == "step" and not e.get("supporting"):
            return labels.get(e["source"], e["source"])
    return "an unknown source"


def _targets(inc: Dict[str, Any], labels: Dict[str, str]) -> str:
    dsts: List[str] = []
    for s in inc["chain"]:
        if s.get("dst") and s["dst"] not in dsts:
            dsts.append(s["dst"])
    names = [labels.get(d, d) for d in dsts]
    if not names:
        return "no single target"
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return f"{names[0]}, {names[1]} and {len(names) - 2} more"


def summary(inc: Dict[str, Any]) -> str:
    labels = _labels(inc)
    steps = inc["chain"]
    k = len(steps)
    n_steps = f"{k} step{'s' if k != 1 else ''}"
    actor, targets = _actor(inc, labels), _targets(inc, labels)
    span = f"between {inc['ts_start_ist']} and {inc['ts_end_ist']} IST"
    risk = f"risk {inc['risk_score']:.1f} of 100 ({inc['risk_band']})"
    if not steps:
        return f"{actor} raised alerts against {targets} {span}; {risk}."
    first = steps[0]["tactic"]
    furthest = max(steps, key=lambda s: int(s["stage_no"]))["tactic"]
    if first == furthest:
        return f"{actor} showed {tactic_name(first)} activity against {targets} in {n_steps} {span}; {risk}."
    return (f"{actor} went from {tactic_name(first)} to {tactic_name(furthest)} against {targets} in {n_steps} "
            f"{span}; {risk}.")


def _ist_of(ts: str) -> str:
    return ist(datetime.strptime(ts.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f" if "." in ts else "%Y-%m-%dT%H:%M:%S"))


def _technique(x: Dict[str, Any]) -> str:
    return f"{x['technique']} {x['technique_name']}" if x.get("technique_name") else x["technique"]


def _step_line(s: Dict[str, Any]) -> str:
    end = f" to {s['ts_end_ist']}" if s["ts_end_ist"] != s["ts_start_ist"] else ""
    outcome = "got through" if s["success"] else "blocked"
    line = (f"{s['n']}. **{s['ts_start_ist']} IST**{end} · {tactic_name(s['tactic'])} · {_technique(s)}: "
            f"{s['action']} ({s['src'] or '-'} → {s['dst'] or '-'}, {s['event_count']:,} events, {outcome})")
    if s.get("ongoing"):
        line += " Still running when later steps began."
    return line


def _support_line(x: Dict[str, Any]) -> str:
    return (f"   - Supporting anomaly ({x['relation']} this step): {x['action']} ({x['rule_id']}, {x['technique']}, "
            f"{x['ts_start_ist']} to {x['ts_end_ist']} IST, {x['event_count']:,} events)")


def _reach_line(r: Dict[str, Any]) -> str:
    via = ""
    if r.get("via"):
        v = r["via"][0]
        via = f", via {v['from']} {v['edge']}" + (f" x{v['count']}" if v.get("count") else "")
    return f"- {r['host']} ({r['zone']}), hop {r['hop']}, {r['kind']}{via}"


def _risk_section(inc: Dict[str, Any]) -> List[str]:
    out = [f"Risk score **{inc['risk_score']:.1f} / 100** ({inc['risk_band']}).", "",
           "| Part | Value | Weight | Points | Why |", "|---|---|---|---|---|"]
    for k, p in inc["risk_parts"].items():
        out.append(f"| {PART_NAMES.get(k, k)} | {p['value']:.2f} | {p['weight']:.2f} | {p['points']:.2f} | "
                   f"{p.get('detail', '')} |")
    return out


def _ti_section(inc: Dict[str, Any], enrichment: Optional[Dict[str, Any]]) -> List[str]:
    if enrichment is None:
        return [NO_TI_FILE]
    hits = ti_matches(inc, enrichment)
    if not hits:
        return ["No entity of this incident was looked up."]
    out = []
    for v, e in hits[:TI_LINES]:
        flags = "; ".join(str(f) for f in e.get("flags") or [])
        out.append(f"- {v}: {e.get('verdict') or 'unknown'}, reputation {float(e.get('reputation') or 0):.2f}"
                   + (f"; {flags}" if flags else ""))
    if enrichment.get("offline"):
        out.append("")
        out.append("Looked up offline: cached answers and local context only.")
    return out


def _actions(inc: Dict[str, Any]) -> List[str]:
    order: List[str] = []
    by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for s in inc["chain"]:
        if s["tactic"] not in by_tactic:
            order.append(s["tactic"])
        by_tactic.setdefault(s["tactic"], []).append(s)
    out = []
    for t in order:
        ss = by_tactic[t]
        first = ss[0]
        nums = ", ".join(str(s["n"]) for s in ss)
        text = ACTIONS.get(t, "Review the evidence of this step.").format(src=first.get("src") or "the source",
                                                                          dst=first.get("dst") or "the target")
        out.append(f"- **{tactic_name(t)}** ({'steps' if len(ss) > 1 else 'step'} {nums}): {text}")
    return out


def render(inc: Dict[str, Any], enrichment: Optional[Dict[str, Any]] = None) -> str:
    """The Markdown report of one incident (module docstring)."""
    out: List[str] = ["## Summary", "", summary(inc), "", "## Risk", ""]
    out += _risk_section(inc)
    out += ["", "## Attack chain", ""]
    for s in inc["chain"]:
        out.append(_step_line(s))
        out += [_support_line(x) for x in s.get("supporting") or []]
    out += ["", "## Gaps", ""]
    out += [f"- {g}" for g in inc["gaps"]] or ["None: every tactic between the first and the last step has evidence."]
    nxt = inc["next"]
    out += ["", "## Reach next", "", nxt["sentence"]]
    if nxt["reachable"]:
        out.append("")
        out += [_reach_line(r) for r in nxt["reachable"][:REACH_LINES]]
    likely = ", ".join(tactic_name(t) for t in nxt.get("likely_tactics") or []) or "none"
    out += ["", f"Likely next tactics (heuristic): {likely}."]
    ents = inc["entities"]
    out += ["", "## Entities", ""]
    for label, key in (("IPs", "ips"), ("Hosts", "hosts"), ("Accounts", "users"), ("Domains", "domains")):
        out.append(f"- {label}: {', '.join(ents.get(key) or []) or 'none'}")
    out += ["", "## Threat intel", ""]
    out += _ti_section(inc, enrichment)
    out += ["", "## Evidence", ""]
    for s in inc["chain"]:
        out.append(f"**Step {s['n']}** ({s['line_total']:,} lines):")
        out.append("")
        out += [f"- {ln['source']} line {ln['line']} (byte {ln['byte_offset']}), {_ist_of(ln['ts'])} IST"
                for ln in (s.get("line_sample") or [])[:EVIDENCE_LINES]]
        out.append("")
    out += ["## Recommended actions", ""]
    out += _actions(inc)
    out += ["", FOOTER]
    return "\n".join(out) + "\n"


def report_for(inc: Dict[str, Any], enrichment: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"source": "template", "markdown": render(inc, enrichment), "triage": None}
