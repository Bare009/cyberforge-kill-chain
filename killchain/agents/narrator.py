"""Narrator and triage opinion, in one LLM call per incident (docs/build-plan.md P10b, B-2).

The model gets the fact sheet (facts.py) and returns JSON: a two-sentence summary, one
sentence per numbered step with the evidence lines it rests on, what may happen next,
and a triage opinion. The guard rejects any answer that drops or adds a step, leaves out
a chain IP or account, names an IP, account, domain or technique that is not in the facts,
or cites a line that is not the step's evidence. A rejected answer gets one retry with
the problems listed; after that the incident keeps its template report.

The Markdown shown in the UI is rendered here from the checked JSON, so its layout and
line citations are always the same.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .facts import MAX_LINES_PER_STEP, allowed_values, fact_sheet, facts_hash, required_values
from .llm import LLMClient, LLMError, LLMResult
from .settings import PROMPTS, llm_config

TRIAGE = ("looks_real", "likely_noise")
# account names that are also ordinary words; mentioning them is never an invented account
COMMON_WORDS = {"admin", "administrator", "root", "guest", "user", "test", "system", "service", "backup", "support"}

# an IPv4 address, also at the end of a sentence ("from 8.8.4.4."), but not inside a longer dotted number
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,}\b", re.I)
LINE_RE = re.compile(r"\blines?\s*:?\s*((?:\d[\d,]{2,}(?:\s*(?:,|and|&)\s*)?)+)", re.I)


def system_prompt() -> str:
    return (PROMPTS / "narrator.md").read_text(encoding="utf-8")


def messages_for(sheet: Dict[str, Any]) -> List[Dict[str, str]]:
    return [{"role": "system", "content": system_prompt()},
            {"role": "user", "content": json.dumps(sheet, ensure_ascii=False, separators=(",", ":"))}]


def _texts(obj: Dict[str, Any]) -> List[str]:
    out = [str(obj.get("summary") or ""), str(obj.get("next") or "")]
    out += [str(s.get("text") or "") for s in obj.get("steps") or [] if isinstance(s, dict)]
    tri = obj.get("triage") if isinstance(obj.get("triage"), dict) else {}
    out += [str(r) for r in tri.get("reasons") or []]
    return out


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def check(obj: Any, inc: Dict[str, Any], known_accounts: Iterable[str] = ()) -> List[str]:
    """Problems with a narrator answer; [] when it may be shown."""
    if not isinstance(obj, dict):
        return ["the answer is not a JSON object"]
    errs: List[str] = []
    allowed = allowed_values(inc)
    need = required_values(inc)
    if not isinstance(obj.get("summary"), str) or not obj["summary"].strip():
        errs.append("summary is missing")
    if not isinstance(obj.get("next"), str):
        errs.append("next is missing")

    steps = obj.get("steps")
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        errs.append("steps must be a list of objects")
        steps = []
    got = [s.get("n") for s in steps]
    if got != need["steps"]:
        errs.append(f"steps must be numbered exactly {need['steps']} in order (got {got})")
    step_lines = {s["n"]: {int(ln["line"]) for ln in (s.get("line_sample") or [])[:MAX_LINES_PER_STEP]}
                  for s in inc.get("chain") or []}
    for s in steps:
        if not isinstance(s.get("text"), str) or not s["text"].strip():
            errs.append(f"step {s.get('n')} has no text")
        cited = s.get("evidence_lines") or []
        if not isinstance(cited, list) or not all(isinstance(x, int) for x in cited):
            errs.append(f"step {s.get('n')}: evidence_lines must be a list of line numbers")
            continue
        bad = sorted(set(cited) - step_lines.get(s.get("n"), set()))
        if bad:
            errs.append(f"step {s.get('n')} cites lines {bad}, which are not that step's evidence_lines")

    tri = obj.get("triage")
    if not isinstance(tri, dict) or tri.get("verdict") not in TRIAGE:
        errs.append("triage.verdict must be looks_real or likely_noise")
    else:
        c = tri.get("confidence")
        if not isinstance(c, (int, float)) or not 0 <= c <= 1:
            errs.append("triage.confidence must be a number from 0 to 1")
        if not isinstance(tri.get("reasons"), list) or not tri["reasons"]:
            errs.append("triage.reasons must be a non-empty list")

    text = "\n".join(_texts(obj))
    for ip in sorted({m for m in IP_RE.findall(text) if _is_ip(m)} - allowed["ips"]):
        errs.append(f"mentions IP {ip}, which is not in the facts")
    for t in sorted({t.upper() for t in TECH_RE.findall(text)} - allowed["techniques"]):
        errs.append(f"mentions technique {t}, which is not in the facts")
    sources = {str(ln.get("source") or "").lower() for s in inc.get("chain") or [] for ln in s.get("line_sample") or []}
    for d in sorted({d.lower() for d in DOMAIN_RE.findall(text) if not IP_RE.fullmatch(d)}):
        if d in sources:
            continue
        if not any(a == d or a.endswith("." + d) for a in allowed["domains"]):
            errs.append(f"mentions domain {d}, which is not in the facts")
    for acct in sorted(set(known_accounts) - set(allowed["users"])):
        if acct.lower() in COMMON_WORDS or len(acct) < 3:
            continue
        if re.search(rf"(?<![\w.-]){re.escape(acct)}(?![\w-])", text):
            errs.append(f"mentions account {acct}, which is not in this incident")
    for m in LINE_RE.finditer(text):
        for num in re.findall(r"\d[\d,]*", m.group(1)):
            n = int(num.replace(",", ""))
            if n >= 1000 and n not in allowed["lines"]:
                errs.append(f"cites line {n}, which is not in the facts")
    for ip in need["ips"]:
        if ip not in text:
            errs.append(f"leaves out chain IP {ip}")
    for u in need["users"]:
        if not re.search(rf"(?<![\w.-]){re.escape(u)}(?![\w-])", text):
            errs.append(f"leaves out account {u}")
    return list(dict.fromkeys(errs))


TACTIC_NAME = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development", "initial-access": "Initial Access",
    "execution": "Execution", "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion", "credential-access": "Credential Access", "discovery": "Discovery",
    "lateral-movement": "Lateral Movement", "collection": "Collection", "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration", "impact": "Impact",
}


def render(obj: Dict[str, Any], inc: Dict[str, Any], model: str) -> str:
    by_n = {s["n"]: s for s in inc.get("chain") or []}
    out = ["### Summary", "", obj["summary"].strip(), "", "### Attack chain", ""]
    for s in obj["steps"]:
        step = by_n.get(s["n"], {})
        head = f"**{s['n']}. {TACTIC_NAME.get(step.get('tactic'), step.get('tactic') or '')}**"
        when = f" ({step.get('ts_start_ist')} IST, {step.get('technique')})" if step else ""
        cite = s.get("evidence_lines") or []
        lines = f" *Evidence: line{'s' if len(cite) > 1 else ''} {', '.join(str(x) for x in cite)}.*" if cite else ""
        out.append(f"{head}{when}: {s['text'].strip()}{lines}")
        out.append("")
    if inc.get("gaps"):
        out += ["### Gaps", ""] + [f"- {g}" for g in inc["gaps"]] + [""]
    out += ["### What may happen next", "", (obj.get("next") or "").strip() or "Nothing further is indicated.", ""]
    tri = obj["triage"]
    label = "Looks real" if tri["verdict"] == "looks_real" else "Likely noise"
    out += ["### Triage opinion", "", f"**{label}** (confidence {float(tri['confidence']):.2f})", ""]
    out += [f"- {r}" for r in tri["reasons"]] + [""]
    out.append(f"*Written by the AI narrator ({model}) from this incident's facts and checked against them. "
               "The triage opinion is shown only; it never hides or reorders an incident.*")
    return "\n".join(out)


def _parse(content: str) -> Any:
    s = content.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        start, end = s.find("{"), s.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(s[start:end + 1])
            except json.JSONDecodeError:
                return None
    return None


@dataclass
class Outcome:
    incident_id: str
    incident_number: int
    entry: Optional[Dict[str, Any]] = None        # report.json entry when accepted
    failure: Optional[str] = None                  # why the template stays
    calls: List[LLMResult] = field(default_factory=list)


def narrate(inc: Dict[str, Any], client: LLMClient, known_accounts: Iterable[str] = (), *,
            max_tokens: Optional[int] = None, prompt_version: Optional[int] = None) -> Outcome:
    cfg = llm_config().get("narrator") or {}
    max_tokens = int(max_tokens or cfg.get("max_tokens", 700))
    version = int(prompt_version or cfg.get("prompt_version", 1))
    sheet = fact_sheet(inc)
    msgs = messages_for(sheet)
    out = Outcome(inc["incident_id"], inc["incident_number"])
    accounts = list(known_accounts)
    problems: List[str] = []
    for attempt in range(2):
        try:
            res = client.chat(msgs, max_tokens=max_tokens, json_mode=True)
        except LLMError as exc:
            out.failure = f"no model answered: {exc}"
            return out
        out.calls.append(res)
        obj = _parse(res.content)
        problems = check(obj, inc, accounts) if obj is not None else ["the answer is not valid JSON"]
        if not problems:
            out.entry = {
                "source": "ai", "markdown": render(obj, inc, res.model), "triage": {
                    "verdict": obj["triage"]["verdict"], "confidence": round(float(obj["triage"]["confidence"]), 2),
                    "reasons": [str(r) for r in obj["triage"]["reasons"]][:6]},
                "model": res.endpoint, "facts_hash": facts_hash(sheet), "prompt_version": version,
                "attempts": attempt + 1, "tokens": sum(c.tokens for c in out.calls),
                "cached": all(c.cached for c in out.calls), "answer": obj,
            }
            return out
        if attempt == 0:
            msgs = msgs + [{"role": "assistant", "content": res.content},
                           {"role": "user", "content": "Your answer broke these rules:\n- " + "\n- ".join(problems[:12])
                            + "\nReturn the corrected JSON object only."}]
    out.failure = "rejected twice by the guard: " + "; ".join(problems[:5])
    return out


def run_accounts(alerts: Iterable[Dict[str, Any]], incidents: Iterable[Dict[str, Any]]) -> Set[str]:
    """Every account name in the run, so the guard can spot one moved into the wrong incident."""
    names = {a["user"] for a in alerts if a.get("user")}
    for inc in incidents:
        names.update((inc.get("entities") or {}).get("users") or [])
    return names


def reusable(prev: Optional[Dict[str, Any]], inc: Dict[str, Any], version: int) -> bool:
    return bool(prev) and prev.get("facts_hash") == facts_hash(fact_sheet(inc)) and prev.get("prompt_version") == version


def summarise_calls(outcomes: List[Outcome]) -> Tuple[Dict[str, Any], Optional[str]]:
    calls = [c for o in outcomes for c in o.calls]
    per: Dict[str, Dict[str, int]] = {}
    for c in calls:
        p = per.setdefault(c.endpoint, {"calls": 0, "cached": 0, "tokens": 0})
        p["calls"] += 1
        p["cached"] += int(c.cached)
        p["tokens"] += 0 if c.cached else c.tokens
    model = max(per, key=lambda k: per[k]["calls"]) if per else None
    return {"calls": len(calls), "cached": sum(c.cached for c in calls),
            "tokens": sum(0 if c.cached else c.tokens for c in calls), "per_endpoint": per}, model
