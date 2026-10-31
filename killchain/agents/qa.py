"""Incident Q&A (docs/build-plan.md P10b): answer a question from one incident's evidence.

The small model gets the question, the incident's fact sheet and up to MAX_LINES evidence
lines read from the log at their byte offsets. Its answer must cite line numbers; an
answer that cites a line it was not given, or names an IP that is in neither the facts
nor the lines, is rejected (one retry with the problems listed). Answers are cached per
question by the LLM client, so a rehearsed question costs nothing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .facts import allowed_values, fact_sheet
from .llm import LLMClient, LLMError, LLMResult
from .narrator import IP_RE, LINE_RE, _is_ip, _parse
from .settings import PROMPTS, llm_config

MAX_LINES = 60
MAX_RAW_CHARS = 400
MIN_QUESTION, MAX_QUESTION = 3, 500


class QuestionError(ValueError):
    """The question itself is not acceptable (empty, too long)."""


def clean_question(q: Any) -> str:
    text = re.sub(r"\s+", " ", str(q or "")).strip()
    if len(text) < MIN_QUESTION:
        raise QuestionError("ask a question of at least 3 characters")
    if len(text) > MAX_QUESTION:
        raise QuestionError(f"keep the question under {MAX_QUESTION} characters")
    return text


def pick_lines(evidence: Any, inc: Dict[str, Any], limit: int = MAX_LINES) -> List[Dict[str, Any]]:
    """Up to `limit` evidence lines, shared fairly between the numbered steps, in time order."""
    chain = inc.get("chain") or []
    if not chain:
        return []
    per = max(1, limit // len(chain))
    out: List[Dict[str, Any]] = []
    for s in chain:
        try:
            got = evidence.lines(inc["incident_number"], s["n"], 0, per)["lines"]
        except KeyError:
            got = []
        out += got
    out = out[:limit]
    out.sort(key=lambda r: (r.get("ts") or "", r.get("line") or 0))
    return out


def messages_for(question: str, inc: Dict[str, Any], lines: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    ev = [{"line": r["line"], "step": r.get("step"), "time_ist": r.get("ts_ist"),
           "text": (r.get("raw") or "(raw text not available)")[:MAX_RAW_CHARS]} for r in lines]
    user = json.dumps({"question": question, "incident": fact_sheet(inc), "evidence_lines": ev},
                      ensure_ascii=False, separators=(",", ":"))
    return [{"role": "system", "content": (PROMPTS / "qa.md").read_text(encoding="utf-8")},
            {"role": "user", "content": user}]


def check_answer(obj: Any, inc: Dict[str, Any], lines: List[Dict[str, Any]]) -> List[str]:
    if not isinstance(obj, dict) or not isinstance(obj.get("answer"), str) or not obj["answer"].strip():
        return ["the answer must be a JSON object with a non-empty 'answer'"]
    given = {int(r["line"]) for r in lines}
    errs: List[str] = []
    cited = obj.get("cited_lines")
    if not isinstance(cited, list) or not all(isinstance(x, int) for x in cited):
        errs.append("cited_lines must be a list of line numbers")
        cited = []
    for n in sorted(set(cited) - given):
        errs.append(f"cites line {n}, which is not one of the evidence lines given")
    text = obj["answer"]
    for m in LINE_RE.finditer(text):
        for num in re.findall(r"\d[\d,]*", m.group(1)):
            n = int(num.replace(",", ""))
            if n >= 1000 and n not in given:
                errs.append(f"mentions line {n}, which is not one of the evidence lines given")
    known_ips = set(allowed_values(inc)["ips"])
    for r in lines:
        known_ips.update(ip for ip in IP_RE.findall(r.get("raw") or "") if _is_ip(ip))
    for ip in sorted({ip for ip in IP_RE.findall(text) if _is_ip(ip)} - known_ips):
        errs.append(f"mentions IP {ip}, which is in neither the facts nor the evidence lines")
    return list(dict.fromkeys(errs))


@dataclass
class Answer:
    question: str
    answer: Optional[str] = None
    cited: List[Dict[str, Any]] = field(default_factory=list)
    model: Optional[str] = None
    cached: bool = False
    attempts: int = 0
    lines_given: int = 0
    problems: List[str] = field(default_factory=list)
    calls: List[LLMResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.answer is not None

    def as_dict(self) -> Dict[str, Any]:
        return {"question": self.question, "answer": self.answer, "cited_lines": self.cited, "model": self.model,
                "cached": self.cached, "attempts": self.attempts, "lines_given": self.lines_given,
                "tokens": sum(0 if c.cached else c.tokens for c in self.calls)}


def ask(question: str, inc: Dict[str, Any], evidence: Any, client: LLMClient) -> Answer:
    """Raises QuestionError for a bad question and LLMError when no model answers."""
    q = clean_question(question)
    cfg = llm_config().get("qa") or {}
    lines = pick_lines(evidence, inc, int(cfg.get("max_lines", MAX_LINES)))
    msgs = messages_for(q, inc, lines)
    out = Answer(q, lines_given=len(lines))
    by_line = {int(r["line"]): r for r in lines}
    for attempt in range(2):
        res = client.chat(msgs, max_tokens=int(cfg.get("max_tokens", 400)), json_mode=True)
        out.calls.append(res)
        out.attempts = attempt + 1
        obj = _parse(res.content)
        problems = check_answer(obj, inc, lines) if obj is not None else ["the answer is not valid JSON"]
        if not problems:
            out.answer = obj["answer"].strip()
            out.cited = [{k: by_line[n].get(k) for k in ("line", "step", "ts_ist", "raw", "source")}
                         for n in dict.fromkeys(obj.get("cited_lines") or []) if n in by_line]
            out.model, out.cached = res.endpoint, all(c.cached for c in out.calls)
            return out
        out.problems = problems
        if attempt == 0:
            msgs = msgs + [{"role": "assistant", "content": res.content},
                           {"role": "user", "content": "Your answer broke these rules:\n- " + "\n- ".join(problems[:10])
                            + "\nReturn the corrected JSON object only."}]
    return out
