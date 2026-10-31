"""Rule writer (docs/build-plan.md P10b, B-4): plain English -> a YAML rule, tested on the run.

draft()  the large model writes a rule from a description, the `events` columns and three
         example rules; the YAML is parsed, validated and its SQL compiled (one retry with
         the problems), then it is run on the run's events like `detect --only`.
test()   validate and run any rule YAML (the UI's editor), without the LLM.
save()   write it to rules/firewall/ or rules/anomaly/ under its id. Only on a button press;
         never overwrites a rule that exists.

Rule SQL is untrusted (it comes from the UI or an LLM), so it only ever runs on a
read-only connection to the prepared events.duckdb with external access turned off and
the configuration locked (no file reads or writes, no ATTACH, no extensions), a memory
and thread cap, and a time limit after which the query is interrupted.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .llm import LLMClient
from .narrator import _parse
from .settings import PROMPTS, ROOT, llm_config

EXAMPLES = ("R01-admin-bruteforce", "R16-web-sql-injection", "R07-success-after-failures")
ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")
MAX_DESCRIPTION = 1000
MAX_YAML = 20_000
HITS_SHOWN = 5


class RuleWriterError(ValueError):
    """Bad input (description, YAML) or no events to test on."""


def rules_root() -> Path:
    import os

    p = Path(os.environ.get("KILLCHAIN_RULES_DIR") or ROOT / "rules")
    return p if p.is_absolute() else ROOT / p


def example_rules(root: Optional[Path] = None) -> List[str]:
    root = root or rules_root()
    out = []
    for rid in EXAMPLES:
        hits = list(root.rglob(f"{rid}.yaml"))
        if hits:
            out.append(hits[0].read_text(encoding="utf-8"))
    return out


class Sandbox:
    """Runs rule SQL on a locked-down, read-only connection to a run's events.duckdb."""

    def __init__(self, run_dir: Path, *, memory_limit: str = "2GB", threads: int = 4, timeout_s: float = 60):
        from killchain import db

        self.path = Path(run_dir) / db.PREPARED_NAME
        self.memory_limit, self.threads, self.timeout_s = memory_limit, threads, timeout_s
        self._lock = threading.Lock()            # one rule test at a time

    @property
    def available(self) -> bool:
        return self.path.is_file()

    def connect(self):
        import duckdb

        if not self.available:
            raise RuleWriterError(f"this run has no prepared {self.path.name}; run "
                                  "`python -m killchain db --parsed ... --run ... --prepare` to test rules on it")
        con = duckdb.connect(str(self.path), read_only=True)
        con.execute("SET TimeZone = 'UTC'")
        con.execute(f"SET memory_limit = '{self.memory_limit}'")
        con.execute(f"SET threads = {int(self.threads)}")
        con.execute("SET enable_external_access = false")
        con.execute("SET lock_configuration = true")
        return con

    def columns(self) -> List[Dict[str, str]]:
        con = self.connect()
        try:
            return [{"name": r[0], "type": r[1]} for r in con.execute("DESCRIBE events").fetchall()]
        finally:
            con.close()

    def run(self, rule: Any) -> Dict[str, Any]:
        """check_rule + run_rule with the time limit; returns counts and the first hits."""
        from killchain.detect import engine

        if not self._lock.acquire(timeout=1):
            raise RuleWriterError("another rule test is running; try again in a moment")
        try:
            con = self.connect()
            timer = threading.Timer(self.timeout_s, con.interrupt)
            try:
                bad = engine.check_rule(con, rule)
                if bad:
                    return {"ran": False, "errors": [bad]}
                t0 = time.perf_counter()
                timer.start()
                try:
                    alerts, ev, stats = engine.run_rule(con, rule)
                except Exception as exc:  # noqa: BLE001 - duckdb errors and the interrupt
                    msg = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
                    if "INTERRUPT" in msg.upper():
                        msg = f"the rule ran longer than {self.timeout_s:.0f} s and was stopped"
                    return {"ran": False, "errors": [f"{rule.id}: {msg}"]}
                hits = engine.alerts_json(alerts)
                return {"ran": True, "errors": [], "alerts": len(hits), "evidence_lines": ev.height,
                        "secs": round(time.perf_counter() - t0, 2), "hits": hits[:HITS_SHOWN]}
            finally:
                timer.cancel()
                con.close()
        finally:
            self._lock.release()


def parse_yaml(text: str) -> Any:
    """(rule, problems). Validates like the rule loader; the layer comes from `layer` (default rule)."""
    from killchain.detect.rules import RuleError, parse_rule

    if not isinstance(text, str) or not text.strip():
        return None, ["the rule is empty"]
    if len(text) > MAX_YAML:
        return None, [f"the rule is longer than {MAX_YAML:,} characters"]
    try:
        d = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, [f"not valid YAML: {str(e).splitlines()[0]}"]
    if not isinstance(d, dict):
        return None, ["the rule must be a YAML mapping"]
    rid = str(d.get("id") or "")
    if not ID_RE.match(rid):
        return None, ["id must start with a letter and use only letters, digits, - and _ (3-64 characters)"]
    try:
        rule = parse_rule(d, Path(f"{rid}.yaml"), str(d.get("layer") or "rule"))
    except RuleError as e:
        return None, [str(e)]
    return rule, []


def test(text: str, sandbox: Sandbox) -> Dict[str, Any]:
    rule, problems = parse_yaml(text)
    if rule is None:
        return {"valid": False, "ran": False, "errors": problems, "rule": None}
    res = sandbox.run(rule)
    return {"valid": not res["errors"] or res["ran"], **res, "rule": _summary(rule)}


def _summary(rule: Any) -> Dict[str, Any]:
    return {"id": rule.id, "title": rule.title, "kind": rule.kind, "layer": rule.layer,
            "technique": rule.label.get("technique"), "tactic": rule.label.get("tactic"), "severity": rule.severity}


@dataclass
class Draft:
    description: str
    yaml: Optional[str] = None
    explanation: Optional[str] = None
    test: Optional[Dict[str, Any]] = None
    model: Optional[str] = None
    cached: bool = False
    attempts: int = 0
    problems: List[str] = field(default_factory=list)
    tokens: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {"description": self.description, "yaml": self.yaml, "explanation": self.explanation,
                "test": self.test, "model": self.model, "cached": self.cached, "attempts": self.attempts,
                "problems": self.problems, "tokens": self.tokens}


def clean_description(text: Any) -> str:
    d = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(d) < 10:
        raise RuleWriterError("describe the rule in at least a few words")
    if len(d) > MAX_DESCRIPTION:
        raise RuleWriterError(f"keep the description under {MAX_DESCRIPTION} characters")
    return d


def messages_for(description: str, columns: List[Dict[str, str]], examples: List[str]) -> List[Dict[str, str]]:
    import json

    user = json.dumps({"description": description,
                       "events_columns": [f"{c['name']} {c['type']}" for c in columns],
                       "example_rules": examples}, ensure_ascii=False)
    return [{"role": "system", "content": (PROMPTS / "rule_writer.md").read_text(encoding="utf-8")},
            {"role": "user", "content": user}]


def draft(description: str, client: LLMClient, sandbox: Sandbox) -> Draft:
    """Raises RuleWriterError for a bad description or a run without events, LLMError when no model answers."""
    desc = clean_description(description)
    cfg = llm_config().get("rule_writer") or {}
    msgs = messages_for(desc, sandbox.columns(), example_rules())
    out = Draft(desc)
    for attempt in range(2):
        res = client.chat(msgs, max_tokens=int(cfg.get("max_tokens", 900)), json_mode=True)
        out.attempts, out.model = attempt + 1, res.endpoint
        out.cached = res.cached if attempt == 0 else (out.cached and res.cached)
        out.tokens += 0 if res.cached else res.tokens
        obj = _parse(res.content)
        if not isinstance(obj, dict) or not isinstance(obj.get("yaml"), str):
            problems = ["answer with a JSON object holding the rule in 'yaml'"]
        else:
            out.yaml, out.explanation = obj["yaml"].strip(), str(obj.get("explanation") or "").strip() or None
            rule, problems = parse_yaml(out.yaml)
            if rule is not None:
                from killchain.detect import engine

                con = sandbox.connect()
                try:
                    bad = engine.check_rule(con, rule)
                finally:
                    con.close()
                problems = [bad] if bad else []
        if not problems:
            out.problems = []
            out.test = test(out.yaml, sandbox)
            return out
        out.problems = problems
        if attempt == 0:
            msgs = msgs + [{"role": "assistant", "content": res.content},
                           {"role": "user", "content": "That rule has these problems:\n- " + "\n- ".join(problems[:8])
                            + "\nReturn the corrected JSON object only."}]
    return out          # with problems: the UI shows the YAML and the problems for a manual fix


def save(text: str, sandbox: Optional[Sandbox] = None, root: Optional[Path] = None) -> Dict[str, Any]:
    """Write a valid rule to rules/<firewall|anomaly>/<id>.yaml. Never overwrites."""
    rule, problems = parse_yaml(text)
    if rule is None:
        raise RuleWriterError("; ".join(problems))
    root = root or rules_root()
    if any(root.rglob(f"{rule.id}.yaml")) or any(root.rglob(f"{rule.id}.yml")):
        raise FileExistsError(f"a rule with id {rule.id} already exists; choose another id")
    folder = root / ("anomaly" if rule.layer == "anomaly" else "firewall")
    folder.mkdir(parents=True, exist_ok=True)
    path = (folder / f"{rule.id}.yaml").resolve()
    if path.parent != folder.resolve():
        raise RuleWriterError("bad rule id")
    with open(path, "x", encoding="utf-8") as f:              # "x": fails if it appeared meanwhile
        f.write(text.rstrip() + "\n")
    try:
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        rel = str(path)
    return {"saved": True, "path": rel, "rule": _summary(rule),
            "next": "Run `python -m killchain detect --run <run>` (then correlate ... bundle) to include it in the run."}
