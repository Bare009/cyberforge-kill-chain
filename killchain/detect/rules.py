"""Load and validate detection rules (rules/**/*.yaml).

A rule file:

    id: fw-bruteforce-burst            # unique; file name should match
    title: Brute force on firewall admin login
    status: stable                     # experimental | test | stable
    layer: rule                        # rule | anomaly (default: anomaly for files under rules/anomaly)
    attack:
      technique: T1110.001
      alt_techniques: [T1110]
      tactic: credential-access        # must be one of the technique's tactics
      technique_by:                    # optional per-line labels: column -> value -> technique
        dst_port: {3389: T1021.001}
    severity: 4                        # 1-5
    confidence: 0.9                    # 0-1
    promote: false                     # true: one hit is enough for an incident
    logsource: firewall                # firewall | windows
    kind: count                        # match | count | distinct | sequence | sql
    where: "log_desc = 'Admin login failed' AND NOT src_internal"
    group_by: [src_ip]                 # columns or "expression AS name"
    window: 10m                        # count, distinct
    field: dst_port                    # distinct: the column whose distinct values are counted
    having: {gte: 100}                 # on the count (count, match) or the distinct count (distinct)
    split_gap: 1h                      # match: a gap longer than this starts a new alert
    steps: [...]                       # sequence: [{name, where, min}], in order
    within: 15m                        # sequence: whole sequence must fit in this time
    sql: "..."                         # sql: returns alert_key, source, line
    entities: {src_ip: src_ip, dst_ip: dst_ip, user: user}   # contract B entity -> SQL over events
    success: "action = 'accept'"       # optional: which evidence lines count as "got through"
    time_quality: valid                # valid (default) | any
    action_text: "{src_ip} tried {event_count} admin passwords in {minutes} minutes"
    tuning: "planted 2,000 in 10 min; background max 25"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from .. import attack

KINDS = ("match", "count", "distinct", "sequence", "sql")
STATUSES = ("experimental", "test", "stable")
LOGSOURCES = {"firewall": "firewall_events", "windows": "windows_events"}
ENTITY_FIELDS = ("src_ip", "dst_ip", "host", "user", "domain", "url")
HAVING_OPS = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<", "eq": "="}
DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(s|m|h|d)\s*$")
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
GROUP_AS_RE = re.compile(r"^(?P<expr>.+?)\s+AS\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$", re.I | re.S)
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_SUCCESS = ("(coalesce(action, '') NOT IN ('deny', 'dropped', 'blocked', 'block', 'drop', 'reset') "
                   "AND coalesce(status, '') NOT IN ('failed', 'failure'))")


class RuleError(ValueError):
    pass


def duration(v: Any, where: str) -> int:
    m = DURATION_RE.match(str(v))
    if not m:
        raise RuleError(f"{where}: {v!r} is not a duration like 30s, 10m, 2h, 3d")
    return int(float(m.group(1)) * UNITS[m.group(2)])


@dataclass
class Rule:
    id: str
    title: str
    path: Path
    kind: str
    logsource: str
    layer: str
    status: str
    label: Dict[str, Any]
    alt_techniques: List[str]
    technique_by: Dict[str, Dict[Any, str]]
    severity: int
    confidence: float
    promote: bool
    where: Optional[str]
    group_by: List[Tuple[str, str]]          # (expression, name)
    window_s: Optional[int]
    field: Optional[str]
    having: List[Tuple[str, float]]          # (op, value)
    split_gap_s: int
    steps: List[Dict[str, Any]]
    within_s: Optional[int]
    sql: Optional[str]
    entities: Dict[str, str]
    success: str
    time_quality: str
    action_text: str
    tuning: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def table(self) -> str:
        return LOGSOURCES[self.logsource]

    def having_sql(self, col: str) -> str:
        return " AND ".join(f"{col} {HAVING_OPS[op]} {v:g}" for op, v in self.having) or "TRUE"


def _need(d: Dict[str, Any], key: str, where: str) -> Any:
    if d.get(key) in (None, ""):
        raise RuleError(f"{where}: '{key}' is required")
    return d[key]


def _group(items: Any, where: str) -> List[Tuple[str, str]]:
    if items in (None, []):
        return []
    if not isinstance(items, list):
        raise RuleError(f"{where}: group_by must be a list")
    out = []
    for it in items:
        s = str(it).strip()
        m = GROUP_AS_RE.match(s)
        if m:
            out.append((m.group("expr").strip(), m.group("name")))
        elif IDENT_RE.match(s):
            out.append((s, s))
        else:
            raise RuleError(f"{where}: group_by entry {s!r} needs 'expression AS name'")
    names = [n for _, n in out]
    if len(set(names)) != len(names):
        raise RuleError(f"{where}: group_by names repeat")
    return out


def parse_rule(d: Dict[str, Any], path: Path, default_layer: str = "rule") -> Rule:
    w = path.name
    if not isinstance(d, dict):
        raise RuleError(f"{w}: the file must be a YAML mapping")
    rid = str(_need(d, "id", w))
    w = f"{path.name} ({rid})"
    kind = _need(d, "kind", w)
    if kind not in KINDS:
        raise RuleError(f"{w}: kind {kind!r} is not one of {list(KINDS)}")
    logsource = d.get("logsource", "firewall")
    if logsource not in LOGSOURCES:
        raise RuleError(f"{w}: logsource {logsource!r} is not one of {list(LOGSOURCES)}")
    status = d.get("status", "experimental")
    if status not in STATUSES:
        raise RuleError(f"{w}: status {status!r} is not one of {list(STATUSES)}")
    layer = d.get("layer", default_layer)
    if layer not in ("rule", "anomaly"):
        raise RuleError(f"{w}: layer must be rule or anomaly")
    att = _need(d, "attack", w)
    try:
        if att.get("technique") == "unknown":
            lab = attack.unknown_label(att.get("tactic"))
        else:
            lab = attack.label(_need(att, "technique", w + " attack"), att.get("tactic"))
        alts = attack.check_alternates(att.get("alt_techniques") or [])
        tby: Dict[str, Dict[Any, str]] = {}
        for col, mapping in (att.get("technique_by") or {}).items():
            tby[col] = {k: attack.technique(v).id for k, v in mapping.items()}
    except attack.AttackError as e:
        raise RuleError(f"{w}: {e}") from None
    sev = d.get("severity", 3)
    if not isinstance(sev, int) or not 1 <= sev <= 5:
        raise RuleError(f"{w}: severity must be an integer 1-5")
    conf = d.get("confidence", 0.7)
    if not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        raise RuleError(f"{w}: confidence must be 0-1")
    having = []
    for op, v in (d.get("having") or {}).items():
        if op not in HAVING_OPS or not isinstance(v, (int, float)):
            raise RuleError(f"{w}: having needs ops {list(HAVING_OPS)} with numbers, got {op}: {v!r}")
        having.append((op, float(v)))
    ents = d.get("entities") or {}
    bad = set(ents) - set(ENTITY_FIELDS)
    if bad:
        raise RuleError(f"{w}: entities {sorted(bad)} are not contract fields {list(ENTITY_FIELDS)}")
    tq = d.get("time_quality", "valid")
    if tq not in ("valid", "any"):
        raise RuleError(f"{w}: time_quality must be valid or any")
    r = Rule(
        id=rid, title=str(_need(d, "title", w)), path=path, kind=kind, logsource=logsource, layer=layer,
        status=status, label=lab, alt_techniques=alts, technique_by=tby, severity=sev, confidence=float(conf),
        promote=bool(d.get("promote", False)), where=d.get("where"), group_by=_group(d.get("group_by"), w),
        window_s=duration(d["window"], w + " window") if d.get("window") else None, field=d.get("field"),
        having=having, split_gap_s=duration(d.get("split_gap", "1h"), w + " split_gap"),
        steps=d.get("steps") or [], within_s=duration(d["within"], w + " within") if d.get("within") else None,
        sql=d.get("sql"), entities={k: str(v) for k, v in ents.items()}, success=d.get("success") or DEFAULT_SUCCESS,
        time_quality=tq, action_text=str(d.get("action_text") or d.get("title")), tuning=str(d.get("tuning", "")),
        raw=d,
    )
    _kind_fields(r, w)
    return r


def _kind_fields(r: Rule, w: str) -> None:
    if r.kind in ("count", "distinct"):
        if not r.window_s:
            raise RuleError(f"{w}: kind {r.kind} needs 'window'")
        if not r.having:
            raise RuleError(f"{w}: kind {r.kind} needs 'having'")
        if not r.where:
            raise RuleError(f"{w}: kind {r.kind} needs 'where'")
    if r.kind == "distinct" and not r.field:
        raise RuleError(f"{w}: kind distinct needs 'field'")
    if r.kind == "match" and not r.where:
        raise RuleError(f"{w}: kind match needs 'where'")
    if r.kind == "sequence":
        if len(r.steps) < 2:
            raise RuleError(f"{w}: kind sequence needs at least 2 steps")
        if not r.within_s:
            raise RuleError(f"{w}: kind sequence needs 'within'")
        if not r.group_by:
            raise RuleError(f"{w}: kind sequence needs 'group_by'")
        for i, s in enumerate(r.steps):
            if not isinstance(s, dict) or not s.get("where"):
                raise RuleError(f"{w}: step {i + 1} needs 'where'")
            s.setdefault("name", f"step {i + 1}")
            s["min"] = int(s.get("min", 1))
    if r.kind == "sql" and not r.sql:
        raise RuleError(f"{w}: kind sql needs 'sql'")


def find_rule_files(roots: Union[str, Path, List[Union[str, Path]]]) -> List[Path]:
    roots = roots if isinstance(roots, list) else [roots]
    files: List[Path] = []
    for root in map(Path, roots):
        files += [root] if root.is_file() else sorted(list(root.rglob("*.yaml")) + list(root.rglob("*.yml")))
    return files


def load_rules(roots: Union[str, Path, List[Union[str, Path]]], only: Optional[List[str]] = None
               ) -> Tuple[List[Rule], List[str]]:
    """(rules, errors). A file that fails to parse is reported, not loaded."""
    rules, errors, seen = [], [], {}
    for p in find_rule_files(roots):
        layer = "anomaly" if "anomaly" in p.parts else "rule"
        try:
            with open(p, encoding="utf-8") as f:
                d = yaml.safe_load(f)
            r = parse_rule(d, p, layer)
        except yaml.YAMLError as e:
            errors.append(f"{p.name}: not valid YAML ({str(e).splitlines()[0]})")
            continue
        except RuleError as e:
            errors.append(str(e))
            continue
        if r.id in seen:
            errors.append(f"{p.name}: id {r.id!r} is also used by {seen[r.id]}")
            continue
        seen[r.id] = p.name
        if only and r.id not in only:
            continue
        rules.append(r)
    if only:
        missing = set(only) - {r.id for r in rules}
        errors += [f"--only {m}: no such rule" for m in sorted(missing)]
    return rules, errors
