"""Dashboard, Alerts and Rules endpoints (docs/build-plan.md P11, day 5).

GET /dashboard/summary   KPI tiles, incidents by risk band and severity, kill chain coverage,
                         alerts per hour, top attackers and targets, data quality, TI and LLM status
GET /alerts              every alert (contract B) with filters, including incident=none
GET /unexplained         anomaly alerts that did not become or join an incident
GET /rules               every detection rule with its hit counts in this run
GET /rules/{id}          one rule: its YAML, settings and recent alerts

Everything is computed once at start-up from the loaded bundle.
"""

from __future__ import annotations

import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from .bundle import REPO_ROOT, RunBundle

log = logging.getLogger(__name__)
router = APIRouter()

TACTIC_ORDER = ("reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact")
TACTIC_NAMES = {t: t.replace("-", " ").title().replace("And", "and") for t in TACTIC_ORDER}
TACTIC_NAMES["command-and-control"] = "Command and Control"
BANDS = ("critical", "high", "medium", "low")
TOP_N = 8


def _ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_internal(ip: Optional[str]) -> bool:
    from killchain.enrich.settings import network

    if not ip:
        return False
    try:
        return network().zone_of(ip)["zone"] != "internet" or network().is_private(ip)
    except Exception:  # noqa: BLE001 - a bad config never breaks the dashboard
        return False


# --------------------------------------------------------------------------- dashboard

def dashboard_summary(b: RunBundle, ti_status: Dict[str, Any]) -> Dict[str, Any]:
    incs = [b.incidents[n] for n in sorted(b.incidents)]
    alerts = b.alerts
    rs = b.run_summary or {}

    bands = Counter(i.get("risk_band") for i in incs)
    sev = Counter(int(i.get("severity") or 0) for i in incs)
    scored = any(float(i.get("risk_score") or 0) > 0 for i in incs)

    # kill chain coverage: how many incidents reach each tactic
    per_tactic = Counter(t for i in incs for t in set(i.get("tactics") or []))
    alerts_tactic = Counter(a.get("tactic") for a in alerts)
    coverage = [{"tactic": t, "name": TACTIC_NAMES[t], "stage_no": k + 1, "incidents": per_tactic.get(t, 0),
                 "alerts": alerts_tactic.get(t, 0)} for k, t in enumerate(TACTIC_ORDER)]

    # alerts per hour, by start time, over the alerts' span
    starts = [d for d in (_ts(a.get("ts_start")) for a in alerts) if d]
    hours: List[Dict[str, Any]] = []
    if starts:
        first = min(starts).replace(minute=0, second=0, microsecond=0)
        last = max(starts).replace(minute=0, second=0, microsecond=0)
        by_hour: Dict[datetime, Counter] = defaultdict(Counter)
        for a in alerts:
            d = _ts(a.get("ts_start"))
            if d:
                by_hour[d.replace(minute=0, second=0, microsecond=0)][a.get("layer") or "rule"] += 1
        h = first
        while h <= last and len(hours) < 24 * 60:
            c = by_hour.get(h, Counter())
            hours.append({"hour": _iso(h), "alerts": sum(c.values()), "rule": c.get("rule", 0),
                          "anomaly": c.get("anomaly", 0), "vendor": c.get("vendor", 0)})
            h += timedelta(hours=1)

    # top attackers (outside sources) and targets (internal destinations)
    att: Dict[str, Dict[str, Any]] = {}
    tgt: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        for ip, bucket, internal_wanted in ((a.get("src_ip"), att, False), (a.get("dst_ip"), tgt, True)):
            if not ip or _is_internal(ip) != internal_wanted:
                continue
            e = bucket.setdefault(ip, {"value": ip, "alerts": 0, "incidents": set(), "max_severity": 0})
            e["alerts"] += 1
            e["max_severity"] = max(e["max_severity"], int(a.get("severity") or 0))
            if a.get("incident_number") is not None:
                e["incidents"].add(a["incident_number"])

    def top(bucket: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows = [{**e, "incidents": sorted(e["incidents"])} for e in bucket.values()]
        rows.sort(key=lambda e: (-len(e["incidents"]), -e["alerts"], -e["max_severity"], e["value"]))
        return rows[:TOP_N]

    counts = rs.get("counts") or {}
    dq = rs.get("data_quality") or {}
    totals = dict(rs.get("totals") or {})
    stages = rs.get("stages") or {}
    # A full `python -m killchain run` (every stage, nothing reused) timed the whole thing end to end,
    # child processes included: show that, so the Dashboard agrees with the job that made the run.
    # A partial rerun (--from, --reuse-parsed) only timed part of it: keep the per-stage totals.
    pipe = rs.get("pipeline") or {}
    opts = pipe.get("options") or {}
    timing = "stages"
    if pipe.get("wall_secs") and not opts.get("from") and not opts.get("reuse_parsed"):
        timing = "pipeline"
        totals = {"processing_secs": pipe.get("wall_secs"), "peak_rss_mb": pipe.get("peak_rss_mb")}
        stages = {s["name"]: {"wall_secs": s.get("wall_secs"), "peak_rss_mb": s.get("peak_rss_mb")}
                  for s in pipe.get("stages") or [] if s.get("status") != "skipped"}
    span_start = min((i["ts_start"] for i in incs), default=None)
    span_end = max((i["ts_end"] for i in incs), default=None)
    worst = [{k: r.get(k) for k in ("incident_number", "title", "risk_score", "risk_band", "severity",
                                     "ts_start", "tactics", "ti_verdict", "triage_verdict")}
             for r in b.index_rows[:5]]
    return {
        "run": b.run,
        "sample": b.sample,
        "empty": b.empty,
        "kpis": {
            "events_parsed": dq.get("events"),
            "log_lines": dq.get("lines"),
            "alerts": len(alerts),
            "incidents": len(incs),
            "critical_incidents": bands.get("critical", 0),
            "critical_severity_incidents": sev.get(5, 0),
            "unexplained": len(b.unexplained),
            "log_start": dq.get("first_good_ts"),
            "log_end": dq.get("last_good_ts"),
            "incident_start": span_start,
            "incident_end": span_end,
            "processing_secs": totals.get("processing_secs"),
            "peak_rss_mb": totals.get("peak_rss_mb"),
            "processing_timing": timing,
            "evidence_lines": counts.get("evidence_lines"),
        },
        "risk_scored": scored,
        "incidents_by_band": [{"band": k, "incidents": bands.get(k, 0)} for k in BANDS],
        "incidents_by_severity": [{"severity": s, "incidents": sev.get(s, 0)} for s in (5, 4, 3, 2, 1)],
        "coverage": coverage,
        "alerts_per_hour": hours,
        "alerts_by_layer": dict(Counter(a.get("layer") or "rule" for a in alerts)),
        "top_attackers": top(att),
        "top_targets": top(tgt),
        "worst_incidents": worst,
        "data_quality": dq or None,
        "stages": stages,
        "threat_intel": ti_status,
        "llm": rs.get("llm"),
    }


@router.get("/dashboard/summary", tags=["dashboard"])
def get_dashboard(request: Request) -> Dict[str, Any]:
    """KPI tiles, incidents by risk band, tactic coverage, alerts per hour, top attackers and targets."""
    st = request.app.state
    if getattr(st, "dashboard", None) is None:
        ti = {k: v for k, v in st.ti.status().items()
              if k in ("source", "offline", "providers", "indicators", "verdicts", "generated_at")}
        st.dashboard = dashboard_summary(st.bundle, ti)
    return st.dashboard


# --------------------------------------------------------------------------- alerts

_ENTITY_FIELDS = ("src_ip", "dst_ip", "host", "user", "domain", "url")


def filter_alerts(rows: List[Dict[str, Any]], *, incident: Optional[str] = None, technique: Optional[str] = None,
                  tactic: Optional[str] = None, rule: Optional[str] = None, layer: Optional[str] = None,
                  severity: Optional[int] = None, entity: Optional[str] = None,
                  q: Optional[str] = None) -> List[Dict[str, Any]]:
    out = rows
    if incident:
        i = incident.strip().lower()
        if i == "none":
            out = [a for a in out if a.get("incident_number") is None]
        elif i == "any":
            out = [a for a in out if a.get("incident_number") is not None]
        elif i.isdigit():
            out = [a for a in out if a.get("incident_number") == int(i)]
        else:
            raise HTTPException(status_code=422, detail="incident must be a number, 'none' or 'any'")
    if technique:
        t = technique.strip().upper()
        out = [a for a in out if (a.get("technique") or "").upper() == t
               or (a.get("technique") or "").upper().startswith(t + ".")
               or t in [x.upper() for x in a.get("alt_techniques") or []]]
    if tactic:
        tac = tactic.strip().lower().replace(" ", "-")
        out = [a for a in out if a.get("tactic") == tac]
    if rule:
        out = [a for a in out if a.get("rule_id") == rule.strip()]
    if layer:
        out = [a for a in out if (a.get("layer") or "rule") == layer.strip()]
    if severity is not None:
        out = [a for a in out if int(a.get("severity") or 0) >= severity]
    if entity:
        e = entity.strip()
        out = [a for a in out if any(a.get(f) == e for f in _ENTITY_FIELDS)]
    if q:
        n = q.strip().lower()
        out = [a for a in out if n in (a.get("title") or "").lower() or n in (a.get("summary") or "").lower()
               or n in (a.get("rule_id") or "").lower()
               or any(n in str(a.get(f) or "").lower() for f in _ENTITY_FIELDS)]
    return out


def _sorted(rows: List[Dict[str, Any]], sort: str) -> List[Dict[str, Any]]:
    if sort == "severity":
        return sorted(rows, key=lambda a: (-int(a.get("severity") or 0), a.get("ts_start") or ""))
    return sorted(rows, key=lambda a: a.get("ts_start") or "", reverse=(sort != "oldest"))


@router.get("/alerts", tags=["alerts"])
def get_alerts(
    request: Request,
    incident: Optional[str] = Query(None, description="incident number, 'none' (in no incident) or 'any'"),
    technique: Optional[str] = Query(None, description="technique id; a parent matches its sub-techniques"),
    tactic: Optional[str] = Query(None),
    rule: Optional[str] = Query(None, description="rule id"),
    layer: Optional[str] = Query(None, description="rule | anomaly | vendor"),
    severity: Optional[int] = Query(None, ge=1, le=5, description="minimum severity"),
    entity: Optional[str] = Query(None, description="exact IP, host, user, domain or URL"),
    q: Optional[str] = Query(None, description="text in the title, summary, rule id or an entity"),
    sort: str = Query("newest", pattern="^(newest|oldest|severity)$"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Every alert (contract B), newest first by default, with counts for the tab badges."""
    b: RunBundle = request.app.state.bundle
    rows = _sorted(filter_alerts(b.alerts, incident=incident, technique=technique, tactic=tactic, rule=rule,
                                 layer=layer, severity=severity, entity=entity, q=q), sort)
    return {
        "run": b.run, "total": len(rows), "limit": limit, "offset": offset,
        "counts": {"all": len(b.alerts),
                   "not_in_incident": sum(a.get("incident_number") is None for a in b.alerts),
                   "unexplained": len(b.unexplained)},
        "alerts": rows[offset: offset + limit],
    }


@router.get("/unexplained", tags=["alerts"])
def get_unexplained(request: Request, limit: int = Query(200, ge=1, le=1000),
                    offset: int = Query(0, ge=0)) -> Dict[str, Any]:
    """Anomaly alerts that did not become or join an incident, with the reason."""
    b: RunBundle = request.app.state.bundle
    return {"run": b.run, "total": len(b.unexplained), "limit": limit, "offset": offset,
            "note": "A single anomaly detector firing alone is listed here, not promoted to an incident.",
            "alerts": b.unexplained[offset: offset + limit]}


# --------------------------------------------------------------------------- rules

def rules_dir() -> Path:
    p = Path(os.environ.get("KILLCHAIN_RULES_DIR") or REPO_ROOT / "rules")
    return p if p.is_absolute() else REPO_ROOT / p


class RuleStore:
    """Rule files from rules/ with this run's hit counts (alerts.json, detect/_stats.json, metrics.json)."""

    def __init__(self, b: RunBundle, root: Optional[Path] = None):
        self.root = Path(root) if root else rules_dir()
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.errors: List[str] = []
        self._load(b)

    def _load(self, b: RunBundle) -> None:
        from killchain.detect.rules import load_rules

        if not self.root.is_dir():
            self.errors.append(f"rules folder not found: {self.root}")
            return
        try:
            rules, errors = load_rules([str(self.root)])
        except Exception as exc:  # noqa: BLE001 - a broken rule file must not stop the API
            self.errors.append(f"could not load rules: {exc}")
            return
        self.errors += errors
        detect = {}
        stats_path = b.run_dir / "detect" / "_stats.json"
        if stats_path.exists():
            import orjson

            try:
                detect = {r["rule_id"]: r for r in orjson.loads(stats_path.read_bytes()).get("per_rule") or []}
            except Exception:  # noqa: BLE001
                log.warning("could not read %s", stats_path)
        evals = {r["rule_id"]: r for r in (b.metrics or {}).get("per_rule") or []}
        by_rule: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for a in b.alerts:
            by_rule[a.get("rule_id")].append(a)

        for r in rules:
            hits = by_rule.get(r.id, [])
            d, ev = detect.get(r.id) or {}, evals.get(r.id)
            try:
                rel = str(r.path.resolve().relative_to(REPO_ROOT)).replace("\\", "/")
            except ValueError:
                rel = r.path.name
            self.rules[r.id] = {
                "id": r.id, "title": r.title, "status": r.status, "layer": r.layer, "kind": r.kind,
                "logsource": r.logsource, "technique": r.label.get("technique"),
                "technique_name": r.label.get("technique_name"), "tactic": r.label.get("tactic"),
                "alt_techniques": list(r.alt_techniques), "severity": r.severity, "confidence": r.confidence,
                "promote": r.promote, "path": rel,
                "alerts": len(hits),
                "alerts_in_incidents": sum(a.get("incident_number") is not None for a in hits),
                "incidents": sorted({a["incident_number"] for a in hits if a.get("incident_number") is not None}),
                "evidence_lines": d.get("evidence_lines"),
                "run_secs": d.get("secs"),
                "ran": r.id in detect,
                "background_alerts": ev.get("background_alerts") if ev else None,
                "truth_lines": ev.get("truth_lines") if ev else None,
                "last_alert": max((a.get("ts_start") or "" for a in hits), default=None) or None,
                "tuning": r.tuning or None,
                "_file": r.path,
            }

    def rows(self) -> List[Dict[str, Any]]:
        return [{k: v for k, v in r.items() if not k.startswith("_")} for r in self.rules.values()]

    def detail(self, rule_id: str, b: RunBundle) -> Optional[Dict[str, Any]]:
        r = self.rules.get(rule_id)
        if r is None:
            return None
        try:
            text = Path(r["_file"]).read_text(encoding="utf-8")
        except OSError as exc:
            text = f"# could not read {r['path']}: {exc}"
        hits = sorted((a for a in b.alerts if a.get("rule_id") == rule_id),
                      key=lambda a: a.get("ts_start") or "", reverse=True)
        return {**{k: v for k, v in r.items() if not k.startswith("_")}, "yaml": text, "recent_alerts": hits[:20]}


@router.get("/rules", tags=["rules"])
def get_rules(request: Request, layer: Optional[str] = Query(None, description="rule | anomaly"),
              q: Optional[str] = Query(None, description="text in the id, title or technique")) -> Dict[str, Any]:
    """Every detection rule with its alerts in this run (and background alerts once eval has run)."""
    st: RuleStore = request.app.state.rules
    rows = st.rows()
    if layer:
        rows = [r for r in rows if r["layer"] == layer.strip()]
    if q:
        n = q.strip().lower()
        rows = [r for r in rows if n in r["id"].lower() or n in (r["title"] or "").lower()
                or n in (r["technique"] or "").lower() or n in (r["technique_name"] or "").lower()]
    rows.sort(key=lambda r: (-r["alerts"], r["id"]))
    b: RunBundle = request.app.state.bundle
    unknown = Counter(a.get("rule_id") for a in b.alerts if a.get("rule_id") not in st.rules)
    return {"total": len(rows), "rules_dir": str(st.root), "errors": st.errors,
            "evaluated": b.metrics is not None,
            # alerts in this run from rules that are not in the rules folder (renamed or removed since)
            "unknown_rules": [{"rule_id": k, "alerts": v} for k, v in sorted(unknown.items())],
            "rules": rows}


@router.get("/rules/{rule_id}", tags=["rules"])
def get_rule(rule_id: str, request: Request) -> Dict[str, Any]:
    """One rule: its YAML, settings, hit counts and most recent alerts."""
    out = request.app.state.rules.detail(rule_id, request.app.state.bundle)
    if out is None:
        raise HTTPException(status_code=404, detail=f"rule {rule_id} not found")
    return out
