"""ATT&CK matrix and technique detail over a run's alerts (P11, MITRE backend).

Response shapes are the same as AI-SOC's `web_app/backend/app/services/mitre_matrix.py`
so its MITRE page (web/src/pages/Mitre.tsx) works unchanged. The pure parts are
ported from there (catalogue loading, technique ids and URLs, shaping the cells);
the MongoDB aggregations are replaced by DuckDB GROUP BY queries over the alerts
of the loaded run.

Differences from AI-SOC, all deliberate:
- Time windows count back from the run's last alert, not from today: the logs
  are historical, so "last 24h" means the last 24 hours of the data.
- "Open" means an alert that is not in an incident; "correlated" means it is
  (docs/build-plan.md P11).
- `source` is the detection layer (rule, anomaly, or vendor: another product's
  alert); `status` is `open` or
  `correlated`; there are no false positives to include, so that flag is
  accepted and echoed but changes nothing.
- The per-technique breakdowns are by detection rule, by asset and by
  incident status, and the trend is by IST day, because the UI shows IST.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import duckdb
import orjson
import pyarrow as pa
from fastapi import APIRouter, HTTPException, Query, Request

CATALOGUE_PATH = Path(__file__).resolve().parents[1] / "attack" / "data" / "attack_catalogue.json"

MAX_RECENT = 10
TOP_N = 10
IST = timedelta(hours=5, minutes=30)
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_SEV_BUCKETS = ("critical", "high", "medium", "low", "info", "unknown")
_SEV_BY_ID = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
_SEV_ID_BY_NAME = {v: k for k, v in _SEV_BY_ID.items()}
SOURCES = ("rule", "anomaly", "vendor")       # contracts.LAYERS: the `source` filter values
PRESETS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90)}
DEFAULT_PRESET = "30d"


class MitreError(ValueError):
    """Caller-correctable problem; the message is safe to show."""


# ── Catalogue (ported from AI-SOC) ───────────────────────────────────────────


@lru_cache(maxsize=1)
def catalogue() -> Dict[str, Any]:
    """The shipped ATT&CK catalogue, with lookup indexes added."""
    cat = orjson.loads(CATALOGUE_PATH.read_bytes())
    cat["by_id"] = {t["id"]: t for t in cat["techniques"]}
    cat["parents"] = [t for t in cat["techniques"] if "parent" not in t]
    cat["subs_by_parent"] = {}
    for t in cat["techniques"]:
        if "parent" in t:
            cat["subs_by_parent"].setdefault(t["parent"], []).append(t)
    return cat


def technique_url(technique_id: str) -> str:
    parent, _, sub = technique_id.partition(".")
    return f"https://attack.mitre.org/techniques/{parent}/" + (f"{sub}/" if sub else "")


def normalise_technique(value: Any) -> Optional[str]:
    """'t1110.001 ' -> 'T1110.001'; None when it is not a technique id."""
    s = str(value or "").strip().upper()
    return s if _TECHNIQUE_RE.match(s) else None


def catalogue_info() -> Dict[str, Any]:
    cat = catalogue()
    return {
        "attackSpecVersion": cat.get("attack_spec_version"),
        "bundleModified": cat.get("bundle_modified"),
        "attribution": cat.get("attribution"),
        "domain": cat.get("domain"),
        "tacticsTotal": len(cat["tactics"]),
        "techniquesTotal": len(cat["parents"]),
        "subtechniquesTotal": len(cat["techniques"]) - len(cat["parents"]),
    }


def _tactic_name(cat: Dict[str, Any], tactic_id: str) -> str:
    return next((t["name"] for t in cat["tactics"] if t["id"] == tactic_id), tactic_id)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _parse_ts(value: Any) -> Optional[datetime]:
    """Contract time ('...Z') -> naive UTC datetime, the form stored in DuckDB."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return None


def _sev_label(severity_id: Any) -> Optional[str]:
    if severity_id is None:
        return None
    try:
        return _SEV_BY_ID.get(int(severity_id), "unknown").upper()
    except (TypeError, ValueError):
        return "UNKNOWN"


def _empty_sev() -> Dict[str, int]:
    return dict.fromkeys(_SEV_BUCKETS, 0)


def _add_sev(into: Dict[str, int], row: Dict[str, Any]) -> None:
    for b in _SEV_BUCKETS:
        into[b] += int(row.get(b) or 0)


_SEV_SQL = ", ".join(
    [f"count(*) FILTER (WHERE severity = {sid}) AS {name}" for sid, name in _SEV_BY_ID.items()]
    + ["count(*) FILTER (WHERE severity IS NULL OR severity NOT BETWEEN 1 AND 5) AS unknown"]
)


class MitreFilters:
    """The query the MITRE page sends: a preset or an absolute window, plus filters."""

    def __init__(self, preset: Optional[str] = None, start: Optional[datetime] = None, end: Optional[datetime] = None,
                 severities: Sequence[str] = (), statuses: Sequence[str] = (), sources: Sequence[str] = (),
                 include_false_positives: bool = False):
        if (start is None) != (end is None):
            raise MitreError("Give both start and end, or neither.")
        if start is not None and end is not None:
            start, end = _to_naive_utc(start), _to_naive_utc(end)
            if end <= start:
                raise MitreError("end must be after start.")
            preset = None
        elif preset is None:
            preset = DEFAULT_PRESET
        if preset is not None and preset not in PRESETS:
            raise MitreError(f"preset must be one of {sorted(PRESETS)}.")
        self.preset, self.start, self.end = preset, start, end
        self.severities = [s.lower() for s in severities if s]
        bad = [s for s in self.severities if s not in _SEV_ID_BY_NAME]
        if bad:
            raise MitreError(f"unknown severity {bad[0]!r}; use {list(_SEV_ID_BY_NAME)}.")
        self.statuses = [s.lower() for s in statuses if s]
        self.sources = [s.lower() for s in sources if s]
        bad = [s for s in self.sources if s not in SOURCES]
        if bad:
            raise MitreError(f"unknown source {bad[0]!r}; use {list(SOURCES)}.")
        self.include_false_positives = include_false_positives

    def window(self, run_end: datetime) -> Tuple[datetime, datetime]:
        if self.start is not None and self.end is not None:
            return self.start, self.end
        return run_end - PRESETS[self.preset], run_end

    def echo(self) -> Dict[str, Any]:
        return {"severities": self.severities, "statuses": self.statuses, "sources": self.sources,
                "includeFalsePositives": self.include_false_positives}


def _to_naive_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


# ── Store: the run's alerts in DuckDB ────────────────────────────────────────

_ALERT_SCHEMA = pa.schema([
    ("alert_id", pa.string()), ("rule_id", pa.string()), ("layer", pa.string()), ("title", pa.string()),
    ("summary", pa.string()), ("technique", pa.string()), ("technique_name", pa.string()),
    ("tactic", pa.string()), ("severity", pa.int32()), ("confidence", pa.float64()),
    ("ts_start", pa.timestamp("us")), ("ts_end", pa.timestamp("us")),
    ("src_ip", pa.string()), ("dst_ip", pa.string()), ("host", pa.string()),
    ("incident_number", pa.int64()),
])


class MitreStore:
    """The run's alerts in an in-memory DuckDB table, queried per request.

    The rows come from the bundle's alerts.json (already checked against
    contract B), the same alerts that alerts.parquet holds. A run has hundreds
    to a few thousand alerts, so the table is small and every query is fast.
    """

    def __init__(self, alerts: List[Dict[str, Any]]):
        rows = []
        for a in alerts:
            rows.append({
                "alert_id": a.get("alert_id"), "rule_id": a.get("rule_id"), "layer": a.get("layer"),
                "title": a.get("title"), "summary": a.get("summary"),
                "technique": a.get("technique"), "technique_name": a.get("technique_name"),
                "tactic": a.get("tactic"),
                "severity": a.get("severity") if isinstance(a.get("severity"), int) else None,
                "confidence": float(a["confidence"]) if isinstance(a.get("confidence"), (int, float)) else None,
                "ts_start": _parse_ts(a.get("ts_start")), "ts_end": _parse_ts(a.get("ts_end")),
                "src_ip": a.get("src_ip"), "dst_ip": a.get("dst_ip"), "host": a.get("host"),
                "incident_number": a.get("incident_number") if isinstance(a.get("incident_number"), int) else None,
            })
        self._con = duckdb.connect(":memory:")
        self._con.execute("SET TimeZone = 'UTC'")
        table = pa.Table.from_pylist(rows, schema=_ALERT_SCHEMA)
        self._con.register("alerts_arrow", table)
        self._con.execute("CREATE TABLE alerts AS SELECT * FROM alerts_arrow")
        self._con.unregister("alerts_arrow")
        ends = [r["ts_end"] or r["ts_start"] for r in rows if r["ts_end"] or r["ts_start"]]
        self.run_end: datetime = max(ends) if ends else datetime.now(timezone.utc).replace(tzinfo=None)

    def _query(self, sql: str, params: Sequence[Any]) -> List[Dict[str, Any]]:
        cur = self._con.cursor()  # one cursor per request: safe across FastAPI worker threads
        try:
            res = cur.execute(sql, list(params))
            cols = [d[0] for d in res.description]
            return [dict(zip(cols, row)) for row in res.fetchall()]
        finally:
            cur.close()

    def _where(self, f: MitreFilters, start: datetime, end: datetime,
               technique: Optional[str] = None) -> Tuple[str, List[Any]]:
        clauses = ["ts_start >= ?", "ts_start <= ?"]
        params: List[Any] = [start, end]
        if f.severities:
            clauses.append(f"severity IN ({', '.join('?' * len(f.severities))})")
            params += [_SEV_ID_BY_NAME[s] for s in f.severities]
        if f.statuses:
            parts = []
            if "open" in f.statuses:
                parts.append("incident_number IS NULL")
            if "correlated" in f.statuses:
                parts.append("incident_number IS NOT NULL")
            clauses.append("(" + (" OR ".join(parts) or "FALSE") + ")")
        if f.sources:
            clauses.append(f"layer IN ({', '.join('?' * len(f.sources))})")
            params += list(f.sources)
        if technique:
            clauses.append("(upper(technique) = ? OR upper(technique) LIKE ?)")
            params += [technique, technique + ".%"]
        return " AND ".join(clauses), params

    # ── Matrix ──────────────────────────────────────────────────────────────

    def matrix(self, f: MitreFilters) -> Dict[str, Any]:
        """Tactic x technique counts for a window (shape of AI-SOC build_matrix)."""
        start, end = f.window(self.run_end)
        where, params = self._where(f, start, end)
        rows = self._query(
            f"""
            SELECT technique, any_value(technique_name) AS name, count(*) AS alerts,
                   max(ts_start) AS last_seen, max(severity) AS max_sev,
                   count(*) FILTER (WHERE incident_number IS NULL) AS open,
                   count(*) FILTER (WHERE incident_number IS NOT NULL) AS correlated,
                   {_SEV_SQL}
            FROM alerts WHERE {where} GROUP BY technique
            """,
            params,
        )

        cat = catalogue()
        seen: Dict[str, Dict[str, Any]] = {}
        unmapped_alerts = 0
        unknown_ids: Dict[str, int] = {}
        total_alerts = 0

        for row in rows:
            n = int(row.get("alerts") or 0)
            total_alerts += n
            observed = normalise_technique(row.get("technique"))
            if observed is None:                       # 'unknown' (anomaly without a label)
                unmapped_alerts += n
                continue
            parent = observed.split(".")[0]
            if parent not in cat["by_id"]:
                unknown_ids[observed] = unknown_ids.get(observed, 0) + n
                continue
            for target in (parent, observed):
                if target != parent and target not in cat["by_id"]:
                    # A sub-technique id this catalogue does not know: keep it on the parent only.
                    continue
                slot = seen.setdefault(target, {
                    "alerts": 0, "open": 0, "correlated": 0, "severity": _empty_sev(),
                    "max_sev_id": None, "last_seen": None,
                })
                slot["alerts"] += n
                slot["open"] += int(row.get("open") or 0)
                slot["correlated"] += int(row.get("correlated") or 0)
                _add_sev(slot["severity"], row)
                msev = row.get("max_sev")
                if msev is not None and (slot["max_sev_id"] is None or int(msev) > int(slot["max_sev_id"])):
                    slot["max_sev_id"] = int(msev)
                ls = row.get("last_seen")
                if isinstance(ls, datetime) and (slot["last_seen"] is None or ls > slot["last_seen"]):
                    slot["last_seen"] = ls
                if target == observed:
                    break

        def _cell(entry: Dict[str, Any]) -> Dict[str, Any]:
            tid = entry["id"]
            obs = seen.get(tid)
            subs = cat["subs_by_parent"].get(tid, [])
            sub_rows = [
                {"id": s["id"], "name": s["name"], "alerts": seen[s["id"]]["alerts"],
                 "maxSeverity": _sev_label(seen[s["id"]]["max_sev_id"]),
                 "lastSeen": _iso(seen[s["id"]]["last_seen"])}
                for s in subs if s["id"] in seen
            ]
            sub_rows.sort(key=lambda r: (-r["alerts"], r["id"]))
            return {
                "id": tid,
                "name": entry["name"],
                "url": technique_url(tid),
                "alerts": obs["alerts"] if obs else 0,
                "seen": obs is not None,
                "openAlerts": obs["open"] if obs else 0,
                "correlatedAlerts": obs["correlated"] if obs else 0,
                "severity": dict(obs["severity"]) if obs else _empty_sev(),
                "maxSeverity": _sev_label(obs["max_sev_id"]) if obs else None,
                "lastSeen": _iso(obs["last_seen"]) if obs else None,
                "subtechniquesTotal": len(subs),
                "subtechniquesSeen": len(sub_rows),
                "subtechniques": sub_rows,
            }

        tactics_out: List[Dict[str, Any]] = []
        for tactic in cat["tactics"]:
            cells = [_cell(t) for t in cat["parents"] if tactic["id"] in t["tactics"]]
            cells.sort(key=lambda c: (-c["alerts"], c["name"], c["id"]))
            hit = [c for c in cells if c["seen"]]
            severity = _empty_sev()
            for c in hit:
                _add_sev(severity, c["severity"])
            max_ids = [seen[c["id"]]["max_sev_id"] for c in hit if seen[c["id"]]["max_sev_id"] is not None]
            tactics_out.append({
                "id": tactic["id"],
                "shortname": tactic["shortname"],
                "name": tactic["name"],
                "url": f"https://attack.mitre.org/tactics/{tactic['id']}/",
                "techniquesTotal": len(cells),
                "techniquesSeen": len(hit),
                "alerts": sum(c["alerts"] for c in hit),
                "severity": severity,
                "maxSeverity": _sev_label(max(max_ids)) if max_ids else None,
                "techniques": cells,
            })

        parents_seen = [tid for tid in seen if "." not in tid]
        subs_seen = [tid for tid in seen if "." in tid]
        top = sorted(
            ({"id": tid, "name": cat["by_id"][tid]["name"], "url": technique_url(tid),
              "tactics": [_tactic_name(cat, x) for x in cat["by_id"][tid]["tactics"]],
              "alerts": s["alerts"], "maxSeverity": _sev_label(s["max_sev_id"]),
              "lastSeen": _iso(s["last_seen"])}
             for tid, s in seen.items() if "." not in tid),
            key=lambda r: (-r["alerts"], r["id"]),
        )[:TOP_N]

        return {
            "period": {"start": _iso(start), "end": _iso(end), "preset": f.preset},
            "filters": f.echo(),
            "catalogue": catalogue_info(),
            "summary": {
                "alertsTotal": total_alerts,
                "alertsMapped": total_alerts - unmapped_alerts - sum(unknown_ids.values()),
                "alertsUnmapped": unmapped_alerts,
                "alertsUnknownTechnique": sum(unknown_ids.values()),
                "techniquesSeen": len(parents_seen),
                "techniquesTotal": len(cat["parents"]),
                "subtechniquesSeen": len(subs_seen),
                "subtechniquesTotal": len(cat["techniques"]) - len(cat["parents"]),
                "tacticsSeen": sum(1 for t in tactics_out if t["techniquesSeen"]),
                "tacticsTotal": len(cat["tactics"]),
            },
            "tactics": tactics_out,
            "topTechniques": top,
            "unknownTechniques": [{"id": k, "alerts": v} for k, v in
                                  sorted(unknown_ids.items(), key=lambda kv: -kv[1])[:TOP_N]],
        }

    # ── Technique detail ────────────────────────────────────────────────────

    def technique_detail(self, technique_id: str, f: MitreFilters) -> Dict[str, Any]:
        """Everything about one technique in the window (shape of AI-SOC build_technique_detail).

        A parent technique includes its sub-techniques, as in the matrix cell.
        """
        tid = normalise_technique(technique_id)
        if tid is None:
            raise MitreError("Expected a technique id like T1110 or T1110.001.")
        cat = catalogue()
        entry = cat["by_id"].get(tid)
        if entry is None:
            raise MitreError(f"{tid} is not in the shipped ATT&CK catalogue.")

        start, end = f.window(self.run_end)
        where, params = self._where(f, start, end, technique=tid)
        q = lambda sql: self._query(sql.format(where=where), params)  # noqa: E731

        totals = (q(f"""
            SELECT count(*) AS alerts, max(severity) AS max_sev, min(ts_start) AS first_seen,
                   max(ts_start) AS last_seen,
                   count(*) FILTER (WHERE incident_number IS NULL) AS open,
                   count(*) FILTER (WHERE incident_number IS NOT NULL) AS correlated,
                   {_SEV_SQL}
            FROM alerts WHERE {{where}}""") or [{}])[0]
        by_day = {r["day"]: r for r in q(f"""
            SELECT strftime(ts_start + INTERVAL 330 MINUTE, '%Y-%m-%d') AS day, count(*) AS alerts, {_SEV_SQL}
            FROM alerts WHERE {{where}} GROUP BY day""")}
        by_tech = q("""
            SELECT upper(technique) AS technique, count(*) AS alerts, max(ts_start) AS last_seen,
                   max(severity) AS max_sev
            FROM alerts WHERE {where} GROUP BY 1 ORDER BY alerts DESC LIMIT 50""")
        by_rule = q(f"""
            SELECT rule_id AS name, count(*) AS alerts FROM alerts WHERE {{where}}
            GROUP BY 1 ORDER BY alerts DESC, name LIMIT {TOP_N}""")
        by_asset = q(f"""
            SELECT coalesce(host, dst_ip) AS name, count(*) AS alerts FROM alerts
            WHERE {{where}} AND coalesce(host, dst_ip) IS NOT NULL
            GROUP BY 1 ORDER BY alerts DESC, name LIMIT {TOP_N}""")
        by_status = q("""
            SELECT CASE WHEN incident_number IS NULL THEN 'not in an incident' ELSE 'in an incident' END AS name,
                   count(*) AS alerts
            FROM alerts WHERE {where} GROUP BY 1 ORDER BY alerts DESC""")
        recent = q(f"""
            SELECT alert_id, ts_start, severity, incident_number, title, summary, rule_id, technique, confidence
            FROM alerts WHERE {{where}} ORDER BY ts_start DESC, alert_id LIMIT {MAX_RECENT}""")

        trend = []
        for key in _ist_day_keys(start, end):
            row = by_day.get(key) or {}
            trend.append({"date": key, "alerts": int(row.get("alerts") or 0),
                          **{b: int(row.get(b) or 0) for b in _SEV_BUCKETS}})

        subs = []
        for r in by_tech:
            sid = normalise_technique(r.get("technique"))
            if sid is None or "." not in sid:
                continue
            known = cat["by_id"].get(sid)
            subs.append({"id": sid, "name": (known or {}).get("name"), "inCatalogue": known is not None,
                         "url": technique_url(sid), "alerts": int(r.get("alerts") or 0),
                         "maxSeverity": _sev_label(r.get("max_sev")), "lastSeen": _iso(r.get("last_seen"))})
        direct = sum(int(r.get("alerts") or 0) for r in by_tech if normalise_technique(r.get("technique")) == tid)

        severity = _empty_sev()
        _add_sev(severity, totals)
        return {
            "technique": {
                "id": tid, "name": entry["name"], "url": technique_url(tid),
                "parent": entry.get("parent"),
                "parentName": (cat["by_id"].get(entry["parent"]) or {}).get("name") if entry.get("parent") else None,
                "tactics": [{"id": x, "name": _tactic_name(cat, x)} for x in entry["tactics"]],
                "subtechniquesTotal": len(cat["subs_by_parent"].get(tid, [])),
            },
            "period": {"start": _iso(start), "end": _iso(end), "preset": f.preset},
            "summary": {
                "alerts": int(totals.get("alerts") or 0),
                "openAlerts": int(totals.get("open") or 0),
                "correlatedAlerts": int(totals.get("correlated") or 0),
                "alertsOnTechniqueItself": direct,
                "severity": severity,
                "maxSeverity": _sev_label(totals.get("max_sev")),
                "firstSeen": _iso(totals.get("first_seen")),
                "lastSeen": _iso(totals.get("last_seen")),
            },
            "trend": trend,
            "subtechniques": subs,
            # AI-SOC's "source" is the SIEM; here it is the detection rule that raised the alert.
            "bySource": [{"source": str(r["name"] or "unknown"), "alerts": int(r["alerts"])} for r in by_rule],
            "byAsset": [{"asset": str(r["name"]), "alerts": int(r["alerts"])} for r in by_asset],
            "byStatus": [{"status": str(r["name"]), "alerts": int(r["alerts"])} for r in by_status],
            "recentAlerts": [
                {"id": r.get("alert_id"),
                 "time": _iso(r.get("ts_start")),
                 "severity": _sev_label(r.get("severity")) or "UNKNOWN",
                 "status": "open" if r.get("incident_number") is None else "correlated",
                 "title": ((r.get("summary") or r.get("title") or "")[:200]) or None,
                 "source": r.get("rule_id"),
                 "subtechniqueId": (lambda t: t if t and "." in t else None)(normalise_technique(r.get("technique"))),
                 "confidence": r.get("confidence"),
                 "incidentNumber": r.get("incident_number")}
                for r in recent
            ],
        }


def _ist_day_keys(start: datetime, end: datetime) -> List[str]:
    """Every IST calendar day the UTC window touches, oldest first (at most 400)."""
    cur = (start + IST).replace(hour=0, minute=0, second=0, microsecond=0)
    last = end + IST
    out: List[str] = []
    while cur <= last and len(out) <= 400:
        out.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return out


# ── Routes ───────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/mitre", tags=["mitre"])


def _store(request: Request) -> MitreStore:
    return request.app.state.mitre


def _filters(preset: Optional[str], start: Optional[datetime], end: Optional[datetime],
             severity: Optional[List[str]], status: Optional[List[str]], source: Optional[List[str]],
             include_false_positives: bool) -> MitreFilters:
    try:
        return MitreFilters(preset=preset, start=start, end=end, severities=severity or [],
                            statuses=status or [], sources=source or [],
                            include_false_positives=include_false_positives)
    except MitreError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/catalogue")
def mitre_catalogue() -> Dict[str, Any]:
    """Which ATT&CK release the shipped catalogue came from, and its attribution."""
    return {"catalogue": catalogue_info()}


@router.get("/matrix")
def mitre_matrix(
    request: Request,
    preset: Optional[str] = Query(None, description="24h | 7d | 30d | 90d, counted back from the run's last alert"),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    severity: Optional[List[str]] = Query(None, description="critical | high | medium | low | info"),
    status: Optional[List[str]] = Query(None, description="open (not in an incident) | correlated"),
    source: Optional[List[str]] = Query(None, description="rule | anomaly | vendor"),
    include_false_positives: bool = Query(False),
) -> Dict[str, Any]:
    f = _filters(preset, start, end, severity, status, source, include_false_positives)
    return _store(request).matrix(f)


@router.get("/techniques/{technique_id}")
def mitre_technique(
    technique_id: str,
    request: Request,
    preset: Optional[str] = Query(None),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    source: Optional[List[str]] = Query(None),
    include_false_positives: bool = Query(False),
) -> Dict[str, Any]:
    f = _filters(preset, start, end, severity, status, source, include_false_positives)
    try:
        return _store(request).technique_detail(technique_id, f)
    except MitreError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
