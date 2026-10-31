"""The P11 bundle step: the final writer of a run's API files (docs/build-plan.md P11).

Reads what the pipeline stages left in the run folder and writes, all or nothing:

  incidents/<n>.json      contract C, with threat intel and narrator reports merged in
  index.json              list rows, with ti_verdict and triage_verdict filled
  alerts.json             contract B list rows, incident_number from the incident membership
  unexplained.json        anomaly alerts that did not become or join an incident
  ti.json                 enrichment.json bound to this run's incident numbers (only when enrich ran)
  incident_lines.parquet  every evidence line of every step, incident numbers checked
  run_summary.json        stage timings and memory, counts, data quality, threat intel and LLM status
  bundle/_stats.json      this stage's own timing

Inputs, in the run folder unless said otherwise:

  index.json, incidents/<n>.json, alerts.json   required; from chain (P7), reach (P8), score (P10, may renumber)
  chains.json                                    pipeline step flags, so a rebundle starts clean
  incident_alerts.parquet, unexplained.parquet   from correlate
  enrichment.json                                from enrich (P9); entities matched by value
  report.json                                    from the narrator (P10b): {incidents: {incident_id: entry}}
  <stage>/_stats.json, <parsed>/_stats.json      stage timings; the parse stats give data quality

Detection fields (chain, graph, reach next, risk score, numbering) are copied, never changed.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .merge import apply_enrichment, apply_report, bind_enrichment, worst_verdict

INDEX_KEYS = ("incident_number", "incident_id", "title", "risk_score", "risk_band", "severity", "ts_start",
              "ts_end", "ts_start_ist", "ts_end_ist", "merged", "tactics", "techniques")
BANDS = ("critical", "high", "medium", "low")


class BundleInputError(Exception):
    """A required input is missing or unreadable."""


@dataclass
class BundleResult:
    run: str
    incidents: List[Dict[str, Any]]
    index: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    extra_files: Dict[str, Any]
    remove_files: List[str]
    summary: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BundleInputError(f"missing {path}") from exc
    except json.JSONDecodeError as exc:
        raise BundleInputError(f"{path} is not valid JSON: {exc}") from exc


def _opt_json(path: Path) -> Optional[Any]:
    return _read_json(path) if path.exists() else None


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- run summary

def data_quality(parse: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """What the Dashboard and System pages show about the raw log, from the parser's _stats.json."""
    if not parse:
        return None
    streams = parse.get("streams") or {}
    ts_q: Dict[str, int] = {}
    issues: Dict[str, int] = {}
    first, last = [], []
    for s in streams.values():
        for k, v in (s.get("ts_quality") or {}).items():
            ts_q[k] = ts_q.get(k, 0) + int(v)
        for k, v in (s.get("parse_issues") or {}).items():
            issues[k] = issues.get(k, 0) + int(v)
        if s.get("first_ok_utc"):
            first.append(s["first_ok_utc"])
        if s.get("last_ok_utc"):
            last.append(s["last_ok_utc"])
    summ = parse.get("summary") or {}
    dups = sum(int((v or {}).get("exact_duplicate_rows") or 0) for v in summ.values() if isinstance(v, dict))
    junk = parse.get("junk_ranges") or []
    small = parse.get("junk_small") or {}
    by_class = parse.get("lines_by_class") or {}
    return {
        "lines": parse.get("lines"),
        "bytes": parse.get("bytes"),
        "events": sum(int(s.get("rows") or 0) for s in streams.values()),
        "events_good_time": ts_q.get("ok", 0),
        "events_frozen_clock": ts_q.get("stuck", 0),
        "ts_quality": ts_q,
        "exact_duplicate_rows": dups,
        "rejected_lines": sum(int(v) for k, v in by_class.items() if k.startswith("rejected:")),
        "lines_by_class": by_class,
        "junk_bytes": sum(int(j.get("bytes") or 0) for j in junk) + int(small.get("bytes") or 0),
        "junk_ranges": [{k: j.get(k) for k in ("source", "start", "end", "bytes", "lines")} for j in junk],
        "parse_issues": issues,
        "first_good_ts": min(first) if first else None,
        "last_good_ts": max(last) if last else None,
        "note": ("Frozen-clock rows keep their line numbers but are left out of time-window rules; "
                 "junk ranges are binary data appended to the log and are not parsed."),
    }


def _stage_entry(stats: Dict[str, Any]) -> Dict[str, Any]:
    keep = ("wall_secs", "peak_rss_mb", "workers", "bytes", "lines", "rules", "alerts", "evidence_lines",
            "layers", "incidents", "steps", "unexplained", "contract_errors", "indicators", "lookups",
            "cache_hits", "failures")
    return {k: stats[k] for k in keep if k in stats}


def collect_stages(run_dir: Path, parsed_dir: Optional[Path], enrichment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    stages: Dict[str, Any] = {}
    if parsed_dir and (parsed_dir / "_stats.json").exists():
        stages["parse"] = _stage_entry(_read_json(parsed_dir / "_stats.json"))
    for p in sorted(run_dir.glob("*/_stats.json")):
        name = p.parent.name
        if name == "bundle":
            continue
        try:
            st = _read_json(p)
        except BundleInputError:
            continue
        if st.get("stage", name) != name:
            continue        # e.g. detect-only/ from tuning one rule, not the full stage
        stages[name] = _stage_entry(st)
    if enrichment:
        s = enrichment.get("summary") or {}
        stages["enrich"] = {"wall_secs": s.get("wall_secs"), "indicators": s.get("indicators"),
                            "lookups": s.get("lookups"), "cache_hits": s.get("cache_hits"),
                            "failures": s.get("failures")}
    return stages


def counts(incidents: List[Dict[str, Any]], alerts: List[Dict[str, Any]], unexplained: List[Dict[str, Any]],
           evidence_lines: Optional[int]) -> Dict[str, Any]:
    bands = {b: 0 for b in BANDS}
    for i in incidents:
        bands[i["risk_band"]] = bands.get(i["risk_band"], 0) + 1
    layers: Dict[str, int] = {}
    for a in alerts:
        layers[a.get("layer") or "rule"] = layers.get(a.get("layer") or "rule", 0) + 1
    starts = [a["ts_start"] for a in alerts if a.get("ts_start")]
    ends = [a["ts_end"] for a in alerts if a.get("ts_end")]
    return {
        "alerts": len(alerts),
        "alerts_by_layer": layers,
        "alerts_in_incidents": sum(a.get("incident_number") is not None for a in alerts),
        "unexplained": len(unexplained),
        "incidents": len(incidents),
        "incidents_by_band": bands,
        "critical_incidents": bands["critical"],
        "steps": sum(len(i.get("chain") or []) for i in incidents),
        "evidence_lines": evidence_lines if evidence_lines is not None
        else sum(int(s.get("line_total") or 0) for i in incidents for s in i.get("chain") or []),
        "first_alert": min(starts) if starts else None,
        "last_alert": max(ends) if ends else None,
    }


def ti_status(ti: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not ti:
        return None
    s = ti.get("summary") or {}
    return {"generated_at": ti.get("generated_at"), "offline": ti.get("offline"), "providers": ti.get("providers"),
            "indicators": len(ti.get("entities") or {}), "verdicts": s.get("verdicts") or {},
            "lookups": s.get("lookups"), "cache_hits": s.get("cache_hits"), "failures": s.get("failures"),
            "skipped_private": s.get("skipped_private")}


def llm_status(reports: Optional[Dict[str, Any]], applied: int) -> Dict[str, Any]:
    if not reports:
        return {"reports": 0, "source": "template", "note": "No narrator output; every incident has its template report."}
    return {"reports": applied, "generated_at": reports.get("generated_at"), "model": reports.get("model"),
            "usage": reports.get("usage")}


# --------------------------------------------------------------------------- the step

def build(run_dir: Path, parsed_dir: Optional[Path] = None) -> BundleResult:
    """Everything the bundle step would write, checked against the contracts; writes nothing."""
    import polars as pl

    from killchain.graph import incident_files as files

    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise BundleInputError(f"run folder not found: {run_dir}")
    warnings: List[str] = []

    index_in = _read_json(run_dir / "index.json")
    if not isinstance(index_in, dict) or not isinstance(index_in.get("incidents"), list):
        raise BundleInputError(f"{run_dir / 'index.json'}: needs an object with a list 'incidents'")
    alerts = _read_json(run_dir / "alerts.json")
    if not isinstance(alerts, list):
        raise BundleInputError(f"{run_dir / 'alerts.json'}: needs a list")
    run = str(index_in.get("run") or run_dir.name)

    incidents: Dict[int, Dict[str, Any]] = {}
    for row in index_in["incidents"]:
        n = row.get("incident_number")
        if not isinstance(n, int):
            raise BundleInputError(f"index.json: row without an integer incident_number: {row.get('incident_id')!r}")
        incidents[n] = _read_json(run_dir / "incidents" / f"{n}.json")
    number_of = {inc["incident_id"]: n for n, inc in incidents.items()}

    # 1. Step flags start from the pipeline's own (chains.json), so a rebundle never keeps old threat intel.
    chains = _opt_json(run_dir / "chains.json")
    if chains:
        base = {c["incident_id"]: {s["n"]: list(s.get("enrichment_flags") or []) for s in c.get("chain") or []}
                for c in chains.get("incidents") or []}
        for inc in incidents.values():
            flags = base.get(inc["incident_id"])
            if flags is None:
                warnings.append(f"incident {inc['incident_number']} ({inc['incident_id']}) is not in chains.json; "
                                "its step flags are kept as they are")
                continue
            for s in inc.get("chain") or []:
                s["enrichment_flags"] = flags.get(s["n"], [])

    # 2. Alert membership: incident_alerts.parquet (correlate) by incident_id, else the steps' alert ids.
    member_of: Dict[str, str] = {}
    members_path = run_dir / "incident_alerts.parquet"
    if members_path.exists():
        for inc_id, alert_id in pl.read_parquet(members_path, columns=["incident_id", "alert_id"]).iter_rows():
            member_of[alert_id] = inc_id
        stale = sorted({i for i in member_of.values() if i not in number_of})
        if stale:
            warnings.append(f"incident_alerts.parquet names {len(stale)} incident(s) missing from index.json, "
                            f"e.g. {stale[0]}; rerun chain")
    else:
        member_of = {s["alert_id"]: inc["incident_id"] for inc in incidents.values()
                     for s in inc.get("chain") or [] if s.get("alert_id")}
    alerts_out = [{**a, "incident_number": number_of.get(member_of.get(a.get("alert_id"), ""))} for a in alerts]
    changed = sum(a.get("incident_number") != b["incident_number"] for a, b in zip(alerts, alerts_out))
    if changed:
        warnings.append(f"{changed} alert(s) had a stale incident_number in alerts.json; fixed from the membership")

    # 3. Threat intel, matched by value so a renumbering by the risk score cannot misplace it.
    enrichment = _opt_json(run_dir / "enrichment.json")
    ti_doc = None
    ti_verdicts: Dict[int, Optional[str]] = {}
    if enrichment is not None:
        if not isinstance(enrichment.get("entities"), dict):
            raise BundleInputError(f"{run_dir / 'enrichment.json'}: needs an object 'entities'")
        ti_doc, missing, dropped = bind_enrichment(enrichment, incidents, alerts_out)
        if missing:
            warnings.append(f"{len(missing)} indicator(s) in the incidents have no threat intel "
                            f"(e.g. {missing[0]}); rerun enrich")
        if dropped:
            warnings.append(f"{len(dropped)} indicator(s) in enrichment.json are in no incident now and were left out")
        for n, inc in incidents.items():
            inc["enrichment"] = {}
            ti_verdicts[n] = apply_enrichment(inc, n, ti_doc)
    else:
        for n, inc in incidents.items():
            ti_verdicts[n] = worst_verdict(e.get("verdict") for e in (inc.get("enrichment") or {}).values()
                                           if e.get("verdict"))

    # 4. Narrator reports, keyed by incident_id.
    reports = _opt_json(run_dir / "report.json")
    triage: Dict[int, Optional[str]] = {}
    applied = 0
    if reports is not None:
        entries = reports.get("incidents") if isinstance(reports, dict) else None
        if not isinstance(entries, dict):
            raise BundleInputError(f"{run_dir / 'report.json'}: needs an object 'incidents' keyed by incident_id")
        for inc_id, entry in entries.items():
            n = number_of.get(inc_id)
            if n is None:
                warnings.append(f"report.json has a report for {inc_id}, which is not in this run; skipped")
                continue
            try:
                triage[n] = apply_report(incidents[n], entry)
                applied += 1
            except ValueError as exc:
                warnings.append(str(exc))
    for n, inc in incidents.items():
        if n not in triage:
            t = (inc.get("report") or {}).get("triage")
            triage[n] = t.get("verdict") if isinstance(t, dict) else None

    # 5. index.json from the incidents themselves.
    ordered = [incidents[n] for n in sorted(incidents)]
    rows = [{**{k: i[k] for k in INDEX_KEYS}, "triage_verdict": triage.get(i["incident_number"]),
             "ti_verdict": ti_verdicts.get(i["incident_number"])} for i in ordered]
    index: Dict[str, Any] = {"run": run, "incidents": rows}
    if index_in.get("sample"):
        index["sample"] = True
    scores = [r["risk_score"] for r in rows]
    if any(scores) and scores != sorted(scores, reverse=True):
        warnings.append("incident numbers are not in risk order (contract C: 1..N worst first); rerun score")

    # 6. Unexplained activity.
    alert_by_id = {a["alert_id"]: a for a in alerts_out}
    unexplained: List[Dict[str, Any]] = []
    unexp_path = run_dir / "unexplained.parquet"
    if unexp_path.exists():
        for r in pl.read_parquet(unexp_path).iter_rows(named=True):
            a = alert_by_id.get(r["alert_id"])
            if a is None:
                warnings.append(f"unexplained.parquet names alert {r['alert_id']}, which is not in alerts.json")
                continue
            unexplained.append({**a, "reason": r.get("reason"), "group_id": r.get("group_id")})
    else:
        unexplained = [{**a, "reason": "not in an incident", "group_id": None} for a in alerts_out
                       if a.get("layer") == "anomaly" and a.get("incident_number") is None]
    unexplained.sort(key=lambda a: (a.get("ts_start") or "", a["alert_id"]))

    extra: Dict[str, Any] = {"unexplained.json": {"run": run, "alerts": unexplained}}
    remove: List[str] = []
    if ti_doc is not None:
        extra["ti.json"] = {**ti_doc, "run": run}
    elif (run_dir / "ti.json").exists():
        remove.append("ti.json")       # an earlier bundle's; enrichment.json is gone

    # 7. Evidence lines: incident numbers follow incident_id.
    evidence_lines = None
    lines_path = run_dir / "incident_lines.parquet"
    if lines_path.exists():
        lines = pl.read_parquet(lines_path)
        evidence_lines = lines.height
        if "incident_id" in lines.columns and "incident_number" in lines.columns:
            fixed = lines.with_columns(
                pl.col("incident_id").replace_strict(number_of, default=None, return_dtype=pl.Int64)
                .alias("incident_number"))
            lost = fixed.filter(pl.col("incident_number").is_null()).height
            if lost:
                warnings.append(f"{lost} evidence line(s) belong to incidents no longer in the run; left out")
                fixed = fixed.filter(pl.col("incident_number").is_not_null())
                evidence_lines = fixed.height
            if lost or not fixed["incident_number"].equals(lines["incident_number"]):
                extra["incident_lines.parquet"] = fixed

    # 8. run_summary.json.
    old = _opt_json(run_dir / "run_summary.json") or {}
    if parsed_dir is None:
        guess = run_dir.parent.parent / "parsed" / run_dir.name
        parsed_dir = guess if guess.is_dir() else None
    parse_stats = _read_json(parsed_dir / "_stats.json") if parsed_dir and (parsed_dir / "_stats.json").exists() else None
    if parse_stats is None:
        warnings.append("no parser _stats.json found (give --parsed); data quality is left empty")
    stages = collect_stages(run_dir, parsed_dir, enrichment)
    inputs = (parse_stats or {}).get("inputs") or []
    summary: Dict[str, Any] = {
        "run": run,
        "sample": bool(old.get("sample") or index_in.get("sample")),
        "source": ", ".join(Path(i["path"]).name for i in inputs if i.get("path")) or old.get("source"),
        "bundled_at": now_iso(),
        "stages": stages,
        "totals": {
            "processing_secs": round(sum(float(s.get("wall_secs") or 0) for s in stages.values()), 2),
            "peak_rss_mb": max([int(s.get("peak_rss_mb") or 0) for s in stages.values()] or [0]),
        },
        "counts": counts(ordered, alerts_out, unexplained, evidence_lines),
        "data_quality": data_quality(parse_stats) or old.get("data_quality"),
        "threat_intel": ti_status(ti_doc),
        "llm": llm_status(reports, applied),
        "warnings": warnings,
    }
    if summary["sample"] and old.get("note"):
        summary["note"] = old["note"]

    errors = files.check(ordered, index, alerts_out)
    return BundleResult(run=run, incidents=ordered, index=index, alerts=alerts_out, extra_files=extra,
                        remove_files=remove, summary=summary, warnings=warnings, errors=errors)


def write(run_dir: Path, result: BundleResult, wall_secs: float, peak_rss_mb: int) -> None:
    """Write a checked result (errors must be empty). Files are replaced atomically, incidents/ as a whole."""
    from killchain.graph import incident_files as files

    if result.errors:
        raise ValueError("bundle has contract errors; nothing written")
    stats = {"stage": "bundle", "wall_secs": round(wall_secs, 2), "peak_rss_mb": peak_rss_mb,
             "incidents": len(result.incidents), "alerts": len(result.alerts),
             "unexplained": len(result.extra_files["unexplained.json"]["alerts"]),
             "indicators": len((result.extra_files.get("ti.json") or {}).get("entities") or {}),
             "reports": result.summary["llm"]["reports"], "warnings": len(result.warnings), "contract_errors": 0}
    summary = dict(result.summary)
    summary["stages"] = {**summary["stages"], "bundle": _stage_entry(stats)}
    summary["totals"] = {
        "processing_secs": round(sum(float(s.get("wall_secs") or 0) for s in summary["stages"].values()), 2),
        "peak_rss_mb": max(int(s.get("peak_rss_mb") or 0) for s in summary["stages"].values()),
    }
    extra = {**result.extra_files, "run_summary.json": summary, "bundle/_stats.json": stats}
    files.write(Path(run_dir), result.incidents, result.index, result.alerts, extra)
    for name in result.remove_files:
        p = Path(run_dir) / name
        if p.exists():
            p.unlink()


def run_bundle(run_dir: Path, parsed_dir: Optional[Path] = None, *, dry_run: bool = False) -> BundleResult:
    import psutil

    t0 = time.perf_counter()
    result = build(run_dir, parsed_dir)
    if not result.errors and not dry_run:
        mem = psutil.Process().memory_info()
        peak = getattr(mem, "peak_wset", None) or mem.rss        # peak_wset: Windows lifetime peak
        write(run_dir, result, time.perf_counter() - t0, round(peak / 2**20))
    return result
