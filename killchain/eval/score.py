"""The PRD metrics for one run, measured against a truth table.

Inputs, all from the run folder (contracts B and C, docs/contracts.md):
  alerts.parquet            one row per alert
  alert_evidence.parquet    every evidence line (alert_id, source, line, technique, ...)
  incidents/<n>.json        incidents; an alert belongs to the incident whose chain lists it
  **/_stats.json            stage timings and memory

Any missing input counts as empty, so the harness runs before the pipeline exists.
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import polars as pl
import yaml

TARGETS = {  # metric: (good, great, higher_is_better)
    "detection_recall": (0.70, 0.90, True),
    "label_accuracy": (0.60, 0.85, True),
    "attack_path_rebuilt": (0.50, 1.00, True),
    "false_alarm_share": (0.30, 0.10, False),
    "processing_secs": (3 * 3600, 3600, False),
    "peak_rss_mb": (16 * 1024, 8 * 1024, False),
    "open_time_p95_ms": (2000, 500, False),
}
INCIDENT_COVERED = 0.8   # a truth incident is "found" when this share of its lines is covered
STEP_COVERED = 0.5       # a truth step counts as present in an incident at this share


def parent(t: Optional[str]) -> Optional[str]:
    return t.split(".")[0] if isinstance(t, str) else None


# ── loading ──────────────────────────────────────────────────────────────────

def load_run(run: Union[str, Path]) -> Dict[str, Any]:
    run = Path(run)
    alerts = pl.read_parquet(run / "alerts.parquet") if (run / "alerts.parquet").exists() else pl.DataFrame(
        schema={"alert_id": pl.Utf8, "rule_id": pl.Utf8, "layer": pl.Utf8, "technique": pl.Utf8})
    ev = pl.read_parquet(run / "alert_evidence.parquet") if (run / "alert_evidence.parquet").exists() else pl.DataFrame(
        schema={"alert_id": pl.Utf8, "source": pl.Utf8, "line": pl.Int64, "technique": pl.Utf8})
    incidents: List[Dict[str, Any]] = []
    for p in sorted((run / "incidents").glob("*.json")) if (run / "incidents").exists() else []:
        incidents.append(json.loads(p.read_text(encoding="utf-8")))
    stats = []
    for p in run.rglob("_stats.json"):
        try:
            stats.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    return {"alerts": alerts, "evidence": ev, "incidents": incidents, "stats": stats}


def membership(incidents: List[Dict[str, Any]]) -> pl.DataFrame:
    rows = [{"incident_number": inc["incident_number"], "incident_id": inc["incident_id"],
             "alert_id": s["alert_id"], "step_n": s["n"]}
            for inc in incidents for s in inc.get("chain", [])]
    return pl.DataFrame(rows, schema={"incident_number": pl.Int64, "incident_id": pl.Utf8,
                                      "alert_id": pl.Utf8, "step_n": pl.Int64})


# ── metrics ──────────────────────────────────────────────────────────────────

def score(truth: pl.DataFrame, run: Dict[str, Any], reviewed: Optional[Dict[str, Any]] = None,
          extra_stats: Optional[List[Dict[str, Any]]] = None, open_times_ms: Optional[List[float]] = None) -> Dict[str, Any]:
    reviewed = reviewed or {}
    alerts, ev, incidents = run["alerts"], run["evidence"], run["incidents"]
    layer = alerts.select("alert_id", pl.col("layer").fill_null("rule") if "layer" in alerts.columns
                          else pl.lit("rule").alias("layer"))
    ev = ev.select("alert_id", "source", "line", pl.col("technique").alias("our_technique")).join(
        layer, on="alert_id", how="left")
    mem = membership(incidents)

    # one row per (truth line, matching evidence row)
    hit = truth.join(ev, on=["source", "line"], how="inner")
    covered = hit.select("incident_id", "step_n", "source", "line").unique()
    n_truth = truth.height
    n_cov = covered.height

    # detection recall, overall / per incident / per class / by layer
    per_inc = (truth.group_by("incident_id", "incident_name", "class").agg(pl.len().alias("lines"))
               .join(covered.group_by("incident_id").agg(pl.len().alias("found")), on="incident_id", how="left")
               .with_columns(pl.col("found").fill_null(0))
               .with_columns((pl.col("found") / pl.col("lines")).alias("recall")).sort("incident_id"))
    per_class = (per_inc.group_by("class").agg(pl.col("lines").sum(), pl.col("found").sum())
                 .with_columns((pl.col("found") / pl.col("lines")).alias("recall")).sort("class"))
    rule_lines = hit.filter(pl.col("layer") == "rule").select("source", "line").unique().height
    anomaly_only = (hit.group_by("source", "line").agg(pl.col("layer").unique().alias("layers"))
                    .filter(pl.col("layers").list.contains("anomaly") & ~pl.col("layers").list.contains("rule")).height)

    # label accuracy: per covered truth line, best label among the evidence rows that cover it
    lab = hit.with_columns(
        (pl.col("our_technique") == pl.col("technique")).alias("exact"),
        (pl.col("our_technique").str.split(".").list.first() == pl.col("technique").str.split(".").list.first()).alias("parent"),
        ((pl.col("our_technique") == pl.col("technique")) | pl.col("alt").list.contains(pl.col("our_technique"))).alias("alt_ok"),
    ).group_by("source", "line").agg(pl.col("exact").any(), pl.col("parent").any(), pl.col("alt_ok").any())
    lab = lab.with_columns((pl.col("alt_ok") | pl.col("parent")).alias("any"))
    label = {k: (lab[k].sum() / n_cov if n_cov else 0.0) for k in ("exact", "parent", "any")}

    # attack paths: one of our incidents must cover the truth incident's steps, in order
    tl = hit.join(mem, on="alert_id", how="inner").rename({"step_n_right": "our_step"}) if mem.height else None
    paths = []
    for (iid, name, ordered), g in truth.group_by("incident_id", "incident_name", "ordered"):
        steps = g.group_by("step_n").agg(pl.len().alias("lines")).sort("step_n")
        best = None
        if tl is not None and tl.height:
            t = tl.filter(pl.col("incident_id") == iid)
            if t.height:
                cov = (t.select("incident_number", "step_n", "source", "line").unique()
                       .group_by("incident_number").agg(pl.len().alias("n")).sort("n", descending=True))
                best = int(cov["incident_number"][0])
        rebuilt, reason = False, "no incident covers it"
        if best is not None:
            t = tl.filter((pl.col("incident_id") == iid) & (pl.col("incident_number") == best))
            per_step = (t.select("step_n", "source", "line", "our_step").unique()
                        .group_by("step_n").agg(pl.col("line").n_unique().alias("found"), pl.col("our_step").min().alias("first_our")))
            st = steps.join(per_step, on="step_n", how="left").with_columns(pl.col("found").fill_null(0))
            present = (st["found"] / st["lines"] >= STEP_COVERED).all()
            order_ok = True
            if ordered and present:
                firsts = st.sort("step_n")["first_our"].to_list()
                order_ok = firsts == sorted(firsts)
            rebuilt = bool(present and order_ok)
            reason = "ok" if rebuilt else ("steps missing from the incident" if not present else "steps out of order")
        paths.append({"incident_id": iid, "incident_name": name, "steps": steps.height, "ordered": bool(ordered),
                      "our_incident": best, "rebuilt": rebuilt, "reason": reason})
    paths.sort(key=lambda p: p["incident_id"])
    n_paths = len(paths)

    # false alarms: our incidents that overlap no truth line
    truth_alerts = set(hit["alert_id"].unique().to_list())
    fa_rows = []
    for inc in incidents:
        ids = {s["alert_id"] for s in inc.get("chain", [])}
        if ids & truth_alerts:
            continue
        r = reviewed.get(inc["incident_id"], {})
        fa_rows.append({"incident_number": inc["incident_number"], "incident_id": inc["incident_id"],
                        "title": inc.get("title"), "reviewed": "real" if r.get("real") is True else
                        "false" if r.get("real") is False else "unreviewed"})
    n_inc = len(incidents)
    not_real = [r for r in fa_rows if r["reviewed"] != "real"]

    # per rule
    if alerts.height:
        bg = alerts.filter(~pl.col("alert_id").is_in(list(truth_alerts))).group_by("rule_id").agg(pl.len().alias("background_alerts"))
        per_rule = (alerts.group_by("rule_id").agg(pl.len().alias("alerts"))
                    .join(hit.join(alerts.select("alert_id", "rule_id"), on="alert_id")
                          .group_by("rule_id").agg(pl.struct("source", "line").n_unique().alias("truth_lines")),
                          on="rule_id", how="left")
                    .join(bg, on="rule_id", how="left").fill_null(0).sort("rule_id"))
    else:
        per_rule = pl.DataFrame(schema={"rule_id": pl.Utf8, "alerts": pl.UInt32, "truth_lines": pl.UInt32,
                                        "background_alerts": pl.UInt32})

    # time and memory
    stats = list(run["stats"]) + list(extra_stats or [])
    secs = sum(float(s.get("wall_secs") or 0) for s in stats)
    rss = max([s.get("peak_rss_mb") or 0 for s in stats] or [0])

    metrics = {
        "detection_recall": n_cov / n_truth if n_truth else 0.0,
        "label_accuracy": label["any"],
        "attack_path_rebuilt": sum(p["rebuilt"] for p in paths) / n_paths if n_paths else 0.0,
        "false_alarm_share": len(not_real) / n_inc if n_inc else 0.0,
        "processing_secs": secs,
        "peak_rss_mb": rss,
        "open_time_p95_ms": _p95(open_times_ms) if open_times_ms else None,
    }
    return {
        "metrics": metrics,
        "grades": {k: grade(k, v) for k, v in metrics.items()},
        "detail": {
            "truth_lines": n_truth, "covered_lines": n_cov, "rule_lines": rule_lines,
            "anomaly_only_lines": anomaly_only,
            "truth_incidents": per_inc.height,
            "incidents_found": int((per_inc["recall"] >= INCIDENT_COVERED).sum()) if per_inc.height else 0,
            "label_exact": label["exact"], "label_parent": label["parent"], "label_any": label["any"],
            "our_incidents": n_inc, "incidents_without_truth": len(fa_rows),
            "confirmed_false": sum(r["reviewed"] == "false" for r in fa_rows),
            "unreviewed": [r for r in fa_rows if r["reviewed"] == "unreviewed"],
            "multi_step_rebuilt": f"{sum(p['rebuilt'] for p in paths if p['steps'] > 1)}/{sum(p['steps'] > 1 for p in paths)}",
            "open_time_p50_ms": statistics.median(open_times_ms) if open_times_ms else None,
        },
        "per_incident": per_inc.to_dicts(),
        "per_class": per_class.to_dicts(),
        "paths": paths,
        "per_rule": per_rule.to_dicts(),
    }


def _p95(xs: List[float]) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]


def grade(metric: str, value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    good, great, higher = TARGETS[metric]
    if higher:
        return "great" if value >= great else "good" if value >= good else "below"
    return "great" if value <= great else "good" if value <= good else "below"


def measure_open_times(api: str, numbers: List[int], timeout: float = 5.0) -> List[float]:
    import httpx

    out = []
    with httpx.Client(timeout=timeout) as c:
        for n in numbers:
            t0 = time.perf_counter()
            c.get(f"{api.rstrip('/')}/incidents/{n}/path").raise_for_status()
            out.append((time.perf_counter() - t0) * 1000)
    return out


def load_reviewed(path: Union[str, Path]) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


# ── report ───────────────────────────────────────────────────────────────────

def render(result: Dict[str, Any]) -> str:
    m, g, d = result["metrics"], result["grades"], result["detail"]
    fmt = {
        "detection_recall": lambda v: f"{v:.1%}", "label_accuracy": lambda v: f"{v:.1%}",
        "attack_path_rebuilt": lambda v: f"{v:.1%}", "false_alarm_share": lambda v: f"{v:.1%}",
        "processing_secs": lambda v: f"{v:,.0f} s", "peak_rss_mb": lambda v: f"{v:,.0f} MB",
        "open_time_p95_ms": lambda v: f"{v:,.0f} ms",
    }
    lines = ["metric                 value        grade   (good / great)"]
    for k, (good, great, higher) in TARGETS.items():
        v = m[k]
        val = "n/a" if v is None else fmt[k](v)
        tgt = f"{fmt[k](good)} / {fmt[k](great)}"
        lines.append(f"{k:22s} {val:12s} {g[k]:7s} ({tgt})")
    lines.append("")
    lines.append(f"truth lines {d['truth_lines']:,}, covered {d['covered_lines']:,} "
                 f"(anomaly-only {d['anomaly_only_lines']:,}); truth incidents {d['truth_incidents']}, "
                 f"found {d['incidents_found']}")
    lines.append(f"labels: exact {d['label_exact']:.1%}, parent {d['label_parent']:.1%}, any accepted {d['label_any']:.1%}")
    lines.append(f"our incidents {d['our_incidents']}, without truth {d['incidents_without_truth']} "
                 f"(confirmed false {d['confirmed_false']}, unreviewed {len(d['unreviewed'])}); "
                 f"multi-step rebuilt {d['multi_step_rebuilt']}")
    missed = [r for r in result["per_incident"] if r["recall"] < INCIDENT_COVERED]
    if missed:
        lines.append("not found: " + ", ".join(f"#{r['incident_id']} {r['incident_name']} ({r['recall']:.0%})" for r in missed))
    if result["per_rule"]:
        lines.append("")
        lines.append("rule                          alerts  truth_lines  background")
        for r in result["per_rule"]:
            lines.append(f"{r['rule_id']:30s}{r['alerts']:6d}{r['truth_lines']:13d}{r['background_alerts']:12d}")
    return "\n".join(lines)
