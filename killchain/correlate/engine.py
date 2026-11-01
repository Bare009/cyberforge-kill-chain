"""Group alerts into incidents (docs/build-plan.md P6).

"Rule" below means a trusted detection: layer rule or vendor (contracts.TRUSTED_LAYERS); "anomaly" is the
anomaly layer.

Steps:
  1. Link rule-layer alerts that share non-hub entities (summed weight >= link_min) and pass the time rule;
     union-find gives the rule components.
  2. Keep the rule components that pass the promotion bar (judged on rule alerts only).
  3. Each anomaly alert joins the one promoted rule component it links to best (weight >= join_min).
  4. Left-over anomaly alerts are union-found among themselves; a component becomes an incident only when
     two different detectors fire on the same entity within `anomaly.within`, else it goes to unexplained.

Outputs in the run folder:
  incidents.parquet         one row per incident (provisional incident_number; P10 renumbers by risk)
  incident_alerts.parquet   one row per (incident, member alert) with the provisional chain order step_n
  unexplained.parquet       anomaly alerts that did not become or join an incident
  correlate/_stats.json     counts, wall time, peak memory
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import polars as pl

from .. import attack
from ..contracts import INCIDENT, TRUSTED_LAYERS, _check, _ts
from .entities import entity_rows, find_hubs

DT = pl.Datetime("us", "UTC")
INCIDENT_SCHEMA = {
    "incident_number": pl.Int64, "incident_id": pl.Utf8, "title": pl.Utf8, "status": pl.Utf8,
    "promoted_by": pl.Utf8, "severity": pl.Int64, "confidence_max": pl.Float64, "ts_start": DT, "ts_end": DT,
    "merged": pl.Struct({"alerts": pl.Int64, "events": pl.Int64}), "anomaly_steps": pl.Int64,
    "rule_ids": pl.List(pl.Utf8), "layers": pl.List(pl.Utf8), "tactics": pl.List(pl.Utf8),
    "techniques": pl.List(pl.Utf8),
    "entities": pl.Struct({k: pl.List(pl.Utf8) for k in ("ips", "hosts", "users", "domains")}),
}
MEMBER_SCHEMA = {"incident_id": pl.Utf8, "incident_number": pl.Int64, "alert_id": pl.Utf8, "step_n": pl.Int64,
                 "rule_id": pl.Utf8, "layer": pl.Utf8, "joined": pl.Utf8, "ts_start": DT, "stage_no": pl.Int64}
UNEXPLAINED_SCHEMA = {"alert_id": pl.Utf8, "rule_id": pl.Utf8, "group_id": pl.Utf8, "reason": pl.Utf8}
STRONG = ("external_ip", "internal_source", "host", "user")


class UnionFind:
    def __init__(self, items=()):
        self.p: Dict[Any, Any] = {x: x for x in items}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)

    def groups(self) -> List[List[Any]]:
        out: Dict[Any, List[Any]] = {}
        for x in self.p:
            out.setdefault(self.find(x), []).append(x)
        return [sorted(g) for g in sorted(out.values(), key=lambda g: min(g))]


def short_hash(ids) -> str:
    return hashlib.md5(",".join(sorted(ids)).encode("utf-8")).hexdigest()[:16]


# ── links ────────────────────────────────────────────────────────────────────

def _value_weight(kind: str, internal: Optional[bool], role_a: str, role_b: str) -> str:
    if kind != "ip":
        return kind
    if internal is not True:
        return "external_ip"
    return "internal_source" if role_a == "src" and role_b == "src" else "internal_target"


def pair_weights(rows: pl.DataFrame, hubs: Set[Tuple[str, str]], settings: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """(alert_a, alert_b) with a < b -> {weight, strong, shared}. Each shared non-hub value counts once,
    at its highest weight; hub values add nothing."""
    w = settings["weights"]
    nh = rows.filter(pl.Series([(k, v) not in hubs for k, v in rows.select("kind", "value").iter_rows()],
                               dtype=pl.Boolean)) if rows.height else rows
    j = nh.join(nh, on=["kind", "value"], suffix="_b").filter(pl.col("alert_id") < pl.col("alert_id_b"))
    best: Dict[Tuple[str, str, str, str], Tuple[float, bool]] = {}
    for r in j.iter_rows(named=True):
        cat = _value_weight(r["kind"], r["internal"], r["role"], r["role_b"])
        key = (r["alert_id"], r["alert_id_b"], r["kind"], r["value"])
        wt, strong = float(w[cat]), cat in STRONG
        old = best.get(key)
        if old is None or wt > old[0]:
            best[key] = (wt, strong or (old[1] if old else False))
        elif strong:
            best[key] = (old[0], True)
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for (a, b, kind, value), (wt, strong) in best.items():
        p = out.setdefault((a, b), {"weight": 0.0, "strong": False, "shared": []})
        p["weight"] = round(p["weight"] + wt, 6)
        p["strong"] = p["strong"] or strong
        p["shared"].append(f"{kind}:{value}")
    return out


def gap_secs(a: Dict[str, Any], b: Dict[str, Any]) -> float:
    """Seconds from the end of the earlier alert to the start of the later one; overlap is 0."""
    e, l = sorted((a, b), key=lambda x: (x["ts_start"], x["stage_no"]))
    return max(0.0, (l["ts_start"] - e["ts_end"]).total_seconds())


def time_ok(a: Dict[str, Any], b: Dict[str, Any], strong: bool, settings: Dict[str, Any]) -> bool:
    """Gap <= time.gap, or <= time.widened_gap when the later alert's stage is not lower and the pair shares
    an external IP, an internal source, a host or a user."""
    e, l = sorted((a, b), key=lambda x: (x["ts_start"], x["stage_no"]))
    gap = max(0.0, (l["ts_start"] - e["ts_end"]).total_seconds())
    if gap <= settings["time"]["gap"]:
        return True
    return bool(strong and gap <= settings["time"]["widened_gap"] and l["stage_no"] >= e["stage_no"])


# ── promotion ────────────────────────────────────────────────────────────────

def promotion(members: List[Dict[str, Any]], settings: Dict[str, Any]) -> Optional[str]:
    """Why a rule component is an incident, or None when it is below the bar."""
    p = settings["promotion"]
    if len({m["rule_id"] for m in members}) >= p["min_rules"]:
        return "rules>=2"
    if len({m["tactic"] for m in members}) >= p["min_tactics"]:
        return "tactics>=2"
    if any(m["severity"] >= p["single_severity"] and m["confidence"] >= p["single_confidence"] for m in members):
        return "single severe alert"
    if any(bool(m.get("promote")) for m in members):
        return "promote rule"
    return None


def detectors_agree(ids: List[str], A: Dict[str, Dict[str, Any]], rows: pl.DataFrame,
                    hubs: Set[Tuple[str, str]], settings: Dict[str, Any]) -> bool:
    """True when `anomaly.min_detectors` different detectors fire on one non-hub entity within `anomaly.within`."""
    need, within = settings["anomaly"]["min_detectors"], settings["anomaly"]["within"]
    by_value: Dict[Tuple[str, str], Set[str]] = {}
    for aid, k, v in rows.filter(pl.col("alert_id").is_in(ids)).select("alert_id", "kind", "value").iter_rows():
        if (k, v) not in hubs:
            by_value.setdefault((k, v), set()).add(aid)
    for group in by_value.values():
        for x in group:
            near = {A[y]["rule_id"] for y in group if gap_secs(A[x], A[y]) <= within}
            if len(near) >= need:
                return True
    return False


# ── main ─────────────────────────────────────────────────────────────────────

def correlate(alerts: pl.DataFrame, evidence: pl.DataFrame, net: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    if "layer" in alerts.columns:
        alerts = alerts.with_columns(pl.col("layer").fill_null("rule"))
    A = {r["alert_id"]: r for r in alerts.iter_rows(named=True)}
    rows = entity_rows(alerts, net)
    hubs = find_hubs(rows, net, settings)
    pw = pair_weights(rows, hubs, settings)
    rule_ids = sorted(a for a, r in A.items() if r["layer"] in TRUSTED_LAYERS)
    anom_ids = sorted(a for a, r in A.items() if r["layer"] not in TRUSTED_LAYERS)

    def linked(a: str, b: str, bar: float) -> Optional[Dict[str, Any]]:
        p = pw.get((min(a, b), max(a, b)))
        if p and p["weight"] >= bar and time_ok(A[a], A[b], p["strong"], settings):
            return p
        return None

    # 1. rule components
    uf = UnionFind(rule_ids)
    links = 0
    for (a, b), p in pw.items():
        if (A[a]["layer"] in TRUSTED_LAYERS and A[b]["layer"] in TRUSTED_LAYERS
                and linked(a, b, settings["link_min"])):
            uf.union(a, b)
            links += 1
    comps = uf.groups()

    # 2. promotion bar on rule alerts
    incidents: List[Dict[str, Any]] = []
    below = 0
    for g in comps:
        why = promotion([A[x] for x in g], settings)
        if why:
            incidents.append({"members": list(g), "extra": [], "promoted_by": why})
        else:
            below += 1

    # 3. anomaly alerts join the best promoted rule component
    left = []
    for x in anom_ids:
        best = None
        for ci, inc in enumerate(incidents):
            cand = None
            for m in inc["members"]:
                p = linked(x, m, settings["join_min"])
                if p:
                    k = (-p["weight"], gap_secs(A[x], A[m]), ci)
                    cand = k if cand is None or k < cand else cand
            if cand and (best is None or cand < best):
                best = cand
        if best is None:
            left.append(x)
        else:
            incidents[best[2]]["extra"].append(x)
            links += 1

    # 4. anomaly-only components
    uf2 = UnionFind(left)
    for i, a in enumerate(left):
        for b in left[i + 1:]:
            if linked(a, b, settings["link_min"]):
                uf2.union(a, b)
                links += 1
    unexplained = []
    anomaly_only = 0
    for g in uf2.groups():
        if detectors_agree(g, A, rows, hubs, settings):
            incidents.append({"members": list(g), "extra": [], "promoted_by": "two anomaly detectors"})
            anomaly_only += 1
        else:
            gid = short_hash(g)
            unexplained += [{"alert_id": x, "rule_id": A[x]["rule_id"], "group_id": gid,
                             "reason": "single anomaly detector"} for x in g]

    inc_df, mem_df = _frames(incidents, A, rows, hubs, evidence)
    stats = {"alerts": len(A), "rule_alerts": len(rule_ids), "anomaly_alerts": len(anom_ids),
             "vendor_alerts": sum(A[a]["layer"] == "vendor" for a in rule_ids), "links": links,
             "rule_components": len(comps), "below_bar": below, "incidents": inc_df.height,
             "anomaly_only_incidents": anomaly_only,
             "anomaly_joined": sum(len(i["extra"]) for i in incidents), "unexplained": len(unexplained),
             "largest_incident_alerts": int(inc_df["merged"].struct.field("alerts").max() or 0) if inc_df.height else 0,
             "hubs": sorted(_display(rows, hubs))}
    return {"incidents": inc_df, "incident_alerts": mem_df,
            "unexplained": pl.DataFrame(unexplained, schema=UNEXPLAINED_SCHEMA), "stats": stats}


def _display(rows: pl.DataFrame, hubs: Set[Tuple[str, str]]) -> Set[str]:
    seen = {(k, v): d for k, v, d in rows.select("kind", "value", "display").iter_rows()}
    return {seen.get(h, h[1]) for h in hubs}


def _unique(xs) -> List[Any]:
    out = []
    for x in xs:
        if x is not None and x not in out:
            out.append(x)
    return out


def _tactic_name(t: str) -> str:
    try:
        return attack.tactic_info(t)["name"]
    except (KeyError, ValueError):
        return str(t)


def _main_entity(ids: List[str], rows: pl.DataFrame, hubs: Set[Tuple[str, str]]) -> Tuple[str, str]:
    """(display, role) of the most frequent non-hub entity, preferring an external IP, then an internal
    source, then a user. Falls back to the first (hub) entity when every entity is a hub."""
    r = rows.filter(pl.col("alert_id").is_in(ids))
    count: Dict[Tuple[int, str, str], int] = {}
    for k, v, d, role, internal in r.select("kind", "value", "display", "role", "internal").iter_rows():
        if (k, v) in hubs:
            continue
        rank = (0 if k == "ip" and internal is not True else 1 if k == "ip" and role == "src"
                else 2 if k == "user" else 3)
        count[(rank, k, v)] = count.get((rank, k, v), 0) + 1
    if not count:
        return (r["display"][0], r["role"][0]) if r.height else ("unknown", "src")
    rank, k, v = min(count, key=lambda x: (x[0], -count[x], x[2]))
    hit = r.filter((pl.col("kind") == k) & (pl.col("value") == v)).sort("role", descending=True)  # src before dst
    return hit["display"][0], hit["role"][0]


def _frames(incidents: List[Dict[str, Any]], A: Dict[str, Dict[str, Any]], rows: pl.DataFrame,
            hubs: Set[Tuple[str, str]], evidence: pl.DataFrame) -> Tuple[pl.DataFrame, pl.DataFrame]:
    ev = evidence.select("alert_id", "source", "line") if evidence.height else None
    inc_rows, mem_rows = [], []
    for inc in incidents:
        ids = inc["members"] + inc["extra"]
        order = sorted(ids, key=lambda x: (A[x]["ts_start"], A[x]["stage_no"], A[x]["rule_id"], x))
        steps = [A[x] for x in order]
        rule_steps = [s for s in steps if s["layer"] in TRUSTED_LAYERS] or steps
        iid = short_hash(ids)
        main, role = _main_entity(ids, rows, hubs)
        rids = _unique(s["rule_id"] for s in steps)
        if len(_unique(s["rule_id"] for s in rule_steps)) == 1:
            title = f"{rule_steps[0]['title']} {'to' if role == 'dst' else 'from'} {main}"
        else:
            tac = _unique(s["tactic"] for s in rule_steps)
            span = _tactic_name(tac[0]) if len(tac) == 1 else f"{_tactic_name(tac[0])} to {_tactic_name(tac[-1])}"
            title = f"{span} by {main}"
        events = (ev.filter(pl.col("alert_id").is_in(ids)).select("source", "line").unique().height
                  if ev is not None else 0)
        r = rows.filter(pl.col("alert_id").is_in(ids))
        by_alert = {x: r.filter(pl.col("alert_id") == x) for x in order}

        def ents(kind: str) -> List[str]:
            return _unique(d for x in order for d in by_alert[x].filter(pl.col("kind") == kind)["display"])

        inc_rows.append({
            "incident_number": 0, "incident_id": iid, "title": title, "status": "incident",
            "promoted_by": inc["promoted_by"], "severity": max(int(s["severity"]) for s in steps),
            "confidence_max": max(float(s["confidence"]) for s in steps),
            "ts_start": min(s["ts_start"] for s in steps), "ts_end": max(s["ts_end"] for s in steps),
            "merged": {"alerts": len(ids), "events": events},
            "anomaly_steps": sum(s["layer"] == "anomaly" for s in steps),
            "rule_ids": rids, "layers": _unique(s["layer"] for s in steps),
            "tactics": _unique(s["tactic"] for s in steps), "techniques": _unique(s["technique"] for s in steps),
            "entities": {"ips": ents("ip"), "hosts": ents("host"), "users": ents("user"), "domains": ents("domain")},
        })
        extra = set(inc["extra"])
        for n, x in enumerate(order, 1):
            mem_rows.append({"incident_id": iid, "incident_number": 0, "alert_id": x, "step_n": n,
                             "rule_id": A[x]["rule_id"], "layer": A[x]["layer"],
                             "joined": "extra" if x in extra else "member", "ts_start": A[x]["ts_start"],
                             "stage_no": int(A[x]["stage_no"])})
    # provisional numbering: severity desc, distinct rules desc, ts_start, incident_id
    inc_rows.sort(key=lambda i: (-i["severity"], -len(i["rule_ids"]), i["ts_start"], i["incident_id"]))
    num = {}
    for n, i in enumerate(inc_rows, 1):
        i["incident_number"] = num[i["incident_id"]] = n
    for m in mem_rows:
        m["incident_number"] = num[m["incident_id"]]
    mem_rows.sort(key=lambda m: (m["incident_number"], m["step_n"]))
    return (pl.DataFrame(inc_rows, schema=INCIDENT_SCHEMA), pl.DataFrame(mem_rows, schema=MEMBER_SCHEMA))


# ── contract check and writing ───────────────────────────────────────────────

def _iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def contract_errors(result: Dict[str, Any], alert_ids: Set[str]) -> List[str]:
    """Check the incident fields P6 owns against contract C (the rest arrive in P7-P11) and that every
    chain alert is a known alert."""
    errors: List[str] = []
    for row in result["incidents"].iter_rows(named=True):
        d = dict(row, ts_start=_iso(row["ts_start"]), ts_end=_iso(row["ts_end"]))
        where = f"incident {d['incident_number']}"
        _check(d, {k: v for k, v in INCIDENT.items() if k in d}, where, errors)
        for k in ("alerts", "events"):
            if not isinstance(d["merged"].get(k), int):
                errors.append(f"{where}.merged.{k}: expected int")
        for k in ("ips", "hosts", "users", "domains"):
            if not isinstance(d["entities"].get(k), list):
                errors.append(f"{where}.entities.{k}: expected a list")
        for k in ("ts_start", "ts_end"):
            _ts(d[k], f"{where}.{k}", errors)
    for m in result["incident_alerts"].iter_rows(named=True):
        if m["alert_id"] not in alert_ids:
            errors.append(f"incident {m['incident_number']} step {m['step_n']}: alert_id {m['alert_id']!r} is not an alert")
    for (num,), g in result["incident_alerts"].group_by("incident_number"):
        if sorted(g["step_n"].to_list()) != list(range(1, g.height + 1)):
            errors.append(f"incident {num}: steps must be numbered 1..N")
    return errors


def write_outputs(run: Path, result: Dict[str, Any], stats: Dict[str, Any]) -> None:
    run.mkdir(parents=True, exist_ok=True)
    result["incidents"].write_parquet(run / "incidents.parquet")
    result["incident_alerts"].write_parquet(run / "incident_alerts.parquet")
    result["unexplained"].write_parquet(run / "unexplained.parquet")
    (run / "correlate").mkdir(exist_ok=True)
    (run / "correlate" / "_stats.json").write_text(json.dumps(stats, indent=1, default=str), encoding="utf-8")
