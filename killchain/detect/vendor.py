"""Vendor alerts: detections another product already raised -> killchain alerts with layer `vendor`.

Records the schema stage put in category `vendor_alert` (Sentinel SecurityAlert, SentinelOne threats,
Wazuh alerts, EDR alerts ...) are detections already. `python -m killchain detect` runs this step after
the rules when such records exist and writes its alerts into the same alerts.parquet and
alert_evidence.parquet (contract B).

Grouping: one alert per (product, alert name, main entity) while the records are less than `group_gap`
apart (config/vendor_alert_keywords.yaml, default 1 h), so a repeated alert does not flood. The main
entity is the host, else the user, else the source IP, else the destination IP. The alert's evidence
lines are its records.

Fields: rule_id `vendor:<product slug>:<alert name slug>`, title = the alert name, severity = the highest
vendor_severity (default 3), confidence = the highest alert_confidence (default 0.7), entities from the
canonical columns plus the alert's entity list (Sentinel `Entities`: Ip, Account and Host objects, kept in
`extra`). promote is true at severity >= promote_severity, so such an alert is an incident on its own.

ATT&CK label, first that applies (technique_source):
  1. vendor   the records' mitre_technique ids that are in the catalogue: the first is the technique,
              the rest alt_techniques; the tactic is the earliest kill chain stage among the vendor's
              tactics that belong to that technique, else among all of its tactics
  2. vendor   only mitre_tactic: that tactic with technique `unknown`
  3. keyword  the first regex of `keywords` that matches the alert name (+ attack, virus, msg)
  4. llm      one LLM call labels every distinct alert name still unlabelled (temperature 0, cached in
              data/cache/vendor_llm/; skipped with --no-llm, LLM_ENABLED not true or no key)
  5. unknown  technique `unknown`, tactic discovery
stage_no and kill_chain_stage follow from the tactic (killchain.attack).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import duckdb
import polars as pl
import yaml

from .. import attack
from .rules import duration

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_YAML = ROOT / "config" / "vendor_alert_keywords.yaml"
CACHE_DIR = ROOT / "data" / "cache" / "vendor_llm"
PROMPT_VERSION = 1
MAX_LLM_NAMES = 200
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
FAILED = {"deny", "dropped", "blocked", "block", "drop", "reset"}
ENTITY_KEYS = {"entities", "alertentities", "evidence", "entity"}
COLS = ["source", "line", "byte_offset", "ts", "ts_utc", "product", "alert_name", "attack", "virus", "msg",
        "log_desc", "vendor_severity", "alert_confidence", "mitre_technique", "mitre_tactic", "src_ip", "dst_ip",
        "user", "host", "host_ip", "hostname", "url", "action", "status", "extra"]
FILE_EXT_RE = re.compile(r"\.(exe|dll|ps1|bat|cmd|vbs|js|zip|docx?|xlsx?|pdf|sys|tmp|dat|bin|lnk|hta)$", re.I)


# ── settings ─────────────────────────────────────────────────────────────────

def load_settings(path: Path = SETTINGS_YAML) -> Dict[str, Any]:
    """The YAML with group_gap in seconds and each keyword compiled and its label checked."""
    d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    kws = []
    for i, k in enumerate(d.get("keywords") or []):
        try:
            lab = attack.label(k["technique"], k.get("tactic"))
        except (attack.AttackError, KeyError) as e:
            raise ValueError(f"{Path(path).name} keyword {i + 1} ({k.get('pattern')!r}): {e}") from None
        kws.append((re.compile(k["pattern"], re.I), lab))
    return {"group_gap": duration(d.get("group_gap", "1h"), "group_gap"),
            "default_confidence": float(d.get("default_confidence", 0.7)),
            "default_severity": int(d.get("default_severity", 3)),
            "promote_severity": int(d.get("promote_severity", 4)), "keywords": kws}


# ── small helpers ────────────────────────────────────────────────────────────

def slug(text: Any, n: int = 60) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")
    return s[:n].rstrip("-") or "unnamed"


def tactic_of(name: Any) -> Optional[str]:
    """ATT&CK tactic shortname for any common spelling ('InitialAccess', 'Initial Access', 'TA0001',
    'initial_access'), or None."""
    t = str(name or "").strip()
    if not t:
        return None
    try:
        return attack.tactic(t)
    except attack.AttackError:
        pass
    key = re.sub(r"[^a-z0-9]", "", t.lower())
    for info in attack.all_tactics():
        if key in (re.sub(r"[^a-z0-9]", "", info["shortname"]), re.sub(r"[^a-z0-9]", "", info["name"].lower()),
                   info["id"].lower()):
            return info["shortname"]
    return None


def split_list(v: Any) -> List[str]:
    """Items of a comma/semicolon separated value or a JSON list written as text."""
    if v is None:
        return []
    s = str(v).strip()
    if s.startswith("["):
        try:
            x = json.loads(s)
            if isinstance(x, list):
                return [str(i).strip() for i in x if str(i).strip()]
        except ValueError:
            pass
    return [p.strip().strip("'\"[]") for p in re.split(r"[,;|]", s) if p.strip().strip("'\"[]")]


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _private(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _blocked(r: Dict[str, Any]) -> bool:
    return (str(r.get("action") or "").lower() in FAILED
            or str(r.get("status") or "").lower() in ("failed", "failure"))


# ── entities ─────────────────────────────────────────────────────────────────

def _entity_objects(objs: Iterable[Any], out: Dict[str, List[str]]) -> None:
    for o in objs:
        if not isinstance(o, dict):
            continue
        typ = str(o.get("Type") or o.get("type") or o.get("kind") or "").lower()
        low = {str(k).lower(): v for k, v in o.items()}
        if typ in ("ip", "ipaddress") or (not typ and low.get("address")):
            for k in ("address", "ipaddress", "ip"):
                if low.get(k) and _is_ip(str(low[k])):
                    out["ips"].append(str(low[k]))
        elif typ in ("host", "machine", "device"):
            h = low.get("hostname") or low.get("netbiosname")
            if h:
                out["hosts"].append(str(h))
            for k in ("address", "ipaddress", "lastipaddress"):
                if low.get(k) and _is_ip(str(low[k])):
                    out["host_ips"].append(str(low[k]))
        elif typ in ("account", "user", "mailbox"):
            u = low.get("name") or low.get("accountname") or low.get("userprincipalname") or low.get("upn")
            if u:
                out["users"].append(str(u))


def entities_from_extra(extra: Optional[str]) -> Dict[str, List[str]]:
    """IPs, hosts, host IPs and users of the alert's entity list, kept in `extra` by the schema stage.

    Handles the list as JSON (an object list or a JSON string of one, as Sentinel exports `Entities`) and
    the flattened form (`Entities.Address = "1.2.3.4,10.0.0.1"`, `Entities.HostName`, `Entities.Name`)."""
    out: Dict[str, List[str]] = {"ips": [], "hosts": [], "host_ips": [], "users": []}
    if not extra:
        return out
    try:
        doc = json.loads(extra)
    except ValueError:
        return out
    if not isinstance(doc, dict):
        return out
    for k, v in doc.items():
        parts = str(k).split(".")
        if re.sub(r"[^a-z]", "", parts[0].lower()) not in ENTITY_KEYS:
            continue
        if len(parts) == 1:
            if isinstance(v, str) and v.strip().startswith("["):
                try:
                    v = json.loads(v)
                except ValueError:
                    continue
            if isinstance(v, list):
                _entity_objects(v, out)
            continue
        sub = re.sub(r"[^a-z]", "", parts[-1].lower())
        vals = split_list(v)
        if sub in ("address", "ipaddress", "ip", "lastipaddress"):
            out["ips"] += [x for x in vals if _is_ip(x)]
        elif sub in ("hostname", "netbiosname", "computer", "computername"):
            out["hosts"] += vals
        elif sub in ("name", "accountname", "userprincipalname", "upn"):
            out["users"] += [x for x in vals if not FILE_EXT_RE.search(x) and "\\" not in x and "/" not in x
                             and not _is_ip(x)]
    for k in out:
        out[k] = list(dict.fromkeys(out[k]))
    return out


def resolve_entities(r: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Contract-B entities of one record: the canonical columns first, then its entity list. An external
    entity IP is the source; the host's own IP (host_ip) is the destination."""
    ents = entities_from_extra(r.get("extra"))
    host = r.get("host") or (ents["hosts"][0] if ents["hosts"] else None)
    user = r.get("user") or (ents["users"][0] if ents["users"] else None)
    host_ip = r.get("host_ip") or (ents["host_ips"][0] if ents["host_ips"] else None)
    ips = [x for x in ents["ips"] if x != host_ip]
    src = r.get("src_ip")
    if not src and ips:                    # an entity IP: outside addresses first (the attacker)
        ext = [x for x in ips if not _private(x)]
        src = ext[0] if ext else ips[0]
    dst = r.get("dst_ip")
    if host_ip and host_ip not in (src, dst):
        # the alerted machine: the target of an outside or other source, else the actor itself
        if src and not dst:
            dst = host_ip
        elif not src:
            src = host_ip
    if not dst:
        rest = [x for x in ips if x not in (src, host_ip)]
        dst = rest[0] if rest else None
    return {"src_ip": src, "dst_ip": dst, "host": host, "user": user, "domain": r.get("hostname"),
            "url": r.get("url")}


def main_entity(e: Dict[str, Optional[str]]) -> str:
    for k in ("host", "user", "src_ip", "dst_ip"):
        if e.get(k):
            return f"{k}:{str(e[k]).strip().lower()}"
    return "-"


# ── ATT&CK labels ────────────────────────────────────────────────────────────

def _earliest(tactics: Sequence[str]) -> str:
    return min(tactics, key=attack.stage_no)


def vendor_label(techniques: Sequence[str], tactics: Sequence[str]) -> Optional[Tuple[Dict[str, Any], List[str]]]:
    """(label, alt_techniques) from the vendor's MITRE fields, or None when they give nothing usable.
    techniques: raw id strings in record order; tactics: raw tactic names."""
    tacs = [t for t in (tactic_of(x) for x in tactics) if t]
    valid: List[str] = []
    for raw in techniques:
        for tid in TECH_RE.findall(str(raw)):
            tid = tid.upper()
            for cand in (tid, attack.parent(tid)):
                if attack.is_technique(cand):
                    if cand not in valid:
                        valid.append(cand)
                    break
    if valid:
        t = attack.technique(valid[0])
        mine = [x for x in tacs if x in t.tactics]
        tac = _earliest(mine or list(t.tactics))
        return attack.label(t.id, tac), valid[1:]
    if tacs:
        return attack.unknown_label(tacs[0]), []
    return None


def keyword_label(text: str, keywords: Sequence[Tuple[re.Pattern, Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    for rx, lab in keywords:
        if rx.search(text):
            return dict(lab)
    return None


LLM_SYSTEM = ("You label security alerts with MITRE ATT&CK. For each alert name give the single best technique id "
              "(T1234 or T1234.001) and its tactic shortname. Use null for the technique when the name does not "
              "say what happened. Answer only with JSON.")


def _llm_key(names: Sequence[str]) -> str:
    blob = json.dumps({"v": PROMPT_VERSION, "names": sorted(set(names))}, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def llm_prompt(names: Sequence[str]) -> List[Dict[str, str]]:
    body = {"alert_names": list(names), "tactics": [t["shortname"] for t in attack.all_tactics()],
            "answer_format": {"labels": {"<alert name exactly as given>": {"technique": "T1234 | T1234.001 | null",
                                                                          "tactic": "<tactic shortname>"}}}}
    return [{"role": "system", "content": LLM_SYSTEM}, {"role": "user", "content": json.dumps(body, ensure_ascii=False)}]


def _parse_json(content: str) -> Dict[str, Any]:
    try:
        doc = json.loads(content)
    except ValueError:
        s, e = content.find("{"), content.rfind("}")
        try:
            doc = json.loads(content[s:e + 1]) if s >= 0 and e > s else {}
        except ValueError:
            doc = {}
    return doc if isinstance(doc, dict) else {}


def llm_labels(names: Sequence[str], client: Any, cache_dir: Path = CACHE_DIR
               ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """({name: label}, info). One call for all names (up to MAX_LLM_NAMES); answers are checked against
    the catalogue and an invalid one is left out. Cached on the sorted name set. Never raises."""
    info: Dict[str, Any] = {"names": len(names), "calls": 0, "cached": False, "rejected": [], "notes": []}
    names = list(dict.fromkeys(names))[:MAX_LLM_NAMES]
    if not names:
        return {}, info
    cache = Path(cache_dir) / f"{_llm_key(names)}.json"
    raw = None
    if cache.exists():
        try:
            raw = json.loads(cache.read_text(encoding="utf-8"))
            info["cached"] = True
        except ValueError:
            raw = None
    if raw is None:
        if client is None:
            return {}, info
        try:
            res = client.chat(llm_prompt(names), max_tokens=min(4000, 200 + 40 * len(names)), json_mode=True)
            info["calls"] = 1
            info["endpoint"] = getattr(res, "endpoint", None)
            raw = _parse_json(res.content)
        except Exception as e:      # LLMError, network, bad JSON: the alerts stay unknown
            info["notes"].append(f"LLM call failed: {type(e).__name__}: {str(e)[:200]}")
            return {}, info
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(raw, indent=1, ensure_ascii=False), encoding="utf-8")
    out: Dict[str, Dict[str, Any]] = {}
    wanted = set(names)
    for name, ans in (raw.get("labels") or {}).items():
        if name not in wanted or not isinstance(ans, dict):
            continue
        tid, tac = ans.get("technique"), tactic_of(ans.get("tactic"))
        try:
            if tid:
                t = attack.technique(str(tid))
                out[name] = attack.label(t.id, tac if tac in t.tactics else _earliest(t.tactics))
            elif tac:
                out[name] = attack.unknown_label(tac)
        except attack.AttackError as e:
            info["rejected"].append(f"{name}: {e}")
    return out, info


# ── grouping and alerts ──────────────────────────────────────────────────────

def read_records(con: duckdb.DuckDBPyConnection) -> Tuple[pl.DataFrame, int]:
    """(vendor_alert rows with a usable time, count of those without)."""
    have = {r[0] for r in con.execute("DESCRIBE SELECT * FROM events").fetchall()}
    sel = ", ".join(c if c in have else f"NULL AS {c}" for c in COLS)
    df = con.sql(f"SELECT {sel} FROM events WHERE category = 'vendor_alert' AND ts_valid "
                 f"ORDER BY ts_utc, source, line").pl()
    bad = con.execute("SELECT count(*) FROM events WHERE category = 'vendor_alert' AND NOT ts_valid").fetchone()[0]
    return df, int(bad)


def count_records(con: duckdb.DuckDBPyConnection) -> int:
    return int(con.execute("SELECT count(*) FROM events WHERE category = 'vendor_alert'").fetchone()[0])


def group_records(rows: List[Dict[str, Any]], gap_s: int) -> List[List[Dict[str, Any]]]:
    """Groups of records: same (product, alert name, main entity), consecutive records < gap_s apart.
    rows carry `_name`, `_ent` (resolve_entities) and ts_utc."""
    by_key: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        by_key.setdefault((slug(r.get("product") or "vendor"), r["_name"].strip().lower(), main_entity(r["_ent"])),
                          []).append(r)
    groups = []
    for key in sorted(by_key):
        cur: List[Dict[str, Any]] = []
        for r in sorted(by_key[key], key=lambda x: (x["ts_utc"], x["line"])):
            if cur and (r["ts_utc"] - cur[-1]["ts_utc"]).total_seconds() > gap_s:
                groups.append(cur)
                cur = []
            cur.append(r)
        if cur:
            groups.append(cur)
    return groups


def _mode(vals: Iterable[Optional[str]]) -> Optional[str]:
    counts: Dict[str, int] = {}
    for v in vals:
        if v:
            counts[v] = counts.get(v, 0) + 1
    return min(counts, key=lambda v: (-counts[v], v)) if counts else None


def _minutes(a: datetime, b: datetime) -> str:
    m = (b - a).total_seconds() / 60
    return f"{m:.0f}" if m >= 10 else (f"{m:.1f}".rstrip("0").rstrip(".") or "0")


def action_text(product: str, name: str, e: Dict[str, Optional[str]], n: int, t0: datetime, t1: datetime) -> str:
    where = []
    if e.get("host"):
        where.append(f"on {e['host']}")
    if e.get("user"):
        where.append(f"for user {e['user']}")
    if e.get("src_ip"):
        where.append(f"from {e['src_ip']}")
    if e.get("dst_ip") and not e.get("host"):
        where.append(f"against {e['dst_ip']}")
    text = f"{product} raised \"{name}\"" + (" " + " ".join(where) if where else "")
    if n > 1:
        text += f", {n:,} times in {_minutes(t0, t1)} minutes"
    return text


def build_alerts(df: pl.DataFrame, settings: Dict[str, Any], client: Any = None, cache_dir: Path = CACHE_DIR,
                 llm_reason: Optional[str] = None, get_client: Optional[Callable[[], Tuple[Any, Optional[str]]]] = None
                 ) -> Tuple[pl.DataFrame, pl.DataFrame, Dict[str, Any]]:
    """Alerts (engine.ALERT_COLS + technique_source) and evidence from vendor_alert rows (read_records).
    client: an LLMClient-like object (chat(messages, max_tokens, json_mode) -> .content); get_client is
    asked for (client, reason-skipped) only when some alert names are still unlabelled."""
    from .engine import EVIDENCE_SCHEMA, _empty_alerts

    rows = df.to_dicts()
    for r in rows:
        r["_name"] = str(r.get("alert_name") or r.get("attack") or r.get("virus") or r.get("log_desc")
                         or r.get("msg") or "Vendor alert").strip()[:200]
        r["_ent"] = resolve_entities(r)
    groups = group_records(rows, settings["group_gap"])

    # labels: vendor fields per group, then keywords per name, then one LLM call, then unknown
    labels: List[Optional[Tuple[Dict[str, Any], List[str], str]]] = []
    for g in groups:
        v = vendor_label([r.get("mitre_technique") for r in g if r.get("mitre_technique")],
                         [t for r in g for t in split_list(r.get("mitre_tactic"))])
        if v:
            labels.append((v[0], v[1], "vendor"))
            continue
        r0 = g[0]
        text = " ".join(str(x) for x in (r0["_name"], r0.get("attack"), r0.get("virus"), r0.get("msg")) if x)
        k = keyword_label(text, settings["keywords"])
        labels.append((k, [], "keyword") if k else None)
    left = sorted({g[0]["_name"] for g, lab in zip(groups, labels) if lab is None})
    llm_info: Dict[str, Any] = {"names": len(left), "calls": 0, "skipped": llm_reason or "no LLM client"}
    got: Dict[str, Dict[str, Any]] = {}
    if left and client is None and get_client is not None:
        client, llm_reason = get_client()
        llm_info["skipped"] = llm_reason
    if left and client is not None:
        got, llm_info = llm_labels(left, client, cache_dir)
        llm_info["skipped"] = None
    elif not left:
        llm_info["skipped"] = "every alert labelled without it"
    for i, g in enumerate(groups):
        if labels[i] is None:
            name = g[0]["_name"]
            labels[i] = (got[name], [], "llm") if name in got else (attack.unknown_label(None), [], "unknown")

    out, ev = [], []
    for g, (lab, alts, source) in zip(groups, labels):
        r0 = g[0]
        product = str(r0.get("product") or "vendor")
        name = r0["_name"]
        rid = f"vendor:{slug(product, 40)}:{slug(name)}"
        ents = {k: _mode(r["_ent"].get(k) for r in g) for k in ("src_ip", "dst_ip", "host", "user", "domain", "url")}
        t0, t1 = g[0]["ts_utc"], max(r["ts_utc"] for r in g)
        sevs = [int(r["vendor_severity"]) for r in g if r.get("vendor_severity") is not None]
        sev = min(5, max(1, max(sevs) if sevs else settings["default_severity"]))
        confs = [float(r["alert_confidence"]) for r in g if r.get("alert_confidence") is not None]
        conf = min(1.0, max(0.0, max(confs) if confs else settings["default_confidence"]))
        blocked = sum(_blocked(r) for r in g)
        n = len(g)
        key = main_entity(r0["_ent"])
        aid = hashlib.md5(f"{rid}|{key}|{t0:%Y-%m-%dT%H:%M:%S.%f}".encode("utf-8")).hexdigest()[:16]
        text = action_text(product, name, ents, n, t0, t1)
        out.append({
            "alert_id": aid, "rule_id": rid, "layer": "vendor", "title": name, **lab, "alt_techniques": alts,
            "severity": sev, "confidence": round(conf, 4), "ts_start": t0, "ts_end": t1, **ents,
            "event_count": n, "blocked_share": round(blocked / n, 4), "success": blocked < n, "summary": text,
            "action_text": text, "incident_number": None, "promote": sev >= settings["promote_severity"],
            "kind": "vendor", "group_key": json.dumps({"product": product, "alert_name": name, "entity": key},
                                                      ensure_ascii=False),
            "src_count": len({r["_ent"]["src_ip"] for r in g if r["_ent"]["src_ip"]}),
            "dst_count": len({r["_ent"]["dst_ip"] for r in g if r["_ent"]["dst_ip"]}),
            "distinct_count": None, "passed": n - blocked, "status": "stable", "technique_source": source,
        })
        ev += [{"alert_id": aid, "source": r["source"], "line": int(r["line"]), "byte_offset": int(r["byte_offset"] or 0),
                "ts": r["ts"], "technique": lab["technique"], "role": "trigger"} for r in g]
    stats = {"records": len(rows), "alerts": len(out), "llm": llm_info,
             "technique_sources": {s: sum(1 for a in out if a["technique_source"] == s)
                                   for s in ("vendor", "keyword", "llm", "unknown")}}
    if not out:
        return _empty_alerts(), pl.DataFrame(schema=EVIDENCE_SCHEMA), stats
    alerts = pl.DataFrame(out, schema_overrides={"alt_techniques": pl.List(pl.Utf8), "incident_number": pl.Int64,
                                                 "distinct_count": pl.Int64, "ts_start": pl.Datetime("us"),
                                                 "ts_end": pl.Datetime("us"), "src_ip": pl.Utf8, "dst_ip": pl.Utf8,
                                                 "host": pl.Utf8, "user": pl.Utf8, "domain": pl.Utf8, "url": pl.Utf8,
                                                 "technique_name": pl.Utf8},
                          infer_schema_length=None).sort("ts_start", "rule_id")
    evidence = pl.DataFrame(ev, schema=EVIDENCE_SCHEMA)
    return alerts, evidence, stats


def run_vendor(con: duckdb.DuckDBPyConnection, no_llm: bool = False, client: Any = None,
               settings: Optional[Dict[str, Any]] = None, cache_dir: Path = CACHE_DIR
               ) -> Tuple[pl.DataFrame, pl.DataFrame, Dict[str, Any]]:
    """The vendor step over a run's events: (alerts, evidence, stats). Empty when no vendor_alert rows."""
    from .engine import EVIDENCE_SCHEMA, _empty_alerts

    t0 = time.perf_counter()
    if count_records(con) == 0:
        return _empty_alerts(), pl.DataFrame(schema=EVIDENCE_SCHEMA), {"records": 0, "alerts": 0}
    settings = settings or load_settings()
    df, bad_ts = read_records(con)

    def get_client() -> Tuple[Any, Optional[str]]:
        from ..schema.llm_map import client_or_reason
        return client_or_reason(no_llm)

    alerts, evidence, stats = build_alerts(df, settings, client, cache_dir, None, get_client)
    stats.update(records_without_time=bad_ts, secs=round(time.perf_counter() - t0, 3))
    return alerts, evidence, stats
