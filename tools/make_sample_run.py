"""Build examples/sample-run/ from real parsed data: chain A (32.127.48.11).

Track B builds the API and UI against this sample until track A's pipeline
produces real runs. Every value comes from the parsed log, so line numbers,
byte offsets and times are real; the risk score, report and threat-intel
values are placeholders in the shape of contract C.

usage: python tools/make_sample_run.py [PARSED_DIR] [OUT_DIR]
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from killchain.contracts import validate_bundle  # noqa: E402

PARSED = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "parsed" / "firex-10G"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "examples" / "sample-run"
ATTACKER, PORTAL = "32.127.48.11", "10.10.20.20"
IST = timedelta(hours=5, minutes=30)
SAMPLE_LINES = 20

# (rule_id, title, filter, technique, alt, tactic, stage_no, kill_chain_stage, severity, action template)
STEPS = [
    ("fw-recon-port-sweep", "Port sweep of the portal",
     (pl.col("log_type") == "traffic") & (pl.col("action") == "deny"),
     "T1595.002", ["T1046", "T1595"], "reconnaissance", 1, "Reconnaissance", 3,
     "{src} probed {ports} ports on {dst}; every attempt was denied."),
    ("fw-web-sqli", "SQL injection against the portal",
     pl.col("log_subtype") == "ips",
     "T1190", ["T1595.002"], "initial-access", 3, "Delivery", 4,
     "{src} sent {n} SQL injection attempts to {dst}; {passed} were not blocked."),
    ("fw-web-shell", "Web shell requests",
     pl.col("log_subtype") == "webfilter",
     "T1505.003", ["T1071.001"], "persistence", 5, "Installation", 4,
     "{src} made {n} requests to upload paths on {dst} that no other source uses."),
    ("fw-exfil-volume", "Large transfer over the web shell",
     (pl.col("log_type") == "traffic") & (pl.col("action") == "accept"),
     "T1048.002", ["T1048", "T1041"], "exfiltration", 13, "Actions on Objectives", 5,
     "{n} HTTPS sessions between {src} and {dst} moved {mb} MB."),
]


def ist(ts) -> str:
    return (ts + IST).strftime("%Y-%m-%d %H:%M:%S")


def utc(ts) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def stable_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def main() -> None:
    lf = pl.scan_parquet(str(PARSED / "firewall" / "*.parquet")).filter(
        (pl.col("ts_quality") == "ok") & (pl.col("src_ip") == ATTACKER) & (pl.col("dst_ip") == PORTAL))
    rows = lf.select("ts", "line", "byte_offset", "source", "log_type", "log_subtype", "action", "dst_port",
                     "attack", "url", "sent_bytes", "rcvd_bytes").collect()
    if rows.height == 0:
        sys.exit(f"no rows for {ATTACKER} in {PARSED}; run the parser first")

    alerts, steps, evidence = [], [], []
    for i, (rule_id, title, flt, tech, alt, tactic, stage, kc, sev, text) in enumerate(STEPS, start=1):
        part = rows.filter(flt).sort("ts")
        n = part.height
        passed = part.filter(~pl.col("action").is_in(["deny", "dropped", "blocked"])).height
        mb = round(float((part["sent_bytes"].fill_null(0) + part["rcvd_bytes"].fill_null(0)).sum()) / 1e6, 1)
        first, last = part["ts"].min(), part["ts"].max()
        alert_id = stable_id(rule_id, ATTACKER, utc(first))
        action = text.format(src=ATTACKER, dst=PORTAL, n=n, ports=part["dst_port"].n_unique(), passed=passed, mb=mb)
        sample = [{"line": r["line"], "byte_offset": r["byte_offset"], "source": r["source"], "ts": utc(r["ts"])}
                  for r in part.head(SAMPLE_LINES).iter_rows(named=True)]
        alerts.append({
            "alert_id": alert_id, "rule_id": rule_id, "layer": "rule", "title": title,
            "technique": tech, "alt_techniques": alt, "technique_name": None, "tactic": tactic,
            "stage_no": stage, "kill_chain_stage": kc, "severity": sev, "confidence": 0.9,
            "ts_start": utc(first), "ts_end": utc(last), "src_ip": ATTACKER, "dst_ip": PORTAL,
            "host": None, "user": None, "domain": "portal.corp.local" if i > 1 else None,
            "url": part["url"].drop_nulls().head(1).to_list()[0] if part["url"].drop_nulls().len() else None,
            "event_count": n, "blocked_share": round(1 - passed / n, 4) if n else 0.0, "success": passed > 0,
            "summary": action, "action_text": action, "incident_number": 1,
        })
        steps.append({
            "n": i, "ts_start": utc(first), "ts_end": utc(last), "ts_start_ist": ist(first), "ts_end_ist": ist(last),
            "ongoing": False, "action": action, "rule_id": rule_id, "alert_id": alert_id, "technique": tech,
            "technique_name": None, "tactic": tactic, "stage_no": stage, "kill_chain_stage": kc,
            "src": ATTACKER, "dst": PORTAL, "event_count": n, "success": passed > 0,
            "line_sample": sample, "line_total": n, "enrichment_flags": [], "confidence": 0.9, "layer": "rule",
        })
        evidence += [{"alert_id": alert_id, **s, "technique": tech, "role": "window"} for s in sample]

    # Names from the ATT&CK catalogue, so the sample matches what the pipeline will write.
    cat = json.loads((ROOT / "killchain" / "attack" / "data" / "attack_catalogue.json").read_text(encoding="utf-8"))
    names = {t["id"]: t["name"] for t in cat["techniques"]}
    for a in alerts:
        a["technique_name"] = names.get(a["technique"])
    for s in steps:
        s["technique_name"] = names.get(s["technique"])

    total_events = sum(s["event_count"] for s in steps)
    incident_id = stable_id(*sorted(a["alert_id"] for a in alerts))
    chain_text = " → ".join(f"{s['n']}. {s['tactic'].replace('-', ' ').title()}" for s in steps)
    # (value 0-1, weight) per part; the formula is in docs/build-plan.md P10.
    raw = {"severity": (1.0, 0.25), "stage": (13 / 14, 0.20), "breadth": (4 / 6, 0.10), "success": (1.0, 0.15),
           "asset": (0.75, 0.15), "reach": (0.0, 0.10), "threat_intel": (0.0, 0.05)}
    risk_parts = {k: {"value": round(v, 4), "weight": w, "points": round(100 * v * w, 1)} for k, (v, w) in raw.items()}
    risk = round(sum(p["points"] for p in risk_parts.values()), 1)
    incident = {
        "incident_number": 1, "incident_id": incident_id,
        "title": f"Web attack chain from {ATTACKER} against the portal",
        "risk_score": risk, "risk_band": "critical" if risk >= 75 else "high" if risk >= 50 else "medium",
        "risk_parts": risk_parts, "severity": max(a["severity"] for a in alerts),
        "ts_start": steps[0]["ts_start"], "ts_end": steps[-1]["ts_end"],
        "ts_start_ist": steps[0]["ts_start_ist"], "ts_end_ist": steps[-1]["ts_end_ist"],
        "merged": {"alerts": len(alerts), "events": total_events},
        "entities": {"ips": [ATTACKER, PORTAL], "hosts": [PORTAL], "users": [], "domains": ["portal.corp.local"]},
        "tactics": [s["tactic"] for s in steps], "techniques": [s["technique"] for s in steps],
        "chain_text": chain_text, "chain": steps,
        "gaps": ["No execution, credential-access or lateral-movement evidence in the firewall log; "
                 "those stages would be in the Windows log, which was not provided."],
        "graph": {
            "nodes": [
                {"id": ATTACKER, "label": ATTACKER, "kind": "external_ip", "zone": "internet", "importance": 0.25},
                {"id": PORTAL, "label": "portal (10.10.20.20)", "kind": "server", "zone": "dmz", "importance": 0.75},
                {"id": "10.10.20.31", "label": "10.10.20.31", "kind": "server", "zone": "server",
                 "importance": 0.75, "reach": "inferred"},
            ],
            "edges": [{"source": ATTACKER, "target": PORTAL, "step": s["n"], "technique": s["technique"],
                       "tactic": s["tactic"], "label": f"{s['n']}. {s['rule_id'].split('-', 1)[1].replace('-', ' ')} x{s['event_count']}",
                       "kind": "step"} for s in steps]
            + [{"source": PORTAL, "target": "10.10.20.31", "step": None, "technique": None, "tactic": None,
                "label": "same server subnet (inferred)", "kind": "reach_inferred"}],
        },
        "enrichment": {
            ATTACKER: {"kind": "ip", "zone": "internet", "verdict": "no-reports", "reputation": 0.0,
                       "providers": [{"provider": "local", "available": True, "malicious": False, "score": None,
                                      "tags": ["external", "seen only in this incident"],
                                      "detail": {"country": None, "first_seen": steps[0]["ts_start"]}}],
                       "placeholder": True},
        },
        "next": {
            "reachable": [{"host": "10.10.20.31", "zone": "server", "hop": 1, "kind": "inferred",
                           "via": [{"from": PORTAL, "edge": "zone_neighbour", "count": 0, "lines": []}]}],
            "sentence": "No internal connections from the portal were observed; servers in the same subnet "
                        "(e.g. 10.10.20.31) are the likely next targets (inferred).",
            "likely_tactics": ["execution", "credential-access", "lateral-movement"],
        },
        "report": {
            "source": "template",
            "markdown": "\n".join(
                [f"**Summary.** {ATTACKER} scanned, exploited and then used a web shell on the portal, "
                 f"and moved data over it ({total_events:,} events across {len(steps)} steps).", "", "**Chain**"]
                + [f"{s['n']}. {s['ts_start_ist']} IST: {s['action']} ({s['technique']}, {s['tactic']})" for s in steps]
                + ["", "**Placeholder:** generated by tools/make_sample_run.py for UI development."]),
            "triage": {"verdict": "looks_real", "confidence": 0.9, "reasons": ["placeholder"]},
        },
        "report_source": "template",
        "layers": ["rule"],
        "sample": True,
    }
    index = {"run": "sample-run", "generated_by": "tools/make_sample_run.py",
             "incidents": [{k: incident[k] for k in ("incident_number", "incident_id", "title", "risk_score",
                                                    "risk_band", "severity", "ts_start", "ts_end", "ts_start_ist",
                                                    "ts_end_ist", "merged", "tactics", "techniques")}
                           | {"triage_verdict": "looks_real", "ti_verdict": "no-reports", "sample": True}]}
    run_summary = {"run": "sample-run", "sample": True, "source": "firex-10G.log", "stages": {},
                   "counts": {"alerts": len(alerts), "incidents": 1, "evidence_lines": total_events},
                   "note": "Hand-made sample in contract C for UI development; not a pipeline run."}

    errors = validate_bundle(incident, index, alerts)
    if errors:
        sys.exit("sample does not match the contracts:\n  " + "\n  ".join(errors))

    (OUT / "incidents").mkdir(parents=True, exist_ok=True)
    dump = lambda p, o: (OUT / p).write_text(json.dumps(o, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    dump("incidents/1.json", incident)
    dump("index.json", index)
    dump("alerts.json", alerts)
    dump("evidence_sample.json", evidence)
    dump("run_summary.json", run_summary)
    print(f"wrote {OUT}: 1 incident, {len(alerts)} alerts, {len(evidence)} evidence lines; "
          f"steps: {[s['event_count'] for s in steps]}")


if __name__ == "__main__":
    main()
