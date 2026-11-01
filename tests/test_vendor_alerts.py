"""Vendor alerts (killchain/detect/vendor.py): grouping, MITRE validation, keywords, the LLM step, entities,
the contract, and vendor alerts as promoted, numbered chain steps."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import polars as pl
import pytest

from killchain import db, schema
from killchain.contracts import TRUSTED_LAYERS, validate_alert
from killchain.correlate import engine as corr
from killchain.correlate.entities import load_settings as corr_settings
from killchain.detect import engine, vendor
from killchain.detect.cli import main as detect_main
from killchain.graph import chain as ch

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures" / "vendor"
T0 = datetime(2026, 10, 28, 1, 0, 0)
SET = vendor.load_settings()


def rec(minutes: float, name: str, line: int, **kw):
    """One vendor_alert row as read_records returns it."""
    r = {c: None for c in vendor.COLS}
    t = T0 + timedelta(minutes=minutes)
    r.update(source="x.json", line=line, byte_offset=line * 100, ts=t.replace(tzinfo=timezone.utc), ts_utc=t,
             product="Acme EDR", alert_name=name)
    r.update(kw)
    return r


def frame(rows):
    return pl.DataFrame(rows, schema_overrides={"ts_utc": pl.Datetime("us"), "ts": pl.Datetime("us", "UTC"),
                                                "vendor_severity": pl.Int64, "alert_confidence": pl.Float64,
                                                "line": pl.Int64, "byte_offset": pl.Int64},
                        infer_schema_length=None)


def build(rows, **kw):
    return vendor.build_alerts(frame(rows), SET, **kw)


# ── settings and labels ──────────────────────────────────────────────────────

def test_keyword_table_loads_and_covers_the_common_names():
    s = vendor.load_settings()
    assert s["group_gap"] == 3600 and s["default_confidence"] == 0.7 and s["promote_severity"] == 4
    want = {"Password spray against Azure AD": "T1110.003", "Brute force attack on RDP": "T1110",
            "Impossible travel activity": "T1078", "Phishing email delivered": "T1566",
            "Malicious macro in a document": "T1566.001", "Ransomware behaviour detected": "T1486",
            "Encoded PowerShell command": "T1059.001", "Suspicious script execution": "T1059",
            "Mimikatz detected": "T1003.001", "Kerberoasting attempt": "T1558.003", "Pass-the-hash": "T1550.002",
            "PsExec lateral movement": "T1021.002", "WMI remote execution": "T1047",
            "RDP session from the internet": "T1021.001", "Scheduled task created": "T1053.005",
            "Service installed": "T1543.003", "Registry run key added": "T1547.001",
            "Privilege escalation via UAC bypass": "T1548", "Security event log cleared": "T1070.001",
            "Defender antivirus disabled": "T1562.001", "Port scan detected": "T1046",
            "Cobalt Strike beacon": "T1071", "DNS tunnelling detected": "T1071.004",
            "Data exfiltration to cloud storage": "T1048", "Trojan:Win32/Emotet": "T1204.002",
            "Web shell detected": "T1505.003", "SQL injection attempt": "T1190", "XSS attempt": "T1189",
            "Exploit attempt CVE-2021-44228": "T1190", "DDoS attack": "T1498"}
    got = {n: (vendor.keyword_label(n, s["keywords"]) or {}).get("technique") for n in want}
    assert got == want
    assert vendor.keyword_label("Something odd happened", s["keywords"]) is None


@pytest.mark.parametrize("raw,tac,expect", [
    (["T1059.001"], ["Execution"], ("T1059.001", "execution", [])),
    (['["T9999", "T1190"]'], ["InitialAccess"], ("T1190", "initial-access", [])),          # first valid one
    (["T1110.003, T1110"], [], ("T1110.003", "credential-access", ["T1110"])),             # rest -> alternates
    (["T1059.999"], [], ("T1059", "execution", [])),                                       # unknown sub -> parent
    (["T1078"], ["InitialAccess", "Persistence"], ("T1078", "initial-access", [])),        # vendor tactic chosen
    (["T1078"], ["Collection"], ("T1078", "initial-access", [])),                          # not its tactic -> earliest
    ([], ["LateralMovement"], ("unknown", "lateral-movement", [])),                        # tactic only
    (["not a technique"], ["TA0006"], ("unknown", "credential-access", [])),
])
def test_mitre_validation(raw, tac, expect):
    lab, alts = vendor.vendor_label(raw, tac)
    assert (lab["technique"], lab["tactic"], alts) == expect
    assert lab["stage_no"] == vendor.attack.stage_no(expect[1])


def test_no_mitre_at_all():
    assert vendor.vendor_label([], []) is None and vendor.vendor_label(["T9999"], ["nonsense"]) is None


def test_tactic_spellings():
    assert [vendor.tactic_of(x) for x in ("InitialAccess", "Command and Control", "TA0006", "privilege_escalation",
                                          "Defense Evasion", "", "Nope")] == \
        ["initial-access", "command-and-control", "credential-access", "privilege-escalation", "defense-evasion",
         None, None]


# ── grouping ─────────────────────────────────────────────────────────────────

def test_grouping_one_alert_per_name_entity_and_gap():
    rows = [rec(0, "Encoded PowerShell", 1, host="WS-1", mitre_technique="T1059.001", vendor_severity=3),
            rec(20, "Encoded PowerShell", 2, host="WS-1", mitre_technique="T1059.001", vendor_severity=4),
            rec(70, "Encoded PowerShell", 3, host="WS-1", mitre_technique="T1059.001"),     # 50 min after line 2
            rec(200, "Encoded PowerShell", 4, host="WS-1", mitre_technique="T1059.001"),    # gap > 1 h: new alert
            rec(5, "Encoded PowerShell", 5, host="WS-2", mitre_technique="T1059.001"),      # other host
            rec(6, "Mimikatz", 6, host="WS-1")]                                             # other name
    a, ev, st = build(rows)
    assert a.height == 4 and st["records"] == 6
    ws1 = a.filter((pl.col("host") == "WS-1") & (pl.col("title") == "Encoded PowerShell")).sort("ts_start")
    assert ws1["event_count"].to_list() == [3, 1] and ws1["severity"].to_list() == [4, 3]
    first = ws1.row(0, named=True)
    assert sorted(ev.filter(pl.col("alert_id") == first["alert_id"])["line"].to_list()) == [1, 2, 3]
    assert first["rule_id"] == "vendor:acme-edr:encoded-powershell" and first["layer"] == "vendor"
    assert first["kind"] == "vendor" and first["promote"] is True and first["confidence"] == 0.7
    assert "3 times in 70 minutes" in first["action_text"] and 'Acme EDR raised "Encoded PowerShell" on WS-1' in first["action_text"]
    assert ev.height == 6 and set(ev["role"].to_list()) == {"trigger"}


def test_main_entity_falls_back_to_user_then_ip():
    rows = [rec(0, "Impossible travel", 1, user="Bob", src_ip="8.8.8.8"),
            rec(10, "Impossible travel", 2, user="bob", src_ip="1.1.1.1"),       # same user, any case
            rec(15, "Impossible travel", 3, src_ip="9.9.9.9")]
    a, _, _ = build(rows)
    assert sorted(a["event_count"].to_list()) == [1, 2]


def test_severity_confidence_and_blocked_share():
    rows = [rec(0, "Trojan found", 1, host="h", vendor_severity=2, alert_confidence=0.9, action="blocked"),
            rec(1, "Trojan found", 2, host="h", vendor_severity=5, action="detected")]
    a = build(rows)[0].row(0, named=True)
    assert (a["severity"], a["confidence"], a["blocked_share"], a["success"], a["passed"]) == (5, 0.9, 0.5, True, 1)
    b = build([rec(0, "Trojan found", 1, host="h")])[0].row(0, named=True)
    assert (b["severity"], b["confidence"], b["promote"]) == (3, 0.7, False)


# ── technique sources ────────────────────────────────────────────────────────

def test_technique_sources_vendor_keyword_unknown():
    rows = [rec(0, "Bad PowerShell", 1, host="h", mitre_technique="T1059.001", mitre_tactic="Execution"),
            rec(1, "Lateral thing", 2, host="h", mitre_tactic="LateralMovement"),
            rec(2, "Mimikatz credential theft", 3, host="h"),
            rec(3, "Zorblax heuristic 7781", 4, host="h")]
    a, _, st = build(rows)
    got = {r["title"]: (r["technique"], r["tactic"], r["technique_source"]) for r in a.iter_rows(named=True)}
    assert got == {"Bad PowerShell": ("T1059.001", "execution", "vendor"),
                   "Lateral thing": ("unknown", "lateral-movement", "vendor"),
                   "Mimikatz credential theft": ("T1003.001", "credential-access", "keyword"),
                   "Zorblax heuristic 7781": ("unknown", "discovery", "unknown")}
    assert st["technique_sources"] == {"vendor": 2, "keyword": 1, "llm": 0, "unknown": 1}
    assert st["llm"]["skipped"] == "no LLM client"


def test_keyword_reads_the_message_too():
    a = build([rec(0, "Alert 4711", 1, host="h", msg="vssadmin delete shadows /all was run")])[0]
    assert (a["technique"][0], a["technique_source"][0]) == ("T1490", "keyword")


class FakeLLM:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def chat(self, messages, max_tokens=700, json_mode=True):
        self.calls.append(json.loads(messages[1]["content"]))
        return SimpleNamespace(content=json.dumps(self.answer), endpoint="fake:model")


def test_llm_labels_all_left_over_names_in_one_call(tmp_path):
    rows = [rec(0, "Zorblax heuristic 7781", 1, host="h1"), rec(1, "Quux behaviour 12", 2, host="h1"),
            rec(2, "Zorblax heuristic 7781", 3, host="h2"), rec(3, "Mimikatz credential theft", 4, host="h1"),
            rec(4, "Blorp 9", 5, host="h3")]
    fake = FakeLLM({"labels": {"Zorblax heuristic 7781": {"technique": "T1053.005", "tactic": "persistence"},
                               "Quux behaviour 12": {"technique": "T9999", "tactic": "execution"},     # invalid
                               "Blorp 9": {"technique": None, "tactic": "Exfiltration"},              # tactic only
                               "Not asked": {"technique": "T1190"}}})
    a, _, st = build(rows, client=fake, cache_dir=tmp_path)
    assert len(fake.calls) == 1
    assert sorted(fake.calls[0]["alert_names"]) == ["Blorp 9", "Quux behaviour 12", "Zorblax heuristic 7781"]
    got = {(r["title"], r["host"]): (r["technique"], r["tactic"], r["technique_source"]) for r in a.iter_rows(named=True)}
    assert got[("Zorblax heuristic 7781", "h1")] == ("T1053.005", "persistence", "llm")
    assert got[("Zorblax heuristic 7781", "h2")] == ("T1053.005", "persistence", "llm")
    assert got[("Quux behaviour 12", "h1")] == ("unknown", "discovery", "unknown")
    assert got[("Blorp 9", "h3")] == ("unknown", "exfiltration", "llm")
    assert got[("Mimikatz credential theft", "h1")][2] == "keyword"
    assert st["llm"]["calls"] == 1 and st["llm"]["rejected"]
    # the answer is cached on the name set: the same names never call the model again
    again = FakeLLM({})
    a2, _, st2 = build(rows, client=again, cache_dir=tmp_path)
    assert again.calls == [] and st2["llm"]["cached"] is True
    assert a2.sort("alert_id")["technique"].to_list() == a.sort("alert_id")["technique"].to_list()


def test_llm_failure_and_no_client_leave_unknown(tmp_path):
    class Broken:
        def chat(self, *a, **k):
            raise RuntimeError("down")

    a, _, st = build([rec(0, "Zorblax", 1, host="h")], client=Broken(), cache_dir=tmp_path)
    assert a["technique_source"][0] == "unknown" and "LLM call failed" in st["llm"]["notes"][0]
    a, _, st = build([rec(0, "Zorblax", 1, host="h")], get_client=lambda: (None, "--no-llm"))
    assert a["technique_source"][0] == "unknown" and st["llm"]["skipped"] == "--no-llm"


def test_get_client_only_asked_when_names_are_left():
    asked = []
    build([rec(0, "Mimikatz", 1, host="h")], get_client=lambda: asked.append(1) or (None, "x"))
    assert asked == []


# ── entities ─────────────────────────────────────────────────────────────────

def test_entities_from_a_sentinel_json_string():
    ents = json.dumps([{"$id": "1", "Type": "ip", "Address": "185.220.101.45"},
                       {"$id": "2", "Type": "host", "HostName": "WS-FIN-012", "Address": "10.10.1.12"},
                       {"$id": "3", "Type": "account", "Name": "j.smith"},
                       {"$id": "4", "Type": "file", "Name": "evil.exe"}])
    e = vendor.resolve_entities({"extra": json.dumps({"Entities": ents})})
    assert e == {"src_ip": "185.220.101.45", "dst_ip": "10.10.1.12", "host": "WS-FIN-012", "user": "j.smith",
                 "domain": None, "url": None}


def test_entities_from_the_flattened_form_and_columns_win():
    extra = json.dumps({"Entities.Type": "ip,account,file", "Entities.Address": "10.10.1.12,8.8.8.8",
                        "Entities.Name": "svc_web,payload.exe"})
    e = vendor.resolve_entities({"extra": extra})
    assert (e["src_ip"], e["dst_ip"], e["user"]) == ("8.8.8.8", "10.10.1.12", "svc_web")
    e = vendor.resolve_entities({"extra": extra, "user": "alice", "src_ip": "1.2.3.4", "host": "h"})
    assert (e["src_ip"], e["user"], e["host"]) == ("1.2.3.4", "alice", "h")


def test_host_ip_is_the_source_when_nothing_else_is():
    e = vendor.resolve_entities({"host": "WS-ENG-011", "host_ip": "10.10.3.11"})
    assert (e["src_ip"], e["dst_ip"]) == ("10.10.3.11", None)
    e = vendor.resolve_entities({"host": "web-01", "host_ip": "10.10.0.31", "src_ip": "203.0.113.50"})
    assert (e["src_ip"], e["dst_ip"]) == ("203.0.113.50", "10.10.0.31")


# ── contract ─────────────────────────────────────────────────────────────────

def test_contract_accepts_vendor_layer():
    a, _, _ = build([rec(0, "Encoded PowerShell", 1, host="h", mitre_technique="T1059.001")])
    js = engine.alerts_json(a)[0]
    assert validate_alert(js) == [] and js["layer"] == "vendor" and js["technique_source"] == "vendor"
    assert "vendor" in TRUSTED_LAYERS and "anomaly" not in TRUSTED_LAYERS
    assert validate_alert({**js, "layer": "bogus"}) != []


# ── exports end to end ───────────────────────────────────────────────────────

def _run(tmp_path, name):
    _, mapping, rep = schema.prepare(FX / name, tmp_path / "run", no_llm=True, schemas_dir=tmp_path / "schemas",
                                     llm_cache=tmp_path / "llm")
    schema.parse(FX / name, tmp_path / "parsed", mapping, quiet=True)
    con = db.open_run(tmp_path / "parsed")
    return con, rep


def test_sentinel_export(tmp_path):
    con, rep = _run(tmp_path, "sentinel_alerts.json")
    assert con.execute("SELECT count(*) FILTER (WHERE category = 'vendor_alert'), count(*) FROM events").fetchone() == (8, 8)
    a, ev, st = vendor.run_vendor(con, no_llm=True)
    assert st["records"] == 8 and a.height == 7          # the two spray records within 1 h are one alert
    by = {r["title"]: r for r in a.sort("ts_start").iter_rows(named=True)}
    spray = a.filter(pl.col("title").str.starts_with("Password spray")).sort("ts_start")
    assert spray["event_count"].to_list() == [2, 1]      # the third spray is 3.7 h later
    rdp = by["Successful RDP sign-in from a Tor exit node"]
    assert (rdp["technique"], rdp["tactic"], rdp["alt_techniques"]) == ("T1078", "initial-access", ["T1021.001"])
    assert (rdp["src_ip"], rdp["dst_ip"], rdp["host"], rdp["user"], rdp["severity"]) == \
        ("185.220.101.45", "10.10.1.12", "WS-FIN-012", "j.smith", 4)
    dump = by["Credential dumping activity observed from LSASS memory"]
    assert (dump["technique"], dump["technique_source"]) == ("T1003.001", "keyword")
    svc = by["Suspicious remote service installation on a domain controller"]
    assert (svc["technique"], svc["tactic"], svc["src_ip"], svc["dst_ip"]) == \
        ("unknown", "lateral-movement", "10.10.1.12", "10.10.0.10")
    assert by["Zorblax heuristic 7781 triggered"]["technique_source"] == "unknown"
    odd = by["Unfamiliar sign-in properties"]                   # Entities as a real list -> flattened form
    assert (odd["src_ip"], odd["user"], odd["severity"]) == ("52.1.2.3", "a.rao", 2)
    assert rdp["rule_id"] == "vendor:asi-scheduled-alerts:successful-rdp-sign-in-from-a-tor-exit-node"
    assert all(validate_alert(x) == [] for x in engine.alerts_json(a))


def test_sentinelone_export(tmp_path):
    con, _ = _run(tmp_path, "sentinelone_threats.json")
    a, _, _ = vendor.run_vendor(con, no_llm=True)
    got = {r["title"]: r for r in a.iter_rows(named=True)}
    emp = got["PowerShell.Empire.Stager"]
    assert (emp["technique"], emp["technique_source"], emp["confidence"], emp["host"], emp["src_ip"]) == \
        ("T1059.001", "vendor", 0.9, "WS-ENG-011", "10.10.3.11")
    assert emp["rule_id"].startswith("vendor:sentinelone:")          # product from the field signature
    mim = got["Mimikatz credential theft"]
    assert (mim["technique"], mim["technique_source"], mim["success"]) == ("T1003.001", "keyword", False)  # mitigated
    assert got["Heur.Behavior.Q19"]["confidence"] == 0.6


def test_wazuh_export(tmp_path):
    con, _ = _run(tmp_path, "wazuh_alerts.ndjson")
    a, _, _ = vendor.run_vendor(con, no_llm=True)
    got = {r["title"]: r for r in a.iter_rows(named=True)}
    bf = got["sshd: brute force trying to get access to the system. Authentication failed."]
    assert (bf["event_count"], bf["technique"], bf["severity"], bf["src_ip"], bf["dst_ip"], bf["host"]) == \
        (2, "T1110", 4, "203.0.113.50", "10.10.0.31", "web-01")
    assert got["sshd: authentication success."]["tactic"] == "initial-access"
    assert (got["PHP web shell access detected"]["technique"], got["PHP web shell access detected"]["technique_source"]) == \
        ("T1505.003", "keyword")
    assert got["Integrity checksum changed."]["technique_source"] == "unknown"
    assert all(r.startswith("vendor:wazuh:") for r in a["rule_id"])


def test_firewall_run_has_no_vendor_step(tmp_path):
    from killchain.schema.canonical import SCHEMA
    import pyarrow as pa
    import pyarrow.parquet as pq

    (tmp_path / "p" / "firewall").mkdir(parents=True)
    t = pa.Table.from_pylist([{"ts": datetime(2026, 1, 1, tzinfo=timezone.utc), "ts_quality": "ok", "source": "f",
                               "line": 1, "byte_offset": 0, "src_ip": "1.1.1.1"}], schema=SCHEMA)
    pq.write_table(t, tmp_path / "p" / "firewall" / "part-0.parquet")
    a, ev, st = vendor.run_vendor(db.open_run(tmp_path / "p"), no_llm=True)
    assert a.height == 0 and ev.height == 0 and st == {"records": 0, "alerts": 0}


def test_detect_cli_writes_vendor_alerts(tmp_path, capsys):
    _run(tmp_path, "sentinel_alerts.json")
    run = tmp_path / "out"
    assert detect_main(["--run", str(run), "--parsed", str(tmp_path / "parsed"), "--no-llm"]) == 0
    out = capsys.readouterr().out
    assert "vendor layer 7 alerts from 8 vendor alert records" in out and "LLM skipped: --no-llm" in out
    js = json.loads((run / "alerts.json").read_text(encoding="utf-8"))
    assert len(js) == 7 and {a["layer"] for a in js} == {"vendor"}
    st = json.loads((run / "detect" / "_stats.json").read_text(encoding="utf-8"))
    assert st["layers"]["vendor"] == 7 and st["vendor"]["technique_sources"]["keyword"] == 1
    assert pl.read_parquet(run / "alert_evidence.parquet").height == 8


# ── correlation and chains ───────────────────────────────────────────────────

NET = db.load_network()
CS = corr_settings()


def _incidents(alerts, evidence=None):
    ev = evidence if evidence is not None else pl.DataFrame(schema=engine.EVIDENCE_SCHEMA)
    return corr.correlate(alerts, ev, NET, CS)


def test_vendor_alerts_link_promote_and_number_in_chains(tmp_path):
    con, _ = _run(tmp_path, "sentinel_alerts.json")
    a, ev, _ = vendor.run_vendor(con, no_llm=True)
    res = _incidents(a, ev)
    inc = res["incidents"].sort("ts_start")
    assert res["stats"]["vendor_alerts"] == 7
    # spray(x2) -> RDP -> LSASS dump -> DC service -> heuristic -> spray: one attack; the lone sign-in is below the bar
    assert inc.height == 1 and inc["merged"][0]["alerts"] == 6 and "vendor" in inc["layers"][0]
    mem = res["incident_alerts"]
    ids = mem["alert_id"].to_list()
    steps = ch.build_steps([r for r in a.iter_rows(named=True) if r["alert_id"] in ids], ev, NET)
    assert [s["n"] for s in steps] == list(range(1, 7)) and {s["layer"] for s in steps} == {"vendor"}
    starts = [s["ts_start"] for s in steps]
    assert starts == sorted(starts)
    assert [s["technique"] for s in steps][:4] == ["T1110.003", "T1078", "T1003.001", "unknown"]


def test_single_severe_vendor_alert_is_an_incident_low_one_is_not():
    hi, _, _ = build([rec(0, "Ransomware behaviour", 1, host="WS-9", vendor_severity=5, mitre_technique="T1486")])
    lo, _, _ = build([rec(0, "Adware found", 1, host="WS-8", vendor_severity=2)])
    res = _incidents(pl.concat([hi, lo], how="diagonal_relaxed"))
    assert res["incidents"].height == 1 and res["incidents"]["promoted_by"][0] in ("single severe alert", "promote rule")
    assert res["stats"]["below_bar"] == 1


def test_anomaly_alert_supports_a_vendor_step():
    v, _, _ = build([rec(0, "Cobalt Strike beacon", 1, host="WS-7", src_ip="10.10.3.7", dst_ip="45.1.2.3",
                         vendor_severity=4, mitre_technique="T1071.001")])
    an = v.with_columns(pl.lit("x-anom").alias("alert_id"), pl.lit("A11-too-regular").alias("rule_id"),
                        pl.lit("anomaly").alias("layer"), pl.lit(2).cast(pl.Int64).alias("severity"),
                        pl.lit(False).alias("promote"))
    res = _incidents(pl.concat([v, an], how="diagonal_relaxed"))
    assert res["incidents"].height == 1 and res["stats"]["anomaly_joined"] == 1
    steps = ch.build_steps(list(pl.concat([v, an], how="diagonal_relaxed").iter_rows(named=True)), None, NET)
    assert len(steps) == 1 and steps[0]["layer"] == "vendor" and steps[0]["supporting"][0]["layer"] == "anomaly"


def test_hub_host_does_not_break_a_chain_linked_by_ip():
    """A domain controller in many unrelated alerts from many clients becomes a dynamic hub; the attack's
    DC steps still join through the attacker workstation's IP, and the DC noise stays out."""
    rows = [rec(0, "Credential dumping", 1, host="WS-A", host_ip="10.10.1.12", user="j", vendor_severity=4),
            rec(30, "Remote service on DC", 2, host="DC", host_ip="10.10.0.10", src_ip="10.10.1.12", user="j",
                vendor_severity=4, mitre_tactic="LateralMovement"),
            rec(50, "Log cleared", 3, host="DC", host_ip="10.10.0.10", src_ip="10.10.1.12", user="j",
                vendor_severity=3)]
    rows += [rec(100 + 200 * k, "Kerberos failures", 10 + k, host="DC", host_ip="10.10.0.10",
                 src_ip=f"10.10.2.{20 + k}", user=f"u{k}", vendor_severity=2, mitre_technique="T1110")
             for k in range(7)]
    a, _, _ = build(rows)
    res = _incidents(a)
    assert "DC" in res["stats"]["hubs"]
    inc = res["incidents"]
    assert inc.height == 1 and inc["merged"][0]["alerts"] == 3


def test_firex_style_layers_unchanged_without_vendor_alerts():
    """No vendor alerts: rule alerts are steps, anomaly alerts support them, as before."""
    v, _, _ = build([rec(0, "x", 1, host="h", vendor_severity=4, mitre_technique="T1486")])
    rule = v.with_columns(pl.lit("rule").alias("layer"), pl.lit("R99").alias("rule_id"))
    steps = ch.build_steps(list(rule.iter_rows(named=True)), None, NET)
    assert steps[0]["layer"] == "rule"
