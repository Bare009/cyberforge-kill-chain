"""Synthetic vendor-alert exports for testing the vendor layer (killchain/detect/vendor.py).

    python tools/make_vendor_samples.py [--out data/tmp/vendor]

Writes three exports, each with planted attacks over shared hosts, IPs and users plus unrelated noise
alerts, and for each a truth file <name>.truth.json {record id: attack name or "noise"}:

  sentinel_securityalert.json  Microsoft Sentinel SecurityAlert rows (JSON array; Entities and Techniques
                               are JSON strings, as Log Analytics exports them)
  sentinelone_threats.json     SentinelOne /threats API page ({"data": [...]})
  wazuh_alerts.ndjson          Wazuh alerts.json lines

Some alerts carry no MITRE field (keyword path) and some have names no keyword knows (LLM / unknown).
Deterministic: same output every run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 28, 1, 0, 0, tzinfo=timezone.utc)


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


# ── Microsoft Sentinel SecurityAlert ─────────────────────────────────────────

HOSTS = {"WS-FIN-012": "10.10.1.12", "WS-HR-013": "10.10.2.13", "SRV-DC-01": "10.10.0.10",
         "SRV-FILE-01": "10.10.0.20", "WS-SALES-011": "10.10.4.11", "WS-ENG-014": "10.10.3.14",
         "WS-ENG-011": "10.10.3.11", "SRV-WEB-01": "10.10.0.30", "WS-ENG-013": "10.10.3.13",
         "WS-SALES-014": "10.10.4.14", "WS-FIN-015": "10.10.1.15"}


def _ents(ips=(), hosts=(), accounts=()) -> str:
    out: List[Dict[str, Any]] = []
    n = 1
    for ip in ips:
        out.append({"$id": str(n), "Type": "ip", "Address": ip})
        n += 1
    for h in hosts:
        out.append({"$id": str(n), "Type": "host", "HostName": h, "NTDomain": "CORP", "OSFamily": "Windows",
                    "Address": HOSTS.get(h)})
        n += 1
    for a in accounts:
        out.append({"$id": str(n), "Type": "account", "Name": a, "NTDomain": "CORP", "UPNSuffix": "corp.example"})
        n += 1
    return json.dumps(out, separators=(",", ":"))


def sentinel() -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    rows: List[Dict[str, Any]] = []
    truth: Dict[str, str] = {}

    def add(attack: str, minutes: float, name: str, sev: str, tactics: str, techniques: Optional[List[str]],
            ips=(), hosts=(), accounts=(), compromised: str = "", provider: str = "ASI Scheduled Alerts",
            product: str = "Azure Sentinel", desc: str = "") -> None:
        aid = f"{len(rows) + 1:08x}-5e17-4a1e-9c00-{len(rows) + 1:012x}"
        rows.append({
            "TenantId": "b3c4d5e6-0000-4000-8000-000000000001", "TimeGenerated": iso(T0 + timedelta(minutes=minutes)),
            "DisplayName": name, "AlertName": name, "AlertSeverity": sev, "Description": desc or name,
            "ProviderName": provider, "VendorName": "Microsoft", "ProductName": product, "Status": "New",
            "ConfidenceLevel": "", "ConfidenceScore": None, "SystemAlertId": aid, "AlertType": name.replace(" ", ""),
            "CompromisedEntity": compromised, "Tactics": tactics,
            "Techniques": json.dumps(techniques) if techniques is not None else "", "Entities": _ents(ips, hosts, accounts),
            "StartTime": iso(T0 + timedelta(minutes=minutes)), "EndTime": iso(T0 + timedelta(minutes=minutes + 1)),
        })
        truth[aid] = attack

    # attack A: password spray from a Tor exit -> RDP to WS-FIN-012 -> PowerShell -> LSASS dump ->
    # remote service on the DC from WS-FIN-012 -> security log cleared on the DC
    tor = "185.220.101.45"
    for k in range(4):                                         # repeats within 1 h -> one alert
        add("A", 10 * k, "Password spray attack against multiple accounts", "Medium", "CredentialAccess", ["T1110.003"],
            ips=[tor], accounts=["j.smith"])
    add("A", 55, "Successful RDP sign-in from a Tor exit node", "High", "InitialAccess,LateralMovement", ["T1078", "T1021.001"],
        ips=[tor], hosts=["WS-FIN-012"], accounts=["j.smith"], compromised="WS-FIN-012")
    for k in range(2):
        add("A", 80 + 5 * k, "Suspicious PowerShell command line", "Medium", "Execution", ["T1059.001"],
            hosts=["WS-FIN-012"], accounts=["j.smith"], compromised="WS-FIN-012", provider="MDATP",
            product="Microsoft Defender Advanced Threat Protection")
    add("A", 100, "Credential dumping activity observed from LSASS memory", "High", "", None,       # no MITRE: keyword
        hosts=["WS-FIN-012"], accounts=["j.smith"], compromised="WS-FIN-012", provider="MDATP",
        product="Microsoft Defender Advanced Threat Protection")
    add("A", 140, "Suspicious remote service installation on a domain controller", "High", "LateralMovement", [],   # tactic only
        ips=["10.10.1.12"], hosts=["SRV-DC-01"], accounts=["j.smith"], compromised="SRV-DC-01")
    add("A", 160, "Security event log was cleared", "Medium", "", None,                              # keyword
        ips=["10.10.1.12"], hosts=["SRV-DC-01"], accounts=["j.smith"], compromised="SRV-DC-01")

    # attack B (day 2): phishing -> Office spawns PowerShell -> Cobalt Strike C2 -> unknown heuristic ->
    # files encrypted and shadow copies deleted on the file server, over SMB from WS-HR-013
    day2 = 24 * 60 + 8 * 60
    c2 = "45.155.205.99"
    add("B", day2, "Email messages containing malicious attachment delivered", "Medium", "InitialAccess", ["T1566.001"],
        ips=[c2], accounts=["m.khan"], provider="OATP", product="Office 365 Advanced Threat Protection")
    add("B", day2 + 12, "Office application spawned PowerShell", "High", "Execution", ["T1204.002", "T1059.001"],
        hosts=["WS-HR-013"], accounts=["m.khan"], compromised="WS-HR-013", provider="MDATP",
        product="Microsoft Defender Advanced Threat Protection")
    add("B", day2 + 20, "Zorblax heuristic 7781 triggered", "Low", "", None,                         # no keyword: LLM / unknown
        hosts=["WS-HR-013"], accounts=["m.khan"], compromised="WS-HR-013", provider="MDATP",
        product="Microsoft Defender Advanced Threat Protection")
    add("B", day2 + 30, "Connection to known Cobalt Strike infrastructure", "High", "CommandAndControl", ["T1071.001"],
        ips=[c2], hosts=["WS-HR-013"], accounts=["m.khan"], compromised="WS-HR-013", provider="MDATP",
        product="Microsoft Defender Advanced Threat Protection")
    for k in range(3):
        add("B", day2 + 110 + 4 * k, "Ransomware behavior: mass file encryption", "High", "Impact", ["T1486"],
            ips=["10.10.2.13"], hosts=["SRV-FILE-01"], accounts=["m.khan"], compromised="SRV-FILE-01")
    add("B", day2 + 116, "Volume shadow copies deleted", "High", "", None,                          # keyword
        ips=["10.10.2.13"], hosts=["SRV-FILE-01"], accounts=["m.khan"], compromised="SRV-FILE-01")

    # noise: lone sign-in oddities, quarantined malware, many DC alerts from different clients (a hub),
    # analytics without MITRE
    rnd = random.Random(7)
    users = ["a.rao", "p.iyer", "s.das", "k.nair", "r.menon", "t.paul", "v.bose", "n.sen"]
    for k in range(8):
        add("noise", 30 + 330 * k + rnd.randint(0, 60), "Unfamiliar sign-in properties", "Low", "InitialAccess", ["T1078"],
            ips=[f"{rnd.choice([20, 52, 104, 142])}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}"],
            accounts=[users[k]], provider="IPC", product="Azure Active Directory Identity Protection")
    for k in range(6):
        client = f"10.10.{rnd.randint(1, 4)}.{20 + k}"
        add("noise", 200 + 260 * k, "Multiple Kerberos pre-authentication failures", "Low", "CredentialAccess", ["T1110"],
            ips=[client], hosts=["SRV-DC-01"], accounts=[users[k]], compromised="SRV-DC-01")
    add("noise", 900, "Malware detected and quarantined", "Medium", "Execution", ["T1204.002"],
        hosts=["WS-ENG-014"], accounts=["k.nair"], compromised="WS-ENG-014", provider="MDATP",
        product="Microsoft Defender Advanced Threat Protection", desc="Trojan:Win32/Wacatac.B!ml quarantined")
    add("noise", 2000, "Custom analytic 42: rare process tree", "Informational", "", None,
        hosts=["WS-SALES-011"], accounts=["t.paul"], compromised="WS-SALES-011")
    add("noise", 2600, "Mailbox forwarding rule to an external domain", "Medium", "Collection", ["T1114.003"],
        accounts=["r.menon"], provider="OATP", product="Office 365 Advanced Threat Protection")
    add("noise", 3100, "Anomalous token used", "Medium", "", None, ips=["52.14.77.9"], accounts=["v.bose"],
        provider="IPC", product="Azure Active Directory Identity Protection")
    rows.sort(key=lambda r: r["TimeGenerated"])
    return rows, truth


# ── SentinelOne threats ──────────────────────────────────────────────────────

def sentinelone() -> Tuple[Dict[str, Any], Dict[str, str]]:
    data: List[Dict[str, Any]] = []
    truth: Dict[str, str] = {}

    def add(attack: str, minutes: float, name: str, conf: str, mitig: str, host: str, user: str,
            indicators: Optional[List[Tuple[str, str, str]]] = None, classification: str = "Malware",
            path: str = "", proc: str = "", external_ip: Optional[str] = None) -> None:
        tid = str(1834000000000000000 + len(data) * 7919)
        ind = [{"category": tac, "description": desc, "ids": [len(data) * 3 + i],
                "tactics": [{"name": tac, "source": "MITRE", "techniques": [{"name": tech,
                             "link": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"}]}]}
               for i, (tac, tech, desc) in enumerate(indicators or [])]
        data.append({
            "id": tid,
            "threatInfo": {"threatId": tid, "threatName": name, "confidenceLevel": conf, "mitigationStatus": mitig,
                           "classification": classification, "createdAt": iso(T0 + timedelta(minutes=minutes)),
                           "identifiedAt": iso(T0 + timedelta(minutes=minutes)), "filePath": path,
                           "sha256": hashlib.sha256(name.encode()).hexdigest(), "originatorProcess": proc,
                           "processUser": f"CORP\\{user}", "analystVerdict": "undefined",
                           "incidentStatus": "unresolved", "engines": ["SentinelOne Cloud"]},
            "agentRealtimeInfo": {"agentComputerName": host, "agentOsName": "Windows 11 Enterprise",
                                  "agentDomain": "CORP", "agentVersion": "23.4.2.14"},
            "agentDetectionInfo": {"agentIpV4": HOSTS.get(host, "10.10.9.9"), "agentLastLoggedInUserName": user,
                                   "externalIp": external_ip},
            "indicators": ind,
        })
        truth[tid] = attack

    # attack C on WS-ENG-011 (pmehta): macro document -> encoded PowerShell stager -> run key ->
    # Mimikatz -> beacon; C2 address 91.92.109.14 shared with the beacon
    c2 = "91.92.109.14"
    add("C", 0, "Invoice_Oct.docm", "malicious", "not_mitigated", "WS-ENG-011", "pmehta",
        [("Initial Access", "T1566.001", "Macro-enabled document opened from e-mail")], "Malware",
        r"C:\Users\pmehta\Downloads\Invoice_Oct.docm", "winword.exe")
    for k in range(3):
        add("C", 4 + 3 * k, "PowerShell.Empire.Stager", "malicious", "not_mitigated", "WS-ENG-011", "pmehta",
            [("Execution", "T1059.001", "Encoded PowerShell launched by Office")], "Trojan",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "winword.exe", c2)
    add("C", 20, "Autorun persistence via registry", "suspicious", "not_mitigated", "WS-ENG-011", "pmehta",
        [("Persistence", "T1547.001", "Run key written by PowerShell")], "Malware", "", "powershell.exe")
    add("C", 41, "Mimikatz credential theft", "malicious", "mitigated", "WS-ENG-011", "pmehta",
        [], "Infostealer", r"C:\Users\Public\m64.exe", "powershell.exe")                     # no indicators: keyword
    add("C", 55, "Beacon to rare external host", "suspicious", "not_mitigated", "WS-ENG-011", "pmehta",
        [("Command and Control", "T1071.001", "Periodic HTTPS callbacks")], "Malware", "", "rundll32.exe", c2)

    # attack D on SRV-WEB-01 (svc_web), day 2: web shell -> reverse shell -> cryptominer, all on the web server
    d2 = 24 * 60 + 6 * 60
    add("D", d2, "Webshell.ASPX.ChinaChopper", "malicious", "not_mitigated", "SRV-WEB-01", "svc_web",
        [("Persistence", "T1505.003", "Web shell written to the web root")], "Backdoor",
        r"C:\inetpub\wwwroot\aspnet_client\x.aspx", "w3wp.exe")
    add("D", d2 + 15, "Reverse shell from IIS worker", "malicious", "not_mitigated", "SRV-WEB-01", "svc_web",
        [], "Malware", "", "w3wp.exe")                                                     # keyword: reverse shell
    for k in range(4):
        add("D", d2 + 40 + 10 * k, "Generic.CoinMiner.XMRig", "malicious", "mitigated", "SRV-WEB-01", "svc_web",
            [], "PUA", r"C:\Windows\Temp\xmrig.exe", "cmd.exe")                              # keyword: crypto miner

    # attack E on WS-ENG-013 (dnair), day 3: injection -> shadow copies deleted -> LockBit encryption ->
    # an odd behavioural name no keyword knows
    d3 = 3 * 24 * 60 + 2 * 60
    add("E", d3, "Process injection into explorer.exe", "malicious", "not_mitigated", "WS-ENG-013", "dnair",
        [("Defense Evasion", "T1055", "Remote thread created in explorer.exe")], "Malware", "", "rundll32.exe")
    add("E", d3 + 6, "SuspiciousActivity.ScriptBlock.88", "suspicious", "not_mitigated", "WS-ENG-013", "dnair",
        [], "Malware", "", "powershell.exe")                                                # no keyword: LLM / unknown
    add("E", d3 + 9, "Shadow copy deletion via vssadmin", "malicious", "mitigated", "WS-ENG-013", "dnair",
        [], "Ransomware", r"C:\Windows\System32\vssadmin.exe", "cmd.exe")                   # keyword
    for k in range(3):
        add("E", d3 + 12 + 2 * k, "Ransomware.LockBit3", "malicious", "mitigated", "WS-ENG-013", "dnair",
            [("Impact", "T1486", "Mass file encryption")], "Ransomware", r"C:\Users\dnair\AppData\Local\Temp\lb3.exe",
            "explorer.exe")

    # noise: adware and PUA on random hosts, one quarantined trojan, an unknown heuristic, and a late,
    # unrelated PUA on WS-ENG-011 five days later (must not join attack C)
    rnd = random.Random(11)
    for k, h in enumerate(["WS-FIN-012", "WS-HR-013", "WS-SALES-011", "WS-ENG-014", "WS-HR-013", "WS-FIN-012"]):
        add("noise", 300 + 420 * k + rnd.randint(0, 90), "PUA.Adware.BrowserHelper", "suspicious", "mitigated", h,
            rnd.choice(["rkumar", "asharma", "sgupta", "kiyer"]), [], "PUA",
            rf"C:\Users\Public\bh{k}.exe", "explorer.exe")
    add("noise", 2500, "Trojan.Agent.Qakbot", "malicious", "mitigated", "WS-SALES-011", "sgupta",
        [("Execution", "T1204.002", "User opened a malicious file")], "Trojan", r"C:\Users\sgupta\Downloads\scan.js",
        "wscript.exe")
    add("noise", 3000, "Heur.Behavior.Q19", "suspicious", "mitigated", "WS-ENG-014", "kiyer", [], "Malware")
    for k, h in enumerate(["WS-SALES-014", "WS-FIN-015", "WS-SALES-014", "WS-FIN-015"]):
        add("noise", 700 + 900 * k, "Generic.Malware.Suspicious", "suspicious", "mitigated", h,
            rnd.choice(["vreddy", "jdsouza"]), [("Execution", "T1204.002", "User ran a downloaded file")], "Malware",
            rf"C:\Users\Public\dl{k}.exe", "explorer.exe")
    add("noise", 5 * 24 * 60, "PUA.Toolbar.Generic", "suspicious", "mitigated", "WS-ENG-011", "pmehta", [], "PUA")
    data.sort(key=lambda r: r["threatInfo"]["createdAt"])
    return {"data": data, "pagination": {"totalItems": len(data), "nextCursor": None}}, truth


# ── Wazuh alerts ─────────────────────────────────────────────────────────────

AGENTS = {"web-01": ("003", "10.10.0.31"), "web-02": ("004", "10.10.0.32"), "db-01": ("005", "10.10.0.40"),
          "ws-ops-01": ("006", "10.10.5.21"), "ws-ops-02": ("007", "10.10.5.22")}


def wazuh() -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    rows: List[Dict[str, Any]] = []
    truth: Dict[str, str] = {}

    def add(attack: str, minutes: float, rule_id: str, level: int, desc: str, agent: str,
            mitre: Optional[Tuple[List[str], List[str]]] = None, srcip: Optional[str] = None,
            user: Optional[str] = None, groups: Tuple[str, ...] = ("syslog",), full_log: str = "",
            url: Optional[str] = None) -> None:
        t = T0 + timedelta(minutes=minutes)
        aid = f"{int(t.timestamp())}.{1000 + len(rows)}"
        rule: Dict[str, Any] = {"level": level, "description": desc, "id": rule_id, "firedtimes": 1,
                                "mail": level >= 12, "groups": list(groups)}
        if mitre:
            rule["mitre"] = {"id": mitre[0], "tactic": mitre[1], "technique": [""] * len(mitre[0])}
        a_id, a_ip = AGENTS[agent]
        rec: Dict[str, Any] = {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}+0000",
                               "rule": rule, "agent": {"id": a_id, "name": agent, "ip": a_ip},
                               "manager": {"name": "wazuh-manager"}, "id": aid, "decoder": {"name": groups[0]},
                               "full_log": full_log or desc, "location": "/var/log/auth.log"}
        data: Dict[str, Any] = {}
        if srcip:
            data["srcip"] = srcip
        if user:
            data["dstuser"] = user
        if url:
            data["url"] = url
        if data:
            rec["data"] = data
        rows.append(rec)
        truth[aid] = attack

    # attack F on web-01 from 203.0.113.50: SSH brute force -> login -> new user -> crontab changed ->
    # outbound connection from web-01 to the same address
    att = "203.0.113.50"
    for k in range(6):
        add("F", 2 * k, "5763", 10, "sshd: brute force trying to get access to the system. Authentication failed.",
            "web-01", (["T1110"], ["Credential Access"]), att, "root", ("syslog", "sshd", "authentication_failures"))
    add("F", 14, "5715", 3, "sshd: authentication success.", "web-01", (["T1078"], ["Defense Evasion", "Initial Access"]),
        att, "deploy", ("syslog", "sshd", "authentication_success"))
    add("F", 25, "5902", 8, "New user added to the system.", "web-01", (["T1136"], ["Persistence"]), None, "backup2",
        ("syslog", "adduser"))
    add("F", 31, "550", 7, "Integrity checksum changed.", "web-01", None, None, "root", ("ossec", "syscheck"),
        "File '/etc/crontab' modified")                                                           # no MITRE
    add("F", 40, "100201", 12, "Outbound connection to suspicious host from web server", "web-01", None, att, None,
        ("custom", "network"))                                                                    # keyword: no match -> LLM/unknown

    # attack G on web-02 from 198.51.100.7 (day 2): SQL injection burst -> web shell request -> privilege
    # escalation via sudo
    g = "198.51.100.7"
    d2 = 24 * 60 + 13 * 60
    for k in range(5):
        add("G", d2 + k, "31164", 6, "SQL injection attempt.", "web-02", (["T1190"], ["Initial Access"]), g, None,
            ("web", "accesslog", "attack"), url=f"/item.php?id=1%27%20OR%201=1--{k}")
    add("G", d2 + 9, "31110", 12, "PHP web shell access detected", "web-02", None, g, None, ("web", "attack"),
        url="/uploads/cmd.php?c=id")                                                              # keyword: web shell
    add("G", d2 + 21, "5402", 3, "Successful sudo to ROOT executed.", "web-02",
        (["T1548.003"], ["Privilege Escalation", "Defense Evasion"]), None, "www-data", ("syslog", "sudo"))
    add("G", d2 + 22, "100305", 10, "Kernel module loaded by unprivileged user", "web-02", None, None, "www-data",
        ("custom", "audit"))                                                                      # unknown

    # noise: SCA checks, PAM sessions, Windows logon failures from internal clients, rootcheck
    rnd = random.Random(5)
    for k in range(8):
        ag = rnd.choice(list(AGENTS))
        add("noise", 100 + 330 * k, "19007", 7, "CIS Benchmark: Ensure SSH root login is disabled: Status changed from passed to failed",
            ag, None, None, None, ("sca",))
    for k in range(7):
        add("noise", 60 + 400 * k + rnd.randint(0, 50), "5501", 3, "PAM: Login session opened.",
            rnd.choice(["db-01", "ws-ops-01", "ws-ops-02"]), (["T1078"], ["Initial Access"]), None,
            rnd.choice(["ops", "dba", "monitor"]), ("pam", "syslog", "authentication_success"))
    for k in range(5):
        add("noise", 700 + 500 * k, "60122", 5, "Logon Failure - Unknown user or bad password", "ws-ops-01",
            (["T1078"], ["Initial Access"]), f"10.10.5.{30 + k}", rnd.choice(["ops", "jdoe", "asmith"]),
            ("windows", "authentication_failed"))
    add("noise", 2900, "510", 7, "Host-based anomaly detection event (rootcheck).", "db-01", None, None, None,
        ("ossec", "rootcheck"))
    rows.sort(key=lambda r: r["timestamp"])
    return rows, truth


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "data" / "tmp" / "vendor"))
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    s_rows, s_truth = sentinel()
    (out / "sentinel_securityalert.json").write_text(json.dumps(s_rows, indent=2), encoding="utf-8")
    (out / "sentinel_securityalert.truth.json").write_text(json.dumps(s_truth, indent=1), encoding="utf-8")
    s1, s1_truth = sentinelone()
    (out / "sentinelone_threats.json").write_text(json.dumps(s1, indent=2), encoding="utf-8")
    (out / "sentinelone_threats.truth.json").write_text(json.dumps(s1_truth, indent=1), encoding="utf-8")
    w_rows, w_truth = wazuh()
    (out / "wazuh_alerts.ndjson").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in w_rows),
                                             encoding="utf-8")
    (out / "wazuh_alerts.truth.json").write_text(json.dumps(w_truth, indent=1), encoding="utf-8")
    for name, t in (("sentinel", s_truth), ("sentinelone", s1_truth), ("wazuh", w_truth)):
        by: Dict[str, int] = {}
        for v in t.values():
            by[v] = by.get(v, 0) + 1
        print(f"{name:12s} {len(t):3d} records  " + ", ".join(f"{k} {n}" for k, n in sorted(by.items())))
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
