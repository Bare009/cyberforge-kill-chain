"""killchain/schema: format detection, flattening, synonym mapping, validation, value maps, the LLM step
(mocked), rule coverage and generic parse round trips on the small fixtures in tests/fixtures/schema."""

from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from killchain.schema import canonical as C
from killchain.schema import formats as F
from killchain.schema import parse, prepare
from killchain.schema.convert import Mapper, records_getter
from killchain.schema.coverage import columns_in, rule_report, rule_requirements
from killchain.schema.mapping import (detect_time_format, load_synonyms, map_value, match_fields, severity_1_5,
                                      severity_scale)

FX = Path(__file__).parent / "fixtures" / "schema"
SYN = load_synonyms()


def _prep(tmp_path: Path, name: str, **kw):
    kw.setdefault("no_llm", True)
    return prepare(FX / name if isinstance(name, str) else name, tmp_path / "run", schemas_dir=tmp_path / "schemas",
                   llm_cache=tmp_path / "llmcache", **kw)


def _parsed(out: Path) -> pa.Table:
    return pq.ParquetDataset(sorted(str(p) for p in (out / "firewall").glob("part-*.parquet"))).read()


def _col(rep, name):
    return next(c for c in rep["columns"] if c["column"] == name)


# ── detection ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,fmt,extra", [
    ("fortigate.txt", "fortigate", {}),
    ("pan.csv", "csv", {"delimiter": ","}),
    ("windows.tsv", "csv", {"delimiter": "\t"}),
    ("ecs.ndjson", "ndjson", {}),
    ("sentinel.json", "json", {}),
    ("checkpoint_kv.txt", "kv", {}),
    ("cef.txt", "syslog", {"payload": "cef"}),
])
def test_detect_formats(name, fmt, extra):
    d = F.detect_file(FX / name)
    assert d.format == fmt
    for k, v in extra.items():
        assert getattr(d, k) == v


def test_detect_gzip(tmp_path):
    gz = tmp_path / "pan.csv.gz"
    with open(FX / "pan.csv", "rb") as f, gzip.open(gz, "wb") as g:
        g.write(f.read())
    d = F.detect_file(gz)
    assert (d.format, d.compressed) == ("csv", "gzip")


def test_detect_leef_and_json_wrapped(tmp_path):
    p = tmp_path / "leef.txt"
    p.write_text("".join(f"<13>Oct 29 01:51:2{i} qradar LEEF:1.0|IBM|QRadar|1.0|Logon|src=10.0.0.{i}\tdst=10.0.0.9\n"
                         for i in range(5)), encoding="utf-8")
    assert F.detect_file(p).label == "syslog/leef"
    w = tmp_path / "wrapped.json"
    w.write_text(json.dumps({"value": [{"a": 1}, {"a": 2}]}), encoding="utf-8")
    assert F.detect_file(w).format == "json"
    assert [r["a"] for r, *_ in F.iter_json_doc(w)] == [1, 2]


# ── flattening and sampling ──────────────────────────────────────────────────

def test_flatten_nested_and_lists_of_objects():
    rec = F.flatten({"source": {"ip": "1.2.3.4", "geo": {"country_name": "India"}}, "tags": ["a", "b"],
                     "Entities": [{"Type": "ip", "Address": "1.2.3.4"}, {"Type": "host", "Address": "10.0.0.1"},
                                  {"Type": "account", "Name": "bob"}], "empty": {}})
    assert rec["source.ip"] == "1.2.3.4" and rec["source.geo.country_name"] == "India"
    assert rec["tags"] == ["a", "b"]
    assert rec["Entities.Type"] == "ip,host,account"
    assert rec["Entities.Address"] == "1.2.3.4,10.0.0.1"
    assert rec["Entities.Name"] == "bob"
    assert "empty" not in rec


def test_sample_start_and_middle(tmp_path):
    big = tmp_path / "big.ndjson"
    line = (FX / "ecs.ndjson").read_bytes().splitlines(keepends=True)[0]
    with open(big, "wb") as f:
        for _ in range(6 * F.HEAD_BYTES // len(line)):
            f.write(line)
    d = F.detect_file(big)
    sample, rej = F.sample_records(big, d, 100, F.Decoder("ndjson"))
    offs = [o for _, _, o in sample]
    assert len(sample) == 200 and not rej
    assert offs[0] == 0 and offs[100] >= big.stat().st_size // 2
    with open(big, "rb") as f:          # the middle sample starts on a line boundary
        f.seek(offs[100] - 1)
        assert f.read(2) == b"\n{"
    first_mid_line = sample[100][1]
    assert first_mid_line == 1 + offs[100] // len(line)


# ── synonyms ─────────────────────────────────────────────────────────────────

def test_synonyms_ignore_case_and_separators():
    m = match_fields(["SOURCE_ADDRESS", "destination-port", "bytesSent", "Generate Time", "x.data.srcip"], "csv", SYN)
    assert m["src_ip"][0] == "SOURCE_ADDRESS"
    assert m["dst_port"] == ["destination-port"]
    assert m["sent_bytes"] == ["bytesSent"]
    assert m["ts"] == ["Generate Time"]
    assert "x.data.srcip" in m["src_ip"]            # last-parts match


def test_synonyms_products():
    win = match_fields(["EventID", "TargetUserName", "IpAddress", "LogonType", "WorkstationName", "Computer"], "csv", SYN)
    assert (win["event_id"], win["user"], win["src_ip"], win["logon_type"], win["src_host"], win["host"]) == \
        (["EventID"], ["TargetUserName"], ["IpAddress"], ["LogonType"], ["WorkstationName"], ["Computer"])
    sen = match_fields(["TimeGenerated", "AlertName", "AlertSeverity", "Tactics", "Techniques", "Entities", "Account"],
                       "json", SYN)
    assert sen["alert_name"] == ["AlertName"] and sen["vendor_severity"] == ["AlertSeverity"]
    assert sen["mitre_tactic"] == ["Tactics"] and sen["mitre_technique"] == ["Techniques"]
    assert sen["alert_entities"] == ["Entities"] and sen["user"] == ["Account"]
    sysmon = match_fields(["Image", "CommandLine", "ParentImage", "Hashes", "TargetFilename"], "json", SYN)
    assert sysmon["process_name"] == ["Image"] and sysmon["parent_process"] == ["ParentImage"]
    assert sysmon["file_hash"] == ["Hashes"] and sysmon["command_line"] == ["CommandLine"]


def test_synonyms_one_column_per_field_and_exact_entries():
    m = match_fields(["Device Name", "rule_name", "rule.name", "Entities.HostName", "Computer"], "csv", SYN)
    assert m["dev_name"] == ["Device Name"] and "Device Name" not in m.get("host", [])
    assert m["attack"] == ["rule.name"]                 # ECS signature; Check Point rule_name is not one
    assert m["host"][0] == "Computer"
    shared = match_fields(["event.dataset", "event.code"], "ndjson", SYN)
    assert shared["log_type"] == shared["log_subtype"] == ["event.dataset"]
    assert shared["log_id"] == shared["event_id"] == ["event.code"]


# ── values, time, severity ───────────────────────────────────────────────────

def test_value_maps_and_contextual_maps():
    recs = [
        {"Type": "TRAFFIC", "Threat/Content Type": "end", "Action": "allow", "IP Protocol": "tcp"},
        {"Type": "TRAFFIC", "Threat/Content Type": "deny", "Action": "drop", "IP Protocol": "udp"},
        {"Type": "URL", "Threat/Content Type": "url", "Action": "alert"},
        {"Type": "URL", "Threat/Content Type": "url", "Action": "block-url"},
        {"Type": "THREAT", "Threat/Content Type": "vulnerability", "Action": "reset-both"},
        {"Type": "THREAT", "Threat/Content Type": "virus", "Action": "alert", "Threat/Content Name": "JS/Nemucod"},
        {"Type": "SYSTEM", "Threat/Content Type": "auth", "Event ID": "auth-fail"},
        {"Type": "SYSTEM", "Threat/Content Type": "auth", "Event ID": "auth-success"},
    ]
    cols = match_fields(list({k for r in recs for k in r}), "csv", SYN)
    m = Mapper({"format": "csv", "columns": {c: {"fields": f} for c, f in cols.items()}})
    t = m.text_columns(records_getter(recs, m.needed_fields()), len(recs))
    assert t["log_type"].to_pylist() == ["traffic", "traffic", "utm", "utm", "utm", "utm", "event", "event"]
    assert t["log_subtype"].to_pylist()[:6] == ["forward", "forward", "webfilter", "webfilter", "ips", "virus"]
    assert t["action"].to_pylist() == ["accept", "deny", "passthrough", "blocked", "dropped", "detected", "login", "login"]
    assert t["proto"].to_pylist()[:2] == ["6", "17"]
    assert t["status"].to_pylist()[6:] == ["failed", "success"]
    assert t["log_desc"].to_pylist()[6:] == ["Admin login failed", "Admin login successful"]
    assert t["virus"].to_pylist()[5] == "JS/Nemucod"
    assert map_value("log_type", "firewall.ha", SYN.value_maps) == "event"
    assert map_value("log_subtype", "firewall.app_control", SYN.value_maps) == "app-ctrl"


def test_time_formats_and_severity():
    assert detect_time_format(["1793238683", "1793238684"])[0] == "epoch"
    assert detect_time_format(["1793238683449", "1793238684000"])[0] == "epoch"
    assert detect_time_format(["2026-10-29T01:51:23.5+05:30", "2026-10-29T01:51:24Z"])[:3:2] == ("iso", True)
    assert detect_time_format(["2026/10/29 01:51:23"])[0] == "%Y/%m/%d %H:%M:%S"
    assert detect_time_format(["not a time", "soon"])[0] is None
    assert severity_scale(["High", "low", "Medium"]) == "text"
    assert severity_scale(["3", "7", "10"]) == "0-10"
    assert severity_scale(["2", "12", "15"]) == "0-15"
    assert [severity_1_5(v, "0-10") for v in ("0", "5", "8", "10")] == [1, 3, 4, 5]
    assert severity_1_5("critical", "text") == 5


# ── validation ───────────────────────────────────────────────────────────────

def test_validation_drops_a_bad_map(tmp_path):
    _, mapping, rep = _prep(tmp_path, "bad_ips.csv")
    dropped = {(d["column"], d["field"]) for d in rep["validation"]["dropped"]}
    assert ("src_ip", "Source address") in dropped           # host names, not addresses
    assert ("dst_port", "Destination Port") in dropped       # 'eighty'
    assert "src_ip" not in mapping["columns"] and "dst_port" not in mapping["columns"]
    assert mapping["columns"]["dst_ip"]["fields"] == ["Destination address"]
    assert _col(rep, "src_ip")["method"] == "unmapped"
    assert "Source address" in rep["unmapped_fields"]       # kept in extra, not guessed


def test_windows_dash_is_null(tmp_path):
    _, mapping, rep = _prep(tmp_path, "windows.tsv")
    assert mapping["columns"]["src_ip"]["fields"] == ["IpAddress"]     # '-' is no value, not a bad address
    assert rep["categories"] == {"auth": 5}
    assert mapping["time"]["format"] == "iso"


# ── LLM (mocked) ─────────────────────────────────────────────────────────────

class FakeLLM:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def chat(self, messages, max_tokens=700, json_mode=True):
        self.calls.append(messages)
        content = self.answers.pop(0) if self.answers else "{}"

        class R:
            pass
        r = R()
        r.content, r.endpoint = content, "fake:model"
        return r


def _odd_csv(tmp_path: Path) -> Path:
    p = tmp_path / "odd.csv"
    rows = ["when_utc,peer_a,peer_b,svc_port,verdict,blob"]
    for i in range(20):
        rows.append(f"2026-10-29T01:51:{i:02d}Z,32.127.48.{i},10.10.20.20,{443 if i % 2 else 80},"
                    f"{'permit-log' if i % 3 else 'stop'},x{i}")
    p.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return p


def test_llm_maps_leftovers_and_is_validated_and_cached(tmp_path):
    answer = json.dumps({
        "field_map": {"peer_a": "src_ip", "peer_b": "dst_ip", "svc_port": "dst_port", "verdict": "action",
                      "blob": "src_ip", "nope": "dst_ip"},
        "value_maps": {"action": {"permit-log": "accept", "stop": "deny", "x": "made-up"}},
        "category": "network", "ts_field": "when_utc", "ts_format": "iso"})
    llm = FakeLLM([answer])
    fmt, mapping, rep = prepare(_odd_csv(tmp_path), tmp_path / "run", schemas_dir=tmp_path / "schemas",
                                llm_cache=tmp_path / "llmcache", llm_client=llm)
    assert len(llm.calls) == 1
    prompt = json.loads(llm.calls[0][1]["content"])
    assert "src_ip" in prompt["columns"] and "peer_a" in prompt["unmatched_fields"]
    assert len(prompt["unmatched_fields"]["peer_a"]) == 5               # 3-5 sample values per field
    cols = mapping["columns"]
    assert cols["src_ip"] == {"fields": ["peer_a"], "method": "llm"}
    assert cols["dst_port"]["fields"] == ["svc_port"] and cols["ts"]["method"] == "llm"
    assert mapping["time"]["field"] == "when_utc"
    assert mapping["value_maps"]["action"] == {"permit-log": "accept", "stop": "deny"}
    dropped = {(d["column"], d["field"]) for d in rep["validation"]["dropped"]}
    assert ("src_ip", "blob") in dropped                                # 'x1' is not an address
    assert "blob" not in cols["src_ip"]["fields"]
    assert any("nope" in r for r in rep["llm"]["rejected"])             # not a field of the file
    assert any("made-up" in r for r in rep["llm"]["rejected"])          # not a canonical value
    assert rep["llm"]["used"] and rep["llm"]["calls"] == 1
    assert len(list((tmp_path / "llmcache").glob("*.json"))) == 1
    # Same field set again (new mapping forced): the cached answer is used, no call
    llm2 = FakeLLM([])
    _, mapping2, rep2 = prepare(_odd_csv(tmp_path), tmp_path / "run2", force=True, schemas_dir=tmp_path / "schemas",
                                llm_cache=tmp_path / "llmcache", llm_client=llm2)
    assert llm2.calls == [] and rep2["llm"]["cached"] and mapping2["columns"]["src_ip"]["method"] == "llm"
    # And the parse applies the LLM's value maps
    parse(_odd_csv(tmp_path), tmp_path / "parsed", mapping, quiet=True)
    t = _parsed(tmp_path / "parsed")
    assert set(t["action"].to_pylist()) == {"accept", "deny"}
    assert t["src_ip"][3].as_py() == "32.127.48.3"


def test_llm_skipped_without_key_or_with_no_llm(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "true")
    for k in ("LLM_PRIMARY_API_KEY", "LLM_FALLBACK_API_KEY"):
        monkeypatch.setenv(k, "")
    from killchain.schema.llm_map import client_or_reason

    assert client_or_reason(True) == (None, "--no-llm")
    client, reason = client_or_reason(False)
    assert client is None and "no LLM key" in reason
    _, mapping, rep = _prep(tmp_path, _odd_csv(tmp_path))
    assert rep["llm"] == {"used": False, "reason": "--no-llm", "added": []}
    assert "src_ip" not in mapping["columns"]


# ── rule coverage ────────────────────────────────────────────────────────────

def test_rule_requirements_from_yaml():
    reqs = {r["id"]: r for r in rule_requirements()}
    assert set(reqs["R01-admin-bruteforce"]["required"]) == {"log_desc", "src_ip", "ts"}
    assert "user" in reqs["R01-admin-bruteforce"]["optional"]
    assert {"log_subtype", "action", "src_ip", "dst_ip", "url"} <= set(reqs["R20-web-shell"]["required"])
    assert "log_id" in reqs["A01-rare-event"]["required"]
    # literals are not columns: 'Admin login failed' holds no identifiers, 'virus' in R04's literal is skipped
    assert columns_in("log_subtype = 'virus' AND action = 'detected'") == ["log_subtype", "action"]
    assert columns_in("ist_hour < 6 AND NOT src_internal") == ["ts", "src_ip"]


def test_rule_report_lists_missing_columns(tmp_path):
    rep = rule_report(rule_requirements(), {"ts", "src_ip", "dst_ip", "dst_port", "log_type"})
    can = {r["id"] for r in rep["can_run"]}
    skipped = {r["id"]: r["missing"] for r in rep["skipped"]}
    assert "R02-port-scan" in can
    assert skipped["R01-admin-bruteforce"] == ["log_desc"]
    _, _, pan = _prep(tmp_path, "pan.csv")
    assert {r["id"]: r["missing"] for r in pan["rules"]["skipped"]
            if not _host_rule(r["id"])} == {"A01-rare-event": ["log_id"]}
    fw = [r for r in rule_requirements() if not _host_rule(r["id"])]
    assert len([r for r in pan["rules"]["can_run"] if not _host_rule(r["id"])]) == len(fw) - 1
    # endpoint rules need process columns; auth rules with a `requires_any` group PAN has (status + user) can run
    assert "EP01-encoded-powershell" in {r["id"] for r in pan["rules"]["skipped"]}
    assert skipped["EP03-credential-dumping"] == ["command_line"]


def _host_rule(rule_id: str) -> bool:
    """rules/endpoint and rules/auth (stage 2): they read host columns firewall logs do not have."""
    return rule_id.startswith(("EP", "AU"))


# ── generic parse round trips ────────────────────────────────────────────────

def _check_layout(t: pa.Table, path: Path, source: str) -> None:
    assert t.schema.equals(C.SCHEMA)
    assert set(t["source"].to_pylist()) == {source}
    data = path.read_bytes()
    for off, ln in zip(t["byte_offset"].to_pylist(), t["line"].to_pylist()):
        assert off == 0 or data[off - 1:off] == b"\n"                 # offsets start a line
        assert data[:off].count(b"\n") + 1 == ln                        # and match the line number


def test_parse_pan_csv_round_trip(tmp_path):
    fmt, mapping, rep = _prep(tmp_path, "pan.csv")
    assert fmt == "csv" and rep["schema_source"] == "new"
    assert (tmp_path / "run" / "schema.yaml").exists() and (tmp_path / "run" / "schema_report.json").exists()
    assert (tmp_path / "schemas" / f"{mapping['fingerprint']}.yaml").exists()
    st = parse(FX / "pan.csv", tmp_path / "parsed", mapping, quiet=True)
    t = _parsed(tmp_path / "parsed")
    _check_layout(t, FX / "pan.csv", "pan.csv")
    assert t.num_rows == 45 and st["streams"]["firewall"]["rows"] == 45 and st["lines"] == 46
    assert t["line"].to_pylist()[0] == 2                                # line 1 is the header
    assert set(t["ts_quality"].to_pylist()) == {"tz_assumed"}
    assert t["parse_issue"].null_count == t.num_rows
    login = t.filter(pa.compute.equal(t["log_desc"], "Admin login failed"))
    assert login.num_rows >= 1 and set(login["status"].to_pylist()) == {"failed"}
    extra = [json.loads(e) for e in t["extra"].to_pylist() if e]
    assert any("Rule" in e for e in extra)                              # unmapped fields kept
    # a second schema run reuses the stored mapping
    _, m2, rep2 = _prep(tmp_path, "pan.csv")
    assert rep2["schema_source"].startswith("reused") and m2 == mapping


def test_parse_ndjson_bad_records_and_db(tmp_path):
    src = (FX / "ecs.ndjson").read_text(encoding="utf-8").splitlines()
    bad_port = json.loads(src[0])
    bad_port["source"]["port"] = "eighty"
    bad_ts = json.loads(src[1])
    bad_ts["@timestamp"] = "yesterday"
    lines = src + ["{not json", "", json.dumps(bad_port), json.dumps(bad_ts)]
    p = tmp_path / "ecs_bad.ndjson"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _, mapping, rep = _prep(tmp_path, p)
    assert rep["validation"]["dropped"] == []                           # 1 bad value in 47 still passes
    st = parse(p, tmp_path / "parsed", mapping, quiet=True)
    assert st["lines_by_class"]["rejected:bad_json"] == 1 and st["lines_by_class"]["blank"] == 1
    t = _parsed(tmp_path / "parsed")
    _check_layout(t, p, "ecs_bad.ndjson")
    by_line = {r["line"]: r for r in t.to_pylist()}
    n = len(src)
    assert by_line[n + 3]["parse_issue"] == "bad_number" and by_line[n + 3]["src_port"] is None
    assert json.loads(by_line[n + 3]["extra"])["_bad_src_port"] == "eighty"
    assert by_line[n + 4]["parse_issue"] == "bad_time" and by_line[n + 4]["ts_quality"] == "missing"
    assert json.loads(by_line[n + 4]["extra"])["_bad_ts"] == "yesterday"
    assert by_line[1]["ts"].isoformat() == "2026-10-28T19:11:08.662794+00:00"
    assert "event.kind" in json.loads(by_line[1]["extra"])
    from killchain import db

    con = db.open_run(tmp_path / "parsed")
    rows, valid = con.execute("SELECT count(*), count(*) FILTER (WHERE ts_valid) FROM events").fetchone()
    assert rows == n + 2 and valid == n                               # rows with a parse_issue are not ts_valid
    assert con.execute("SELECT count(*) FROM events WHERE src_internal IS NOT NULL").fetchone()[0] > 0


@pytest.mark.parametrize("name,rows,check", [
    ("sentinel.json", 3, lambda r: r["alert_name"].startswith("Possible SQL") and r["vendor_severity"] == 4
     and r["mitre_technique"] == "T1190" and r["category"] == "vendor_alert" and r["alert_confidence"] == 0.8),
    ("checkpoint_kv.txt", 5, lambda r: r["action"] == "deny" and r["src_ip"] == "32.127.48.11" and r["proto"] == 6),
    ("cef.txt", 5, lambda r: r["action"] == "deny" and r["dst_port"] == 1 and r["sent_bytes"] == 60
     and r["dev_name"] == "fw01" and r["proto"] == 6),
    ("windows.tsv", 5, lambda r: r["event_id"] == "4625" and r["status"] == "failed" and r["logon_type"] == "3"
     and r["category"] == "auth"),
])
def test_parse_other_formats(tmp_path, name, rows, check):
    _, mapping, _ = _prep(tmp_path, name)
    parse(FX / name, tmp_path / "parsed", mapping, quiet=True)
    t = _parsed(tmp_path / "parsed")
    assert t.schema.equals(C.SCHEMA) and t.num_rows == rows
    first = sorted(t.to_pylist(), key=lambda r: r["line"])[0]
    assert check(first), first
    if name != "sentinel.json":
        _check_layout(t, FX / name, name)


def test_json_array_line_and_offset(tmp_path):
    _, mapping, _ = _prep(tmp_path, "sentinel.json")
    parse(FX / "sentinel.json", tmp_path / "parsed", mapping, quiet=True)
    t = _parsed(tmp_path / "parsed")
    data = (FX / "sentinel.json").read_bytes()
    for off, ln in zip(t["byte_offset"].to_pylist(), t["line"].to_pylist()):
        assert data[off:off + 1] == b"{" and data[:off].count(b"\n") + 1 == ln
    extra = json.loads(t["extra"][0].as_py())
    assert extra["Entities.Address"] == "32.127.48.11,10.10.20.20"


def test_parse_gzip(tmp_path, monkeypatch):
    import sys

    P = sys.modules["killchain.schema.prepare"]
    monkeypatch.setattr(P, "DECOMPRESSED", tmp_path / "dec")
    gz = tmp_path / "ecs.ndjson.gz"
    with open(FX / "ecs.ndjson", "rb") as f, gzip.open(gz, "wb") as g:
        g.write(f.read())
    fmt, mapping, rep = _prep(tmp_path, gz)
    assert fmt == "ndjson (gzip)" and mapping["compressed"] == "gzip"
    assert rep["plain_input"].startswith(str(tmp_path / "dec"))
    parse(gz, tmp_path / "parsed", mapping, quiet=True)
    t = _parsed(tmp_path / "parsed")
    assert t.num_rows == 45 and set(t["source"].to_pylist()) == {"ecs.ndjson"}
    assert len(list((tmp_path / "dec").glob("*/ecs.ndjson"))) == 1        # decompressed once, reused


def test_fortigate_input_uses_the_existing_parser(tmp_path):
    fmt, mapping, rep = _prep(tmp_path, "fortigate.txt")
    assert fmt == "fortigate" and mapping["format"] == "fortigate" and rep["parser"] == "fortigate"
    assert _col(rep, "src_ip")["method"] == "fortigate" and _col(rep, "src_ip")["coverage"] == 1.0
    # every firewall and anomaly rule can run; the endpoint/auth rules need host columns a firewall lacks
    assert [r["id"] for r in rep["rules"]["skipped"] if not _host_rule(r["id"])] == []
    assert {r["id"] for r in rep["rules"]["skipped"] if _host_rule(r["id"])} >= {"EP01-encoded-powershell"}
    st = parse(FX / "fortigate.txt", tmp_path / "parsed", mapping, workers=1)
    assert st["lines_by_class"] == {"firewall": 6}
    from killchain.parser.fortigate import SCHEMA as FG

    assert _parsed(tmp_path / "parsed").schema.equals(FG)


def test_cli(tmp_path, capsys):
    from killchain.schema.cli import main

    shutil.copy(FX / "pan.csv", tmp_path / "pan.csv")
    code = main(["--input", str(tmp_path / "pan.csv"), "--name", "t", "--no-llm", "--data-dir", str(tmp_path),
                 "--schemas-dir", str(tmp_path / "schemas"), "--parse", "--workers", "1"])
    out = capsys.readouterr().out
    assert code == 0
    assert "format    csv" in out and "LLM: not used (--no-llm)" in out and "skipped A01-rare-event: missing log_id" in out
    assert (tmp_path / "runs" / "t" / "schema.yaml").exists()
    assert (tmp_path / "parsed" / "t" / "_stats.json").exists()
