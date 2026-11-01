"""Convert a slice of a FortiGate log into Palo Alto-style CSV and ECS NDJSON (test data for killchain/schema).

    python tools/convert_firewall.py --raw data/raw/firex-10G.log --incident 28 --run data/runs/firex-10G \
        --out-dir data/tmp/zz --name zz-slice [--margin-mb 6]

The slice is one contiguous byte range of the raw file: from `margin` MB before the first line of the
truth incident to `margin` MB after its last line (resynced to line boundaries), so it holds the whole
incident plus the background around it. Every FortiGate line becomes one PAN row and one ECS object, in
the same order, with each product's own field names and value words:

  PAN CSV   Type TRAFFIC/THREAT/URL/SYSTEM, Threat/Content Type (end, deny, vulnerability, virus, url, dns,
            app-ctrl, auth, vpn, general ...), Action allow/deny/drop/reset-both/alert/block-url,
            "Source address", "Destination Port", "Bytes Sent", "Generate Time" (UTC, seconds) ...
            Admin logins are SYSTEM rows with Event ID auth-fail / auth-success.
  ECS       @timestamp (UTC, µs), event.dataset firewall.<subtype>, event.category, event.action
            allowed/denied/dropped/blocked/detected/login, event.outcome, event.code (the FortiGate logid),
            source.*, destination.*, network.*, user.name, url.original / url.domain, dns.question.name,
            rule.name (signature or malware name) ...

App-control rows have no real PAN equivalent; they are THREAT rows with subtype app-ctrl. Outputs:
<out>/<name>.csv, <out>/<name>.ndjson, <out>/<name>.linemap.parquet (original line -> line and byte offset
in each output) and, with --run, truth files remapped to each output (<out>/truth-{fg,pan,ecs}.parquet).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import time
from datetime import timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from killchain.parser.cli import next_line_start  # noqa: E402
from killchain.parser.lines import LineParser  # noqa: E402
from killchain.parser.worker import count_newlines  # noqa: E402

try:
    import orjson

    def _dumps(o: Any) -> bytes:
        return orjson.dumps(o)
except ImportError:  # pragma: no cover
    def _dumps(o: Any) -> bytes:
        return json.dumps(o, separators=(",", ":"), ensure_ascii=False).encode()

PAN_HEADER = ["Receive Time", "Serial #", "Type", "Threat/Content Type", "Generate Time", "Source address",
              "Destination address", "Rule", "Source User", "Application", "Virtual System", "Source Zone",
              "Destination Zone", "Inbound Interface", "Outbound Interface", "Session ID", "Source Port",
              "Destination Port", "IP Protocol", "Action", "Bytes", "Bytes Sent", "Bytes Received", "Packets Sent",
              "Packets Received", "Elapsed Time (sec)", "Category", "Source Country", "Destination Country",
              "Threat/Content Name", "Threat ID", "Severity", "URL/Filename", "URL Domain", "Event ID", "Admin",
              "Description", "Device Name", "Session End Reason"]
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}
CONFIG_ACTIONS = {"Add", "Edit", "Delete"}


def _slug(s: Optional[str]) -> Optional[str]:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") if s else None


def _n(v: Any) -> str:
    return "" if v is None else str(v)


# ── PAN ──────────────────────────────────────────────────────────────────────

def pan_row(r: Dict[str, Any]) -> List[str]:
    lt, st, act = r["log_type"], r["log_subtype"], r["action"]
    user = r["user"]
    admin = None
    event_id = None
    if lt == "traffic":
        typ = "TRAFFIC"
        sub = "end" if act == "accept" else "deny" if act == "deny" else (act or "end")
        pact = {"accept": "allow", "deny": "deny" if r["line"] % 2 else "drop"}.get(act, act)
    elif lt == "utm":
        typ = "URL" if st == "webfilter" else "THREAT"
        sub = {"ips": "vulnerability", "virus": "virus", "webfilter": "url"}.get(st, st)
        pact = {("ips", "dropped"): "reset-both", ("ips", "detected"): "alert", ("virus", "blocked"): "block",
                ("virus", "detected"): "alert", ("webfilter", "passthrough"): "alert",
                ("webfilter", "blocked"): "block-url", ("dns", "pass"): "allow",
                ("app-ctrl", "pass"): "allow"}.get((st, act), act)
    else:
        typ = "SYSTEM"
        sub = {"system": "general"}.get(st, st)
        pact = None if act in ("login", "N/A") else act
        if act == "login":
            sub = "auth"
            event_id = "auth-success" if r["status"] == "success" else "auth-fail"
        else:
            event_id = _slug(r["log_desc"]) or _slug(act)
        if act in CONFIG_ACTIONS:
            typ, sub, admin, user = "CONFIG", "config", user, None
    ts = r["ts"].astimezone(timezone.utc).strftime("%Y/%m/%d %H:%M:%S") if r["ts"] else ""
    proto = r["proto"]
    sb, rb = r["sent_bytes"], r["rcvd_bytes"]
    threat = r["attack"] or r["virus"]
    return [ts, _n(r["dev_id"]), typ, _n(sub), ts, _n(r["src_ip"]), _n(r["dst_ip"]),
            f"rule-{r['policy_id']}" if r["policy_id"] is not None else "", _n(user), _n(r["app"]), _n(r["vd"]),
            _n(r["src_intf_role"]), _n(r["dst_intf_role"]), _n(r["src_intf"]), _n(r["dst_intf"]),
            _n(r["session_id"]), _n(r["src_port"]), _n(r["dst_port"]),
            "" if proto is None else PROTO.get(proto, str(proto)), _n(pact),
            "" if sb is None and rb is None else str((sb or 0) + (rb or 0)), _n(sb), _n(rb),
            _n(r["sent_pkts"]), _n(r["rcvd_pkts"]), _n(r["duration"]), _n(r["cat_desc"]), _n(r["src_country"]),
            _n(r["dst_country"]), _n(threat), _n(r["attack_id"]), _n(r["severity"]), _n(r["url"]),
            _n(r["hostname"]), _n(event_id), _n(admin), _n(r["msg"]), _n(r["dev_name"]), _n(r["reason"])]


# ── ECS ──────────────────────────────────────────────────────────────────────

def _put(d: Dict[str, Any], path: str, v: Any) -> None:
    if v is None or v == "":
        return
    keys = path.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = v


def ecs_doc(r: Dict[str, Any]) -> Dict[str, Any]:
    lt, st, act = r["log_type"], r["log_subtype"], r["action"]
    d: Dict[str, Any] = {"@timestamp": r["ts"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if r["ts"] else None}
    ds = {"app-ctrl": "app_control", "forward": "traffic"}.get(st, st)
    _put(d, "event.kind", "event")
    _put(d, "event.module", "firewall")
    _put(d, "event.dataset", f"firewall.{ds}")
    _put(d, "event.code", r["log_id"])
    if lt == "traffic":
        cat, typ = ["network"], ["connection", "allowed" if act == "accept" else "denied"]
        eact = {"accept": "allowed", "deny": "denied"}.get(act, act)
    elif lt == "utm":
        cat = {"ips": ["intrusion_detection", "network"], "virus": ["malware"], "webfilter": ["web"]}.get(st, ["network"])
        typ = ["info"]
        eact = {"dropped": "dropped", "detected": "detected", "blocked": "blocked", "passthrough": "allowed",
                "pass": "allowed"}.get(act, act)
    else:
        if act == "login":
            cat, typ, eact = ["authentication"], ["start"], "login"
            _put(d, "event.outcome", "success" if r["status"] == "success" else "failure")
        elif act in CONFIG_ACTIONS:
            cat, typ, eact = ["configuration"], ["change"], act.lower()
        else:
            cat, typ, eact = (["network"] if st == "vpn" else ["host"]), ["info"], (None if act == "N/A" else act)
    _put(d, "event.category", cat)
    _put(d, "event.type", typ)
    _put(d, "event.action", eact)
    _put(d, "event.reason", r["reason"])
    _put(d, "observer.name", r["dev_name"])
    _put(d, "observer.serial_number", r["dev_id"])
    _put(d, "observer.type", "firewall")
    _put(d, "observer.vendor", "Fortinet")
    _put(d, "observer.product", "FortiGate")
    _put(d, "observer.ingress.interface.name", r["src_intf"])
    _put(d, "observer.ingress.zone", r["src_intf_role"])
    _put(d, "observer.egress.interface.name", r["dst_intf"])
    _put(d, "observer.egress.zone", r["dst_intf_role"])
    _put(d, "source.ip", r["src_ip"])
    _put(d, "source.port", r["src_port"])
    _put(d, "source.bytes", r["sent_bytes"])
    _put(d, "source.packets", r["sent_pkts"])
    _put(d, "source.geo.country_name", r["src_country"])
    _put(d, "destination.ip", r["dst_ip"])
    _put(d, "destination.port", r["dst_port"])
    _put(d, "destination.bytes", r["rcvd_bytes"])
    _put(d, "destination.packets", r["rcvd_pkts"])
    _put(d, "destination.geo.country_name", r["dst_country"])
    if r["proto"] is not None:
        _put(d, "network.transport", PROTO.get(r["proto"], str(r["proto"])))
        _put(d, "network.iana_number", str(r["proto"]))
    if r["sent_bytes"] is not None or r["rcvd_bytes"] is not None:
        _put(d, "network.bytes", (r["sent_bytes"] or 0) + (r["rcvd_bytes"] or 0))
    _put(d, "network.protocol", r["service"].lower() if r["service"] else None)
    _put(d, "network.application", r["app"])
    _put(d, "user.name", r["user"])
    if st == "dns":
        _put(d, "dns.question.name", r["hostname"])
    else:
        _put(d, "url.domain", r["hostname"])
    _put(d, "url.original", r["url"])
    _put(d, "url.category", r["cat_desc"])
    _put(d, "rule.name", r["attack"] or r["virus"])
    _put(d, "rule.id", r["attack_id"])
    _put(d, "log.level", r["level"])
    _put(d, "message", r["msg"])
    return d


# ── main ─────────────────────────────────────────────────────────────────────

def slice_bounds(raw: Path, run: Optional[Path], incident: Optional[int], start: Optional[int], end: Optional[int],
                 margin: int) -> Tuple[int, int]:
    size = raw.stat().st_size
    if incident is not None:
        t = pl.read_parquet(run / "truth.parquet").filter(pl.col("incident_id") == incident)
        if not t.height:
            sys.exit(f"incident {incident} not in {run / 'truth.parquet'}")
        start, end = int(t["byte_offset"].min()) - margin, int(t["byte_offset"].max()) + margin
    with open(raw, "rb") as f:
        a = next_line_start(f, max(0, start or 0), size)
        b = next_line_start(f, min(size, end if end is not None else size), size)
    return a, b


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--raw", default=str(ROOT / "data" / "raw" / "firex-10G.log"))
    ap.add_argument("--run", default=str(ROOT / "data" / "runs" / "firex-10G"), help="run with truth.parquet")
    ap.add_argument("--incident", type=int, help="slice around this truth incident")
    ap.add_argument("--start", type=int)
    ap.add_argument("--end", type=int)
    ap.add_argument("--margin-mb", type=float, default=6.0)
    ap.add_argument("--out-dir", default=str(ROOT / "data" / "tmp" / "zz"))
    ap.add_argument("--name", default="zz-slice")
    ap.add_argument("--batch", type=int, default=50000)
    a = ap.parse_args(argv)
    raw, run, out = Path(a.raw), Path(a.run), Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    start, end = slice_bounds(raw, run, a.incident, a.start, a.end, int(a.margin_mb * 2**20))
    base = 1 + sum(count_newlines((str(raw), s, min(s + (256 << 20), start))) for s in range(0, start, 256 << 20))
    print(f"slice bytes {start:,}-{end:,} ({(end - start) / 2**20:.1f} MB), first line {base:,}", flush=True)
    pan_path, ecs_path = out / f"{a.name}.csv", out / f"{a.name}.ndjson"
    parser = LineParser(raw.name)
    maps: List[Tuple[int, int, int, int, int, int]] = []
    pan_line, ecs_line = 2, 1
    with open(raw, "rb") as f, open(pan_path, "wb") as pf, open(ecs_path, "wb") as ef:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(PAN_HEADER)
        pf.write(buf.getvalue().encode())
        pan_off, ecs_off = pf.tell(), 0
        f.seek(start)
        pos, line_no = start, base
        batch: List[Tuple[bytes, int, int]] = []

        def flush() -> None:
            nonlocal pan_line, ecs_line, pan_off, ecs_off
            if not batch:
                return
            tables = parser.parse(batch)
            fw = tables.get("firewall")
            batch.clear()
            if fw is None:
                return
            for r in fw.sort_by("line").to_pylist():
                buf.seek(0)
                buf.truncate()
                w.writerow(pan_row(r))
                b = buf.getvalue().encode()
                pf.write(b)
                e = _dumps(ecs_doc(r)) + b"\n"
                ef.write(e)
                maps.append((r["line"], r["byte_offset"], pan_line, pan_off, ecs_line, ecs_off))
                pan_line += 1
                ecs_line += 1
                pan_off += len(b)
                ecs_off += len(e)

        while pos < end:
            rawl = f.readline()
            if not rawl:
                break
            batch.append((rawl.rstrip(b"\n").rstrip(b"\r"), line_no, pos))
            pos += len(rawl)
            line_no += 1
            if len(batch) >= a.batch:
                flush()
        flush()
    lm = pl.DataFrame(maps, schema=["orig_line", "orig_offset", "pan_line", "pan_offset", "ecs_line", "ecs_offset"],
                      orient="row")
    lm.write_parquet(out / f"{a.name}.linemap.parquet")
    print(f"wrote {len(maps):,} records: {pan_path} ({pan_path.stat().st_size / 2**20:.1f} MB), "
          f"{ecs_path} ({ecs_path.stat().st_size / 2**20:.1f} MB) in {time.perf_counter() - t0:.1f} s")
    tp = run / "truth.parquet"
    if tp.exists():
        t = pl.read_parquet(tp).filter(pl.col("source") == raw.name)
        t = t.join(lm, left_on="line", right_on="orig_line", how="inner")
        t.drop([c for c in lm.columns if c != "orig_line"]).write_parquet(out / "truth-fg.parquet")
        for kind, path in (("pan", pan_path), ("ecs", ecs_path)):
            (t.with_columns(pl.col(f"{kind}_line").alias("line"), pl.col(f"{kind}_offset").alias("byte_offset"),
                            pl.lit(path.name).alias("source"))
             .select(pl.read_parquet(tp).columns).write_parquet(out / f"truth-{kind}.parquet"))
        print(f"truth: {t.height:,} lines of {t['incident_id'].n_unique()} incidents inside the slice "
              f"-> {out / 'truth-fg.parquet'}, truth-pan.parquet, truth-ecs.parquet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
