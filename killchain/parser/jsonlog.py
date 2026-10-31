"""JSON lines (Windows event logs, ECS/EDR exports) -> the `windows` table.

The organisers' Windows stream is JSON lines, but no sample of it has been
shared yet, so field names are matched against alias lists that cover the
common shapes: ECS / Winlogbeat (`winlog.event_data.TargetUserName`), flat
NXLog-style exports (`TargetUserName`, `EventID`) and the ECS EDR events in
edr_events.json. Matching is case-insensitive on the flattened dotted path.
Everything that does not map to a column is kept in `extra`, so a wrong guess
loses nothing; adjust ALIASES once the real file arrives.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import pyarrow as pa

from . import arrowutil as au

# column -> candidate flattened paths, lower-case, first match wins
ALIASES: Dict[str, List[str]] = {
    "ts": ["@timestamp", "timestamp", "timecreated", "system.timecreated.systemtime",
           "timecreated.systemtime", "eventtime", "event_time", "utctime", "time", "ts", "event.created"],
    "event_id": ["winlog.event_id", "event.code", "eventid", "event_id", "system.eventid", "eventcode"],
    "provider": ["winlog.provider_name", "event.provider", "providername", "provider", "system.provider.name",
                 "sourcename"],
    "channel": ["winlog.channel", "channel", "system.channel", "logname"],
    "record_id": ["winlog.record_id", "eventrecordid", "system.eventrecordid", "recordnumber", "record_id"],
    "host": ["host.name", "winlog.computer_name", "computer", "computername", "hostname", "host.hostname",
             "system.computer", "host"],
    "host_ip": ["host.ip", "host_ip"],
    "user": ["user.name", "winlog.event_data.subjectusername", "subjectusername", "eventdata.subjectusername",
             "user", "username", "accountname"],
    "user_domain": ["user.domain", "winlog.event_data.subjectdomainname", "subjectdomainname"],
    "target_user": ["winlog.event_data.targetusername", "targetusername", "eventdata.targetusername",
                    "user.target.name", "target_user", "samaccountname"],
    "target_domain": ["winlog.event_data.targetdomainname", "targetdomainname", "user.target.domain"],
    "logon_type": ["winlog.event_data.logontype", "logontype", "winlog.logon.type", "logon_type"],
    "src_ip": ["source.ip", "winlog.event_data.ipaddress", "ipaddress", "src_ip", "sourceaddress", "sourceip",
               "client.ip", "clientaddress"],
    "src_port": ["source.port", "winlog.event_data.ipport", "ipport", "src_port", "sourceport"],
    "src_host": ["winlog.event_data.workstationname", "workstationname", "source.domain", "clientname"],
    "dst_ip": ["destination.ip", "dst_ip", "destinationaddress", "destinationip"],
    "dst_port": ["destination.port", "dst_port", "destinationport"],
    "dst_domain": ["destination.domain", "dns.question.name", "queryname", "dns_query"],
    "process_name": ["process.name", "winlog.event_data.newprocessname", "newprocessname", "image",
                     "winlog.event_data.processname", "processname", "process.executable"],
    "command_line": ["process.command_line", "winlog.event_data.commandline", "commandline", "command_line"],
    "parent_process": ["process.parent.name", "winlog.event_data.parentprocessname", "parentprocessname",
                       "parentimage", "process.parent.executable"],
    "service_name": ["winlog.event_data.servicename", "servicename", "service.name", "service_name"],
    "service_file": ["winlog.event_data.imagepath", "imagepath", "winlog.event_data.servicefilename",
                     "servicefilename"],
    "share_name": ["winlog.event_data.sharename", "sharename"],
    "relative_target": ["winlog.event_data.relativetargetname", "relativetargetname"],
    "ticket_encryption": ["winlog.event_data.ticketencryptiontype", "ticketencryptiontype"],
    "status": ["winlog.event_data.status", "status"],
    "sub_status": ["winlog.event_data.substatus", "substatus"],
    "outcome": ["event.outcome", "outcome", "result", "keywords"],
    "member": ["winlog.event_data.membername", "membername", "winlog.event_data.membersid", "membersid"],
    "privileges": ["winlog.event_data.privilegelist", "privilegelist"],
    "file_path": ["file.path", "targetfilename", "winlog.event_data.objectname", "objectname"],
    "registry_path": ["registry.path", "targetobject"],
    "event_action": ["event.action", "action", "winlog.task", "task"],
    "event_category": ["event.category", "category"],
    "bytes": ["network.bytes", "bytes"],
    "message": ["message", "msg", "description"],
    "vendor_rule": ["rule.name", "rule_name"],
    "vendor_technique": ["threat.technique.id", "mitre_technique"],
}
COLUMNS = [c for c in ALIASES if c != "ts"]
INT_COLS = {"event_id", "record_id", "src_port", "dst_port", "bytes"}

SCHEMA = pa.schema(
    [
        ("ts", pa.timestamp("us", tz="UTC")),
        ("ts_quality", pa.string()),
        ("source", pa.string()),
        ("line", pa.int64()),
        ("byte_offset", pa.int64()),
        ("line_hash", pa.int64()),
    ]
    + [(c, pa.int64() if c in INT_COLS else pa.string()) for c in COLUMNS]
    + [("extra", pa.string())]
)


def flatten(obj: Dict[str, Any], prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if out is None:
        out = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flatten(v, key + ".", out)
        else:
            out[key] = v
    return out


def _scalar(v: Any) -> Any:
    if isinstance(v, list):
        if not v:
            return None
        if len(v) == 1:
            v = v[0]
        else:
            return ",".join(str(x) for x in v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return au.dumps(v)
    return v


class JsonBatch:
    stream = "windows"
    schema = SCHEMA

    def __init__(self) -> None:
        self.ts: List[Any] = []
        self.rows: List[tuple] = []
        self.meta: List[Tuple[int, int, int]] = []
        self.extras: List[Optional[str]] = []
        self.unknown_keys: Counter = Counter()

    def __len__(self) -> int:
        return len(self.rows)

    def add(self, obj: Dict[str, Any], line_no: int, offset: int, line_hash: int) -> None:
        flat = flatten(obj)
        lower = {k.lower(): k for k in flat}
        used = set()
        values: Dict[str, Any] = {}
        for col, paths in ALIASES.items():
            for p in paths:
                k = lower.get(p)
                if k is None:
                    continue
                v = _scalar(flat[k])
                if v is None or v == "":
                    continue
                values[col] = v
                used.add(k)
                break
        self.ts.append(values.pop("ts", None))
        self.rows.append(tuple(values.get(c) for c in COLUMNS))
        self.meta.append((line_no, offset, line_hash))
        rest = {k: flat[k] for k in flat if k not in used}
        if rest:
            self.unknown_keys.update(rest.keys())
            self.extras.append(au.dumps(rest))
        else:
            self.extras.append(None)

    def to_table(self, source: str, tq: au.TimeQuality, default_tz: int) -> Tuple[pa.Table, dict]:
        ts, valid, quality = au.json_time(self.ts, default_tz)
        tq.apply(ts, valid, quality)
        cols = list(zip(*self.rows))
        lines, offsets, hashes = zip(*self.meta)
        n = len(self.rows)
        arrays = {
            "ts": au.ts_array(ts, valid),
            "ts_quality": au.quality_array(quality),
            "source": pa.array([source] * n, pa.string()),
            "line": pa.array(lines, pa.int64()),
            "byte_offset": pa.array(offsets, pa.int64()),
            "line_hash": pa.array(hashes, pa.int64()),
        }
        for c, values in zip(COLUMNS, cols):
            text = pa.array([None if v is None else str(v) for v in values], pa.string())
            arrays[c] = au.to_int(text) if c in INT_COLS else text
        arrays["extra"] = pa.array(self.extras, pa.string())
        return pa.table(arrays, schema=SCHEMA), au.batch_info(ts, valid, quality)
