"""killchain's canonical event columns: the FortiGate parser's columns plus optional ones for other products.

Every generic parse writes exactly SCHEMA into <parsed>/firewall/part-*.parquet, so db.py, the rules and
every later stage read a file of any product the same way as a FortiGate log. Columns the source does
not have stay null. The optional columns are listed in EXTRA_COLUMNS and documented in docs/schema.md.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import pyarrow as pa

from ..parser.fortigate import FIELDS, SCHEMA as FG_SCHEMA

# (column, type, meaning) of the columns the generic parser adds after the FortiGate ones.
EXTRA_COLUMNS: List[Tuple[str, str, str]] = [
    ("category", "str", "record group: network | endpoint | auth | vendor_alert | other"),
    ("product", "str", "product or provider that wrote the record"),
    ("host", "str", "machine the record is about (endpoint, computer, agent)"),
    ("host_ip", "str", "IP address of that machine"),
    ("src_host", "str", "name of the source machine (Windows WorkstationName, CEF shost)"),
    ("event_id", "str", "vendor event id or event type (Windows EventID, PAN Event ID, Okta eventType ...)"),
    ("process_name", "str", "process image name or path"),
    ("command_line", "str", "process command line"),
    ("parent_process", "str", "parent process name or path"),
    ("file_path", "str", "file path the event touched"),
    ("file_hash", "str", "file hash (sha256, sha1 or md5)"),
    ("logon_type", "str", "Windows logon type (2 interactive, 3 network, 10 remote interactive ...)"),
    ("alert_name", "str", "name of a detection another product raised (vendor alert)"),
    ("vendor_severity", "int", "severity normalised to 1-5 (1 informational ... 5 critical)"),
    ("alert_confidence", "float", "vendor alert confidence 0-1"),
    ("mitre_technique", "str", "ATT&CK technique ids the vendor gave, comma separated"),
    ("mitre_tactic", "str", "ATT&CK tactics the vendor gave, comma separated"),
]

MEANINGS: Dict[str, str] = {
    "ts": "event time (one field, or date and time fields)",
    "tz": "time zone of the event time, e.g. +0530",
    "date": "date part when date and time are separate fields",
    "time_of_day": "time part when date and time are separate fields",
    "log_id": "vendor log id / message id",
    "log_type": "traffic | utm | event (FortiGate type: traffic = sessions, utm = security inspection, event = device/system)",
    "log_subtype": "forward | ips | virus | webfilter | dns | app-ctrl | vpn | system | auth",
    "level": "log level",
    "action": "accept | deny | close | pass | passthrough | blocked | detected | dropped | reset | tunnel-up | login",
    "status": "success | failed (outcome of a login or operation)",
    "reason": "reason text",
    "src_ip": "source IP address", "src_port": "source port", "src_intf": "ingress interface",
    "src_intf_role": "ingress zone/role", "src_country": "source country name",
    "dst_ip": "destination IP address", "dst_port": "destination port", "dst_intf": "egress interface",
    "dst_intf_role": "egress zone/role", "dst_country": "destination country name",
    "proto": "IP protocol number (6 tcp, 17 udp, 1 icmp)", "service": "service / application protocol name",
    "policy_id": "firewall policy number", "session_id": "session number", "app": "application name",
    "app_cat": "application category", "app_risk": "application risk", "duration": "session seconds",
    "sent_bytes": "bytes sent by the source", "rcvd_bytes": "bytes received by the source",
    "sent_pkts": "packets sent", "rcvd_pkts": "packets received",
    "hostname": "destination domain: HTTP host, DNS query name, SNI",
    "dns_query": "DNS query name (fills hostname and sets log_subtype dns)",
    "url": "URL path requested (without the host)", "cat_desc": "URL category",
    "attack": "IPS/IDS signature name", "attack_id": "signature id", "severity": "event severity text",
    "cr_score": "client reputation score", "virus": "malware name found by antivirus",
    "user": "user / account name", "ui": "admin interface", "method": "HTTP method or login method",
    "log_desc": "event description (FortiGate logdesc, e.g. 'Admin login failed')",
    "msg": "message text", "dev_name": "name of the device that wrote the log", "dev_id": "device serial",
    "vd": "virtual domain", "alert_entities": "list of entities attached to a vendor alert",
}
for _c, _t, _m in EXTRA_COLUMNS:
    MEANINGS.setdefault(_c, _m)

INT_COLS = {name for _, name, kind in FIELDS if kind == "int"} | {c for c, t, _ in EXTRA_COLUMNS if t == "int"}
FLOAT_COLS = {c for c, t, _ in EXTRA_COLUMNS if t == "float"}
FG_COLUMNS = [name for _, name, _ in FIELDS]
OUTPUT_COLUMNS = FG_COLUMNS + [c for c, _, _ in EXTRA_COLUMNS]
# Mappable names that are not output columns: they feed ts, hostname or extra.
VIRTUAL = ("ts", "tz", "date", "time_of_day", "dns_query", "alert_entities")
MAPPABLE = list(VIRTUAL) + OUTPUT_COLUMNS
IP_COLS = ("src_ip", "dst_ip", "host_ip")
PORT_COLS = ("src_port", "dst_port")
COUNT_COLS = ("sent_bytes", "rcvd_bytes", "sent_pkts", "rcvd_pkts", "duration")
LITERAL_COLS = ("action", "status", "log_type", "log_subtype")     # compared to literals by the rules
LAYOUT_COLS = ("ts", "ts_quality", "event_time_raw", "source", "line", "byte_offset", "line_hash",
               "parse_issue", "extra")

# Derived columns of db.py -> the parser column they come from (for rule coverage).
DERIVED = {
    "src_internal": "src_ip", "src_zone": "src_ip", "src_role": "src_ip", "src_importance": "src_ip",
    "src_net24": "src_ip", "src_ip_int": "src_ip",
    "dst_internal": "dst_ip", "dst_zone": "dst_ip", "dst_role": "dst_ip", "dst_importance": "dst_ip",
    "dst_net24": "dst_ip", "dst_ip_int": "dst_ip",
    "ts_utc": "ts", "ts_ist": "ts", "ist_hour": "ts", "ts_valid": "ts",
}

_extra_fields = [(c, pa.int64() if t == "int" else pa.float64() if t == "float" else pa.string())
                 for c, t, _ in EXTRA_COLUMNS]
_fg = [f for f in FG_SCHEMA if f.name not in ("parse_issue", "extra")]
SCHEMA = pa.schema(_fg + [pa.field(n, t) for n, t in _extra_fields]
                   + [FG_SCHEMA.field("parse_issue"), FG_SCHEMA.field("extra")])
