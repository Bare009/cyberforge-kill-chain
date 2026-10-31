# Copied from AI-SOC: backend/services/collectors/syslog_parser.py (unchanged apart
# from this header). killchain uses it in syslog_server.py; the sink then
# forwards the message body (a FortiGate key=value line) to data/ingest/live.log.
"""Syslog line -> alert dict.

Decodes one syslog message (already de-framed) into a dict the normalisation
agent can classify deterministically. Pure stdlib, no I/O -- shared by the
syslog listener (`syslog_server.py`) and the first-party agent endpoint in the
mTLS service, which receives raw syslog lines forwarded by `agent/soar_agent.py`.

Envelope formats
  * RFC 5424  `<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG`
  * RFC 3164  `<PRI>Mmm dd hh:mm:ss HOST TAG[pid]: MSG` (and common variants:
              ISO timestamps, a year after the day, no hostname, no PRI)

Payload formats detected inside MSG
  * CEF   `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|k=v ...`
  * LEEF  `LEEF:1.0|Vendor|Product|Version|EventID|k=v<TAB>...` and LEEF 2.0
          with a custom delimiter
  * JSON  a JSON object body (SentinelOne, USM Anywhere and Sumo Logic
          forwarders can all emit this). The object is returned as the alert
          itself so the vendor's own structural fingerprint still applies.
  * anything else is kept as a plain message.

Output shape (non-JSON payloads) -- the keys the normaliser already reads:
  title, description, message, severity (low/medium/high/critical/
  informational), timestamp (ISO 8601), hostname,
  data.{srcip,dstip,srcport,dstport,srcuser,dstuser,proto,...},
  plus `syslog` / `cef` / `leef` blocks carrying everything decoded, and
  `raw_syslog` (the original line, capped).

Robustness rule: parsing never raises. A line that cannot be decoded at all is
still returned as a plain message, because dropping an event is worse than
ingesting it with less structure.
"""

from __future__ import annotations

import json
import re
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Dict, List, Optional, Tuple

MAX_RAW_CHARS = 8192

# Zone applied to zone-less timestamps for the message being parsed. A
# ContextVar rather than a parameter threaded through every helper; set and
# reset by parse_syslog only.
_ASSUME_TZ: ContextVar[Optional[tzinfo]] = ContextVar('syslog_assume_tz', default=None)

_SYSLOG_SEVERITY_NAMES = (
    'emergency', 'alert', 'critical', 'error',
    'warning', 'notice', 'informational', 'debug',
)

# Syslog severity (0-7) -> the generic labels severity_mapper understands.
_SYSLOG_SEVERITY_LABEL = {
    0: 'critical', 1: 'critical', 2: 'critical',
    3: 'high',
    4: 'medium',
    5: 'low',
    6: 'informational', 7: 'informational',
}

_MONTHS = {m: i for i, m in enumerate(
    ('jan', 'feb', 'mar', 'apr', 'may', 'jun',
     'jul', 'aug', 'sep', 'oct', 'nov', 'dec'), start=1)}

_PRI_RE = re.compile(r'^<(\d{1,3})>')
_5424_VERSION_RE = re.compile(r'^(\d{1,2}) ')
_3164_TS_RE = re.compile(
    r'^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})(?:\s+(?P<year>\d{4}))?\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*'
)
_ISO_TS_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*'
)
_TAG_RE = re.compile(r'^(?P<app>[^\s:\[\]]{1,64})(?:\[(?P<pid>[^\]]{1,32})\])?:\s?')
_CEF_START_RE = re.compile(r'CEF:\s?\d+\|')
_LEEF_START_RE = re.compile(r'LEEF:\s?\d(?:\.\d)?\|')
_CEF_EXT_KEY_RE = re.compile(r'(?:^|(?<=\s))([A-Za-z0-9_.\-\[\]]{1,64})=')
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9._:\-]{1,255}$')

# CEF extension keys -> the structured `data` keys the indicator extractor reads.
_CEF_TO_DATA = {
    'src': 'srcip', 'sourceTranslatedAddress': 'src_nat_ip',
    'dst': 'dstip', 'destinationTranslatedAddress': 'dst_nat_ip',
    'spt': 'srcport', 'dpt': 'dstport',
    'suser': 'srcuser', 'duser': 'dstuser',
    'shost': 'src_hostname', 'dhost': 'dst_hostname',
    'smac': 'src_mac', 'dmac': 'dst_mac',
    'proto': 'proto', 'app': 'app_protocol',
    'act': 'action', 'outcome': 'outcome', 'reason': 'reason',
    'request': 'url', 'requestMethod': 'http_method',
    'fname': 'filename', 'filePath': 'filepath', 'fileHash': 'file_hash',
    'sproc': 'src_process', 'dproc': 'process',
    'cat': 'category', 'dvc': 'device_ip', 'dvchost': 'device_hostname',
    'externalId': 'external_id', 'cnt': 'count',
}

# LEEF attribute keys -> `data` keys.
_LEEF_TO_DATA = {
    'src': 'srcip', 'dst': 'dstip',
    'srcPort': 'srcport', 'dstPort': 'dstport',
    'usrName': 'srcuser', 'dstUserName': 'dstuser', 'suser': 'srcuser', 'duser': 'dstuser',
    'srcMAC': 'src_mac', 'dstMAC': 'dst_mac',
    'proto': 'proto', 'cat': 'category', 'identHostName': 'src_hostname',
    'url': 'url', 'action': 'action', 'resource': 'resource',
    'policy': 'policy', 'fileName': 'filename', 'filePath': 'filepath',
}

_CEF_TIME_KEYS = ('rt', 'start', 'end', 'deviceReceiptTime')
_CEF_TIME_FORMATS = (
    '%b %d %Y %H:%M:%S.%f',
    '%b %d %Y %H:%M:%S',
    '%b %d %H:%M:%S.%f',
    '%b %d %H:%M:%S',
)


# ── Public API ───────────────────────────────────────────────────────────────

def parse_syslog(
    line: Any,
    *,
    sender_ip: Optional[str] = None,
    received_at: Optional[datetime] = None,
    assume_tz: Optional[tzinfo] = None,
) -> Dict[str, Any]:
    """Decode one syslog message into an alert dict. Never raises.

    `assume_tz` is the zone for timestamps that carry none (RFC 3164, CEF `rt`
    strings, LEEF `devTime`) -- the connector's configured source timezone.
    Without it they are read as UTC and flagged `timestamp_zone_assumed`, so the
    normaliser's time-quality check can report it.

    When the message has no timestamp at all, none is invented: the alert's
    `timestamp` is left unset and the normaliser records it as missing (and
    uses the platform receipt time), instead of silently passing the receipt
    time off as the event time.
    """
    received_at = received_at or datetime.now(timezone.utc)
    text = _to_text(line)
    token = _ASSUME_TZ.set(assume_tz)
    try:
        try:
            header, msg = _parse_envelope(text, received_at)
        except Exception:  # pragma: no cover -- defensive: never drop an event
            header, msg = {'format': 'raw'}, text
        if sender_ip:
            header['sender_ip'] = sender_ip

        try:
            return _decode_payload(text, header, msg, received_at)
        except Exception:  # pragma: no cover -- defensive
            return _plain_event(text, header, msg, received_at)
    finally:
        _ASSUME_TZ.reset(token)


def _zone() -> tzinfo:
    return _ASSUME_TZ.get() or timezone.utc


def _mark_zone(header: Dict[str, Any]) -> None:
    """Record that a zone-less timestamp was interpreted in an assumed zone."""
    tz = _ASSUME_TZ.get()
    header['timestamp_zone_assumed'] = True
    header['timestamp_zone'] = str(tz) if tz is not None else 'UTC'


def severity_label_0_10(value: Any) -> Optional[str]:
    """Map a CEF/LEEF 0-10 severity (number or ArcSight label) to a label."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    named = {
        'unknown': None, 'low': 'low', 'medium': 'medium', 'high': 'high',
        'very-high': 'critical', 'very high': 'critical', 'critical': 'critical',
        'informational': 'informational', 'info': 'informational',
    }
    if s in named:
        return named[s]
    try:
        n = float(s)
    except ValueError:
        return None
    if n <= 0:
        return 'informational'
    if n <= 3:
        return 'low'
    if n <= 6:
        return 'medium'
    if n <= 8:
        return 'high'
    return 'critical'


# ── Envelope ─────────────────────────────────────────────────────────────────

def _to_text(line: Any) -> str:
    if isinstance(line, (bytes, bytearray)):
        text = bytes(line).decode('utf-8', errors='replace')
    else:
        text = str(line or '')
    return text.replace('\x00', '').lstrip('\ufeff').rstrip('\r\n')


def _parse_envelope(text: str, received_at: datetime) -> Tuple[Dict[str, Any], str]:
    header: Dict[str, Any] = {'format': 'raw'}
    rest = text

    m = _PRI_RE.match(rest)
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            header['priority'] = pri
            header['facility'] = pri // 8
            header['severity'] = pri % 8
            header['severity_name'] = _SYSLOG_SEVERITY_NAMES[pri % 8]
        rest = rest[m.end():]

    v = _5424_VERSION_RE.match(rest)
    if m and v:
        return _parse_5424(rest[v.end():], header, int(v.group(1)))
    return _parse_3164(rest, header, received_at, had_pri=bool(m))


def _nil(v: str) -> Optional[str]:
    return None if v in ('-', '') else v


def _parse_5424(rest: str, header: Dict[str, Any], version: int) -> Tuple[Dict[str, Any], str]:
    header['format'] = 'rfc5424'
    header['version'] = version
    parts = rest.split(' ', 5)
    while len(parts) < 6:
        parts.append('-')
    ts, host, app, procid, msgid, remainder = parts
    header['timestamp'] = _nil(ts)
    header['hostname'] = _nil(host)
    header['app_name'] = _nil(app)
    header['procid'] = _nil(procid)
    header['msgid'] = _nil(msgid)

    sd, msg = _parse_structured_data(remainder)
    if sd:
        header['structured_data'] = sd
    return header, msg.lstrip('\ufeff')


def _parse_structured_data(s: str) -> Tuple[Dict[str, Dict[str, str]], str]:
    """Parse RFC 5424 STRUCTURED-DATA. Returns ({sd_id: {k: v}}, remaining msg)."""
    if s.startswith('-'):
        return {}, s[1:].lstrip(' ')
    out: Dict[str, Dict[str, str]] = {}
    i, n = 0, len(s)
    while i < n and s[i] == '[':
        i += 1
        j = i
        while j < n and s[j] not in ' ]':
            j += 1
        sd_id = s[i:j]
        params: Dict[str, str] = {}
        i = j
        while i < n and s[i] != ']':
            if s[i] == ' ':
                i += 1
                continue
            eq = s.find('=', i)
            if eq == -1 or eq + 1 >= n or s[eq + 1] != '"':
                # Malformed element: treat everything from here as message.
                return out, s[i:].lstrip(' ')
            name = s[i:eq]
            k = eq + 2
            val_chars: List[str] = []
            while k < n:
                c = s[k]
                if c == '\\' and k + 1 < n and s[k + 1] in '"\\]':
                    val_chars.append(s[k + 1])
                    k += 2
                    continue
                if c == '"':
                    break
                val_chars.append(c)
                k += 1
            params[name] = ''.join(val_chars)
            i = k + 1
        i += 1  # skip ']'
        if sd_id:
            out[sd_id] = params
    return out, s[i:].lstrip(' ')


def _parse_3164(
    rest: str, header: Dict[str, Any], received_at: datetime, *, had_pri: bool
) -> Tuple[Dict[str, Any], str]:
    ts_iso: Optional[str] = None
    m = _ISO_TS_RE.match(rest)
    if m:
        ts_iso = m.group('ts')
        rest = rest[m.end():]
    else:
        m = _3164_TS_RE.match(rest)
        if m:
            ts_iso = _bsd_timestamp(m, received_at)
            if ts_iso:
                _mark_zone(header)
            rest = rest[m.end():]

    if not had_pri and not ts_iso:
        # No syslog envelope at all (e.g. a bare CEF line over TCP).
        return header, rest

    header['format'] = 'rfc3164'
    header['timestamp'] = ts_iso

    # Payload that starts straight after the timestamp: no hostname, no tag.
    if not _payload_starts(rest):
        tok, _, after = rest.partition(' ')
        if tok and not tok.endswith(':') and _HOSTNAME_RE.match(tok) and after:
            header['hostname'] = tok
            rest = after

    if not _payload_starts(rest):
        t = _TAG_RE.match(rest)
        if t:
            header['app_name'] = t.group('app')
            if t.group('pid'):
                header['procid'] = t.group('pid')
            rest = rest[t.end():]
    return header, rest


def _payload_starts(s: str) -> bool:
    return s.startswith(('CEF:', 'LEEF:', '{'))


def _bsd_timestamp(m: 're.Match[str]', received_at: datetime) -> Optional[str]:
    """RFC 3164 has no year or zone. Assume UTC and infer the year, rolling
    back one year when the result would be more than a day in the future (a
    December event received in January)."""
    mon = _MONTHS.get(m.group('mon').lower())
    if not mon:
        return None
    try:
        hh, mm, ss = (int(x) for x in m.group('time').split(':'))
        year = int(m.group('year')) if m.group('year') else received_at.year
        day = int(m.group('day'))
        dt = datetime(year, mon, day, hh, mm, ss, tzinfo=_zone()).astimezone(timezone.utc)
        if not m.group('year') and dt - received_at > timedelta(days=1):
            dt = datetime(year - 1, mon, day, hh, mm, ss, tzinfo=_zone()).astimezone(timezone.utc)
        return dt.isoformat()
    except ValueError:
        return None


# ── Payload ──────────────────────────────────────────────────────────────────

def _decode_payload(
    text: str, header: Dict[str, Any], msg: str, received_at: datetime
) -> Dict[str, Any]:
    stripped = msg.strip()

    if stripped.startswith('{'):
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            header['payload_format'] = 'json'
            obj.setdefault('_syslog', header)
            obj.setdefault('raw_syslog', text[:MAX_RAW_CHARS])
            return obj

    cm = _CEF_START_RE.search(msg)
    if cm:
        return _cef_event(text, header, msg[cm.start():], msg[:cm.start()].strip(), received_at)

    lm = _LEEF_START_RE.search(msg)
    if lm:
        return _leef_event(text, header, msg[lm.start():], received_at)

    return _plain_event(text, header, msg, received_at)


def _base_event(text: str, header: Dict[str, Any], received_at: datetime) -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        'syslog': header,
        'raw_syslog': text[:MAX_RAW_CHARS],
    }
    # Only a real event time. No fallback to receipt time here: the normaliser
    # grades a missing timestamp and substitutes the platform receipt time
    # itself, so the gap stays visible instead of looking like a clean event.
    if header.get('timestamp'):
        ev['timestamp'] = header['timestamp']
    if header.get('hostname'):
        ev['hostname'] = header['hostname']
    return ev


def _plain_event(
    text: str, header: Dict[str, Any], msg: str, received_at: datetime
) -> Dict[str, Any]:
    header['payload_format'] = 'text'
    ev = _base_event(text, header, received_at)
    msg = msg.strip() or text.strip()
    app = header.get('app_name')
    first_line = msg.splitlines()[0] if msg else ''
    ev['title'] = (f'{app}: {first_line}' if app else first_line)[:200] or 'Syslog event'
    ev['description'] = msg[:4000]
    ev['message'] = msg[:4000]
    sev = header.get('severity')
    if isinstance(sev, int):
        ev['severity'] = _SYSLOG_SEVERITY_LABEL[sev]
    data: Dict[str, Any] = {}
    if header.get('hostname'):
        data['hostname'] = header['hostname']
    if header.get('sender_ip'):
        data['device_ip'] = header['sender_ip']
    if data:
        ev['data'] = data
    return ev


def _split_unescaped(s: str, sep: str, maxsplit: int) -> List[str]:
    """Split on `sep` not preceded by a backslash, unescaping \\sep and \\\\."""
    parts: List[str] = []
    buf: List[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '\\' and i + 1 < n and s[i + 1] in (sep, '\\'):
            buf.append(s[i + 1])
            i += 2
            continue
        if c == sep and len(parts) < maxsplit:
            parts.append(''.join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append(''.join(buf))
    return parts


def _unescape_cef_value(v: str) -> str:
    out: List[str] = []
    i, n = 0, len(v)
    while i < n:
        c = v[i]
        if c == '\\' and i + 1 < n:
            nxt = v[i + 1]
            if nxt in '=\\|':
                out.append(nxt)
                i += 2
                continue
            if nxt == 'n':
                out.append('\n')
                i += 2
                continue
            if nxt == 'r':
                out.append('\r')
                i += 2
                continue
        out.append(c)
        i += 1
    return ''.join(out).strip()


def parse_cef_extension(ext: str) -> Dict[str, str]:
    """Parse a CEF extension (`k=v k2=v with spaces k3=v`).

    Values may contain unescaped spaces, so a value runs until the next
    ` key=`. An escaped `\\=` never starts a key.
    """
    keys: List[Tuple[str, int, int]] = []
    for m in _CEF_EXT_KEY_RE.finditer(ext):
        eq_pos = m.end() - 1
        if eq_pos > 0 and ext[eq_pos - 1] == '\\':
            continue
        keys.append((m.group(1), m.start(1), m.end()))
    out: Dict[str, str] = {}
    for idx, (key, _start, vstart) in enumerate(keys):
        vend = keys[idx + 1][1] if idx + 1 < len(keys) else len(ext)
        out[key] = _unescape_cef_value(ext[vstart:vend])
    return out


def _cef_timestamp(
    ext: Dict[str, str], received_at: datetime, header: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    for key in _CEF_TIME_KEYS:
        raw = ext.get(key)
        if not raw:
            continue
        raw = raw.strip()
        if raw.isdigit():
            try:
                n = int(raw)
                secs = n / 1000.0 if n >= 1e12 else float(n)
                return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                continue
        # A trailing zone name ("... 12:00:00 UTC"). UTC/GMT is honoured; any
        # other abbreviation is ambiguous (IST is India, Israel or Ireland), so
        # the connector's configured zone is used and the guess is flagged.
        zm = re.search(r'\s+([A-Za-z]{1,5})$', raw)
        zone_name = zm.group(1).upper() if zm else None
        candidate = raw[:zm.start()] if zm else raw
        explicit_utc = zone_name in ('UTC', 'GMT', 'Z')
        for fmt in _CEF_TIME_FORMATS:
            try:
                dt = datetime.strptime(candidate, fmt)
            except ValueError:
                continue
            if '%Y' not in fmt:
                dt = dt.replace(year=received_at.year)
            if explicit_utc:
                return dt.replace(tzinfo=timezone.utc).isoformat()
            if header is not None:
                _mark_zone(header)
            return dt.replace(tzinfo=_zone()).astimezone(timezone.utc).isoformat()
        return raw  # let the normaliser's timestamp tool try
    return None


def _labelled_customs(ext: Dict[str, str]) -> Dict[str, str]:
    """Resolve csN/cnN/cfpN/flexString* values to their `...Label` names."""
    out: Dict[str, str] = {}
    for key, val in ext.items():
        if key.endswith('Label'):
            continue
        label = ext.get(f'{key}Label')
        if label:
            out[label] = val
    return out


def _cef_event(
    text: str, header: Dict[str, Any], cef: str, prefix: str, received_at: datetime
) -> Dict[str, Any]:
    header['payload_format'] = 'cef'
    parts = _split_unescaped(cef, '|', 7)
    while len(parts) < 8:
        parts.append('')
    version = parts[0].split(':', 1)[-1].strip()
    vendor, product, dev_version, sig_id, name, severity, ext_raw = parts[1:8]
    ext = parse_cef_extension(ext_raw)

    ev = _base_event(text, header, received_at)
    ts = _cef_timestamp(ext, received_at, header)
    if ts:
        ev['timestamp'] = ts

    ev['title'] = (name or sig_id or 'CEF event')[:200]
    ev['name'] = ev['title']
    msg = ext.get('msg') or ''
    ev['description'] = (msg or name or prefix)[:4000]
    ev['message'] = (msg or name)[:4000]
    label = severity_label_0_10(severity)
    if label:
        ev['severity'] = label

    data: Dict[str, Any] = {}
    for src_key, dst_key in _CEF_TO_DATA.items():
        if ext.get(src_key):
            data.setdefault(dst_key, ext[src_key])
    if header.get('hostname'):
        data.setdefault('hostname', header['hostname'])
    if header.get('sender_ip'):
        data.setdefault('device_ip', header['sender_ip'])
    if data:
        ev['data'] = data

    ev['cef'] = {
        'version': version,
        'device_vendor': vendor,
        'device_product': product,
        'device_version': dev_version,
        'signature_id': sig_id,
        'name': name,
        'severity': severity,
        'extensions': ext,
    }
    customs = _labelled_customs(ext)
    if customs:
        ev['cef']['custom_fields'] = customs
    if sig_id:
        ev['rule_id'] = sig_id
    return ev


def _leef_event(
    text: str, header: Dict[str, Any], leef: str, received_at: datetime
) -> Dict[str, Any]:
    header['payload_format'] = 'leef'
    version = leef.split('|', 1)[0].split(':', 1)[-1].strip()
    is_v2 = version.startswith('2')
    parts = _split_unescaped(leef, '|', 6 if is_v2 else 5)
    while len(parts) < (7 if is_v2 else 6):
        parts.append('')
    vendor, product, dev_version, event_id = parts[1:5]

    delim = '\t'
    if is_v2:
        raw_delim = parts[5]
        attrs_raw = parts[6]
        if raw_delim:
            if raw_delim.lower().startswith(('0x', 'x')) and len(raw_delim) > 1:
                try:
                    delim = chr(int(raw_delim.lower().lstrip('0').lstrip('x'), 16))
                except ValueError:
                    delim = '\t'
            else:
                delim = raw_delim[0]
    else:
        attrs_raw = parts[5]

    attrs: Dict[str, str] = {}
    for pair in attrs_raw.split(delim):
        if '=' not in pair:
            continue
        k, _, v = pair.partition('=')
        k = k.strip()
        if k:
            attrs[k] = v.strip()

    ev = _base_event(text, header, received_at)
    if attrs.get('devTime'):
        leef_ts = _cef_timestamp({'rt': attrs['devTime']}, received_at, header)
        if leef_ts:
            ev['timestamp'] = leef_ts

    title = attrs.get('name') or attrs.get('eventName') or event_id or 'LEEF event'
    ev['title'] = title[:200]
    ev['name'] = ev['title']
    ev['description'] = (attrs.get('msg') or attrs.get('message') or title)[:4000]
    ev['message'] = ev['description']
    label = severity_label_0_10(attrs.get('sev'))
    if label:
        ev['severity'] = label

    data: Dict[str, Any] = {}
    for src_key, dst_key in _LEEF_TO_DATA.items():
        if attrs.get(src_key):
            data.setdefault(dst_key, attrs[src_key])
    if header.get('hostname'):
        data.setdefault('hostname', header['hostname'])
    if header.get('sender_ip'):
        data.setdefault('device_ip', header['sender_ip'])
    if data:
        ev['data'] = data

    ev['leef'] = {
        'version': version,
        'vendor': vendor,
        'product': product,
        'product_version': dev_version,
        'event_id': event_id,
        'attributes': attrs,
    }
    if event_id:
        ev['rule_id'] = event_id
    return ev
