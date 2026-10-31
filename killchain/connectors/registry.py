# Copied from AI-SOC: web_app/backend/app/services/siem_integrations.py
# killchain changes: Motor/MongoDB replaced by the JSON-file store (store.py,
# `db` is a ConnectorStore and calls are synchronous); get_settings() replaced
# by env vars (config.py); tenancy, licensing and audit removed; webhook path is
# /ingest/webhook/{id}; the auth cache is invalidated on every change; the
# public row adds linesForwarded / notAnalysable / duplicates (sink.py
# counters); the agents list is empty (no agent endpoint) and unmatched syslog
# senders come from the listener's memory (syslog_server.py);
# merge_with_observed_sources has no Mongo stats to merge and fills the
# observed fields from the connector's own counters.
"""Connector registry for customer log sources (Settings -> SIEM Integrations).

Each document describes one configured log source: which vendor it is, which
*transport* delivers its alerts, how that transport is authenticated, and
whether it is enabled. Other modules read this same store:

  * the webhook endpoint (`webhook.py`) authenticates requests against it
    (`auth.py`);
  * the poller (`poller.py`) runs API-pull connectors from it, and the optional
    syslog listener (`syslog_server.py`) matches senders against it.

This module and those readers must agree on the document shape and on the
secret hashing scheme.

Document shape
--------------
    connector_id, vendor, name, enabled, created_at, created_by, updated_at,
    transport            webhook | api_pull | syslog | agent  (absent = webhook)
    auth_mode            webhook/agent: mtls | hmac | bearer
                         api_pull: api     syslog: source_ip | mtls
    secret_hash, secret_hint, secret_rotated_at     webhook/agent bearer|hmac
    allowed_cn_pattern                              any mtls mode
    last_seen_at, alerts_received                   ingest counters
    pull        {client, config, interval_seconds, credentials_enc,
                 credential_hint, credentials_updated_at}          api_pull
    pull_state  {cursor, next_run_at, last_run_at, last_success_at,
                 last_error, last_run, consecutive_failures,
                 lease_owner, lease_until}          written by the collector
    syslog      {allowed_sources: [cidr, ...]}      syslog
    syslog_state {last_message_at, last_sender_ip}  written by the collector

Secret handling
---------------
* Webhook/agent secrets are generated here, returned to the caller exactly
  once, and stored only as SHA-256. That is the right choice *for this input*:
  a 256-bit random token has no guessable structure, so a slow KDF buys nothing
  and would throttle the per-request verification. Never use it for passwords.
* API-pull credentials must be usable by the collector, so they are encrypted
  (Fernet) instead -- see `credentials.py`. They are write-only
  through this API: nothing returns them, only a hint.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from . import credentials as cred_store
from .auth import invalidate_cache
from .config import CollectorSettings, collector_allow_http, syslog_enabled
from .store import ConnectorStore
from .vendors import (
    TRANSPORTS,
    auth_modes_for,
    default_auth_mode,
    get_vendor,
    pull_spec,
    vendor_label,
    vendor_transports,
)

UTC = timezone.utc

COLLECTION = 'siem_integrations'

# Prefix makes a leaked token identifiable in logs/secret scanners.
_SECRET_PREFIX = 'soar_'
_SECRET_BYTES = 32  # 256 bits of entropy

# Length of the public connector id that appears in the webhook URL.
_CONNECTOR_ID_BYTES = 12

_NAME_MAX = 60
_VALID_CONNECTOR_ID = re.compile(r'^[A-Za-z0-9_-]{6,64}$')

_MIN_INTERVAL = 60
_MAX_INTERVAL = 86_400
_MAX_SOURCES = 64
_MAX_CRED_LEN = 4096
_MAX_JSON_FIELD = 4096


class SiemIntegrationError(ValueError):
    """Raised for caller-correctable problems (bad vendor, duplicate name, ...)."""


def _now() -> datetime:
    return datetime.now(UTC)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def verify_secret(secret: str, secret_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), secret_hash or '')


def _generate_secret() -> str:
    return _SECRET_PREFIX + secrets.token_urlsafe(_SECRET_BYTES)


def _generate_connector_id() -> str:
    # A random id rather than the Mongo ObjectId: ObjectIds embed a timestamp
    # and a monotonic counter, so they are partially predictable, and this value
    # is part of a semi-public webhook URL.
    return secrets.token_urlsafe(_CONNECTOR_ID_BYTES).replace('_', '-')


def _secret_hint(secret: str) -> str:
    """Short non-reversible display hint, e.g. 'soar_A1b2…' for the UI."""
    body = secret[len(_SECRET_PREFIX):] if secret.startswith(_SECRET_PREFIX) else secret
    return f'{_SECRET_PREFIX}{body[:4]}…'


def webhook_path(connector_id: str) -> str:
    return f'/ingest/webhook/{connector_id}'


def agent_path(connector_id: str) -> str:
    return f'/api/v1/agent/{connector_id}'


def transport_of(doc: dict[str, Any]) -> str:
    return str(doc.get('transport') or 'webhook').lower()


def _iso(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=UTC)).isoformat()
    return str(v)


def _public_pull_state(state: dict[str, Any] | None) -> dict[str, Any]:
    state = state or {}
    err = state.get('last_error') or None
    cursor = state.get('cursor') or {}
    return {
        'nextRunAt': _iso(state.get('next_run_at')),
        'lastRunAt': _iso(state.get('last_run_at')),
        'lastSuccessAt': _iso(state.get('last_success_at')),
        'consecutiveFailures': int(state.get('consecutive_failures') or 0),
        'running': bool(state.get('lease_owner')),
        'watermark': cursor.get('watermark') if isinstance(cursor, dict) else None,
        'lastRun': state.get('last_run') or None,
        'lastError': (
            {'kind': err.get('kind'), 'message': err.get('message'), 'at': _iso(err.get('at'))}
            if isinstance(err, dict) else None
        ),
    }


def _public_health(health: dict[str, Any] | None) -> dict[str, Any]:
    """Health block written by the log collector's monitor and reconciler."""
    health = health or {}
    status = health.get('status') or {}
    rec = health.get('reconciliation') or status.get('reconciliation') or {}
    q = status.get('quality_1h') or None
    return {
        # None = learned from history, 0 = off, n = minutes (configured).
        'silenceMinutes': health.get('silence_minutes'),
        'effectiveSilenceMinutes': status.get('silence_threshold_minutes'),
        'silenceThresholdSource': status.get('silence_threshold_source'),
        'checkedAt': _iso(status.get('checked_at')),
        'lastSeenAt': _iso(status.get('last_seen_at')),
        'openIncidents': list(status.get('open_incidents') or []),
        'quality1h': (
            {
                'total': int(q.get('total') or 0),
                'futureDated': int(q.get('future') or 0),
                'withoutTimestamp': int(q.get('no_time') or 0),
                'poor': int(q.get('poor') or 0),
                'incomplete': int(q.get('incomplete') or 0),
                'maxAheadSeconds': float(q.get('max_ahead_seconds') or 0),
                'meanLagSeconds': q.get('mean_lag_seconds'),
            }
            if q else None
        ),
        'reconciliation': (
            {
                'checkedAt': _iso(rec.get('checked_at')),
                'windowHours': rec.get('window_hours'),
                'received': int(rec.get('received') or 0),
                'accounted': int(rec.get('accounted') or 0),
                'open': int(rec.get('open') or 0),
                'lost': int(rec.get('lost') or 0),
                'replayed': int(rec.get('replayed') or 0),
                'edgeDroppedTotal': int(rec.get('edge_dropped_total') or 0),
                'byStatus': {str(k): int(v) for k, v in (rec.get('by_status') or {}).items()},
            }
            if rec else None
        ),
    }


_TZ_OFFSET_RE = re.compile(r'^(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?$', re.IGNORECASE)


def clean_time_zone(value: str | None) -> str | None:
    """Validate a connector time zone: IANA name or fixed offset. '' clears it.

    Mirrors backend/services/ingestion/source_time.resolve_timezone, which is
    what actually applies it (the two run in separate images).
    """
    s = (value or '').strip()
    if not s:
        return None
    if s.upper() in ('UTC', 'GMT', 'Z'):
        return 'UTC'
    m = _TZ_OFFSET_RE.match(s)
    if m:
        hh, mm = int(m.group(2)), int(m.group(3) or 0)
        if hh > 14 or mm > 59:
            raise SiemIntegrationError(f'{s!r} is not a valid UTC offset.')
        return f'{m.group(1)}{hh:02d}:{mm:02d}'
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(s)
    except Exception as exc:
        raise SiemIntegrationError(
            f'Unknown time zone {s!r}. Use an IANA name such as "Asia/Kolkata" or an offset such as "+05:30".'
        ) from exc
    return s


def clean_silence_minutes(value: int | None) -> int | None:
    """-1 / None = learn from history, 0 = off, 5..10080 = explicit minutes."""
    if value is None or int(value) < 0:
        return None
    n = int(value)
    if n == 0:
        return 0
    if not 5 <= n <= 10_080:
        raise SiemIntegrationError('Silence threshold must be between 5 minutes and 7 days (or 0 to turn it off).')
    return n


def _public(doc: dict[str, Any], *, base_url: str) -> dict[str, Any]:
    """Registry document -> API shape. Never includes secrets or their hashes."""
    cid = doc['connector_id']
    transport = transport_of(doc)
    base = base_url.rstrip('/')
    out: dict[str, Any] = {
        'connectorId': cid,
        'vendor': doc.get('vendor'),
        'vendorLabel': vendor_label(doc.get('vendor', '')),
        'name': doc.get('name'),
        'transport': transport,
        'authMode': doc.get('auth_mode'),
        'enabled': bool(doc.get('enabled', True)),
        'webhookUrl': f'{base}{webhook_path(cid)}' if transport == 'webhook' else None,
        'agentEndpoint': f'{base}{agent_path(cid)}' if transport == 'agent' else None,
        'secretHint': doc.get('secret_hint'),
        'allowedCnPattern': doc.get('allowed_cn_pattern'),
        'createdAt': _iso(doc.get('created_at')),
        'createdBy': doc.get('created_by'),
        'lastSeenAt': _iso(doc.get('last_seen_at')),
        'alertsReceived': int(doc.get('alerts_received', 0) or 0),
        # killchain: raw lines appended to data/ingest/live.log, records that
        # carried no raw line, and re-sent records skipped by the sink.
        'linesForwarded': int(doc.get('lines_forwarded', 0) or 0),
        'notAnalysable': int(doc.get('not_analysable', 0) or 0),
        'duplicates': int(doc.get('duplicates', 0) or 0),
        'secretRotatedAt': _iso(doc.get('secret_rotated_at')),
        'pull': None,
        'pullState': None,
        'syslog': None,
        'timeZone': doc.get('time_zone'),
        'health': _public_health(doc.get('health')),
    }
    if transport == 'api_pull':
        pull = doc.get('pull') or {}
        out['pull'] = {
            'client': pull.get('client'),
            'config': pull.get('config') or {},
            'intervalSeconds': int(pull.get('interval_seconds') or 0),
            'credentialHint': pull.get('credential_hint'),
            'credentialsUpdatedAt': _iso(pull.get('credentials_updated_at')),
        }
        out['pullState'] = _public_pull_state(doc.get('pull_state'))
    if transport == 'syslog':
        syslog = doc.get('syslog') or {}
        state = doc.get('syslog_state') or {}
        out['syslog'] = {
            'allowedSources': list(syslog.get('allowed_sources') or []),
            'lastMessageAt': _iso(state.get('last_message_at')),
            'lastSenderIp': state.get('last_sender_ip'),
        }
    return out


def _clean_name(name: str) -> str:
    n = (name or '').strip()
    if not n:
        raise SiemIntegrationError('Connection name is required.')
    if len(n) > _NAME_MAX:
        raise SiemIntegrationError(f'Connection name must be {_NAME_MAX} characters or fewer.')
    return n


def _validate_cn_pattern(pattern: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise SiemIntegrationError(f'Invalid CN pattern: {exc}') from exc


# ── API pull validation ──────────────────────────────────────────────────────

def _validate_url(value: str, label: str) -> str:
    url = value.strip()
    parts = urlsplit(url)
    schemes = ('https', 'http') if collector_allow_http() else ('https',)
    if parts.scheme not in schemes or not parts.hostname:
        raise SiemIntegrationError(f'{label} must be a full https:// URL.')
    if parts.username or parts.password:
        raise SiemIntegrationError(f'{label} must not contain credentials; use the credential fields.')
    return url.rstrip('/') if parts.path in ('', '/') else url


def _coerce_field(field: dict[str, Any], raw: Any) -> Any:
    key, label, ftype = field['key'], field.get('label', field['key']), field.get('type', 'text')
    if ftype == 'url':
        return _validate_url(str(raw), label)
    if ftype == 'number':
        try:
            n = int(raw)
        except (TypeError, ValueError) as exc:
            raise SiemIntegrationError(f'{label} must be a whole number.') from exc
        bounds = {'page_size': (1, 500), 'initial_lookback_minutes': (1, 43_200)}.get(key, (0, 1_000_000))
        if not bounds[0] <= n <= bounds[1]:
            raise SiemIntegrationError(f'{label} must be between {bounds[0]} and {bounds[1]}.')
        return n
    if ftype == 'boolean':
        if isinstance(raw, str):
            return raw.strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(raw)
    if ftype == 'select':
        allowed = [o['value'] for o in field.get('options', [])]
        if raw not in allowed:
            raise SiemIntegrationError(f'{label} must be one of: {", ".join(map(str, allowed))}.')
        return raw
    if ftype == 'json':
        val = raw
        if isinstance(raw, str):
            if not raw.strip():
                return None
            try:
                val = json.loads(raw)
            except ValueError as exc:
                raise SiemIntegrationError(f'{label} is not valid JSON.') from exc
        if not isinstance(val, dict):
            raise SiemIntegrationError(f'{label} must be a JSON object.')
        if len(json.dumps(val)) > _MAX_JSON_FIELD:
            raise SiemIntegrationError(f'{label} is too large.')
        return val
    text = str(raw).strip()
    if len(text) > 500:
        raise SiemIntegrationError(f'{label} is too long.')
    return text


def validate_pull_config(vendor: str, config_in: dict[str, Any] | None) -> dict[str, Any]:
    spec = pull_spec(vendor)
    if not spec:
        raise SiemIntegrationError(f'{vendor_label(vendor)} does not support API pull.')
    config_in = config_in or {}
    out: dict[str, Any] = {}
    for field in spec['config_fields']:
        key = field['key']
        raw = config_in.get(key)
        empty = raw is None or (isinstance(raw, str) and raw.strip() == '' and not field.get('allow_empty'))
        if empty:
            if 'default' in field:
                out[key] = field['default']
            elif field.get('required'):
                raise SiemIntegrationError(f'{field.get("label", key)} is required.')
            continue
        value = _coerce_field(field, raw)
        if value is not None:
            out[key] = value

    if spec['client'] == 'generic_rest':
        if out.get('auth_type') == 'header' and not out.get('auth_header'):
            raise SiemIntegrationError('API key header name is required for "API key header" authentication.')
        if out.get('pagination') == 'cursor' and not (out.get('cursor_path') and out.get('cursor_param')):
            raise SiemIntegrationError('Cursor pagination needs the next-cursor path and cursor parameter.')
    return out


def _required_credentials(spec: dict[str, Any], config: dict[str, Any]) -> list[str]:
    if spec['client'] == 'generic_rest':
        return {
            'bearer': ['token'], 'header': ['token'],
            'basic': ['username', 'password'], 'none': [],
        }.get(str(config.get('auth_type') or 'bearer'), [])
    return [f['key'] for f in spec['credential_fields'] if f.get('required')]


def validate_pull_credentials(
    vendor: str,
    config: dict[str, Any],
    creds_in: dict[str, Any] | None,
    existing: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Merge supplied credential fields over `existing`, then check completeness.

    Blank fields in `creds_in` mean "keep the stored value", so an operator can
    change one field without re-typing the others.
    """
    spec = pull_spec(vendor) or {}
    allowed = {f['key'] for f in spec.get('credential_fields', [])}
    merged: dict[str, str] = {k: str(v) for k, v in (existing or {}).items() if k in allowed and v}
    for key, value in (creds_in or {}).items():
        if key not in allowed or value is None:
            continue
        s = str(value).strip()
        if not s:
            continue
        if len(s) > _MAX_CRED_LEN:
            raise SiemIntegrationError(f'Credential {key!r} is too long.')
        merged[key] = s
    missing = [k for k in _required_credentials(spec, config) if not merged.get(k)]
    if missing:
        labels = {f['key']: f.get('label', f['key']) for f in spec.get('credential_fields', [])}
        raise SiemIntegrationError('Missing credentials: ' + ', '.join(labels.get(k, k) for k in missing) + '.')
    return merged


def _clean_interval(value: Any, vendor: str) -> int:
    spec = pull_spec(vendor) or {}
    if value in (None, ''):
        return int(spec.get('default_interval_seconds') or 300)
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise SiemIntegrationError('Poll interval must be a whole number of seconds.') from exc
    if not _MIN_INTERVAL <= n <= _MAX_INTERVAL:
        raise SiemIntegrationError(f'Poll interval must be between {_MIN_INTERVAL} and {_MAX_INTERVAL} seconds.')
    return n


def _encrypt_or_fail(values: dict[str, str]) -> str:
    try:
        return cred_store.encrypt(values)
    except cred_store.CredentialConfigError as exc:
        raise SiemIntegrationError(str(exc)) from exc


# ── Syslog validation ────────────────────────────────────────────────────────

def normalise_sources(sources: list[str] | None) -> list[str]:
    out: list[str] = []
    for raw in sources or []:
        s = str(raw).strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise SiemIntegrationError(f'{s!r} is not a valid IP address or CIDR range.') from exc
        if net.prefixlen == 0:
            raise SiemIntegrationError(
                f'{s} would accept syslog from any address. List the specific sender '
                'addresses or ranges instead.'
            )
        if str(net) not in out:
            out.append(str(net))
    if len(out) > _MAX_SOURCES:
        raise SiemIntegrationError(f'At most {_MAX_SOURCES} source ranges per connection.')
    return out


async def _check_source_overlap(
    db: ConnectorStore, sources: list[str], *, exclude_id: str | None = None
) -> None:
    """Reject a range that another syslog connection already claims exactly --
    the listener could not tell which connection a message belongs to."""
    if not sources:
        return
    query: dict[str, Any] = {'transport': 'syslog', 'syslog.allowed_sources': {'$in': sources}}
    if exclude_id:
        query['connector_id'] = {'$ne': exclude_id}
    clash = db.find_one(query)
    if clash:
        taken = sorted(set(sources) & set((clash.get('syslog') or {}).get('allowed_sources') or []))
        raise SiemIntegrationError(
            f'{", ".join(taken)} is already assigned to the connection "{clash.get("name")}".'
        )


# ── CRUD ─────────────────────────────────────────────────────────────────────

def _created_key(d: dict[str, Any]) -> str:
    return _iso(d.get('created_at')) or ''


async def list_integrations(
    db: ConnectorStore, *, base_url: str
) -> list[dict[str, Any]]:
    docs = sorted(db.find({}), key=_created_key, reverse=True)
    return [_public(d, base_url=base_url) for d in docs]


async def get_integration(
    db: ConnectorStore, connector_id: str, *, base_url: str
) -> dict[str, Any] | None:
    doc = db.find_one({'connector_id': connector_id})
    return _public(doc, base_url=base_url) if doc else None


async def create_integration(
    db: ConnectorStore,
    *,
    vendor: str,
    name: str,
    auth_mode: str | None,
    allowed_cn_pattern: str | None,
    created_by: str | None,
    base_url: str,
    transport: str | None = None,
    pull_config: dict[str, Any] | None = None,
    pull_interval_seconds: int | None = None,
    credentials: dict[str, Any] | None = None,
    allowed_sources: list[str] | None = None,
    time_zone: str | None = None,
    silence_minutes: int | None = None,
) -> dict[str, Any]:
    """Create a connector. Returns the public shape plus a one-time `secret`
    (webhook/agent connectors using bearer or hmac; None otherwise)."""
    vendor = (vendor or '').strip().lower()
    spec = get_vendor(vendor)
    if spec is None:
        raise SiemIntegrationError(f'Unknown log source: {vendor!r}')

    transport = (transport or 'webhook').strip().lower()
    if transport not in TRANSPORTS:
        raise SiemIntegrationError(f'Unsupported transport: {transport!r}')
    if transport not in vendor_transports(vendor):
        raise SiemIntegrationError(
            f'{spec["label"]} does not support {transport.replace("_", " ")}. '
            f'Supported: {", ".join(vendor_transports(vendor))}.'
        )

    name = _clean_name(name)
    auth_mode = (auth_mode or default_auth_mode(vendor, transport)).strip().lower()
    allowed_modes = auth_modes_for(vendor, transport)
    if auth_mode not in allowed_modes:
        raise SiemIntegrationError(
            f'{spec["label"]} ({transport.replace("_", " ")}) cannot use {auth_mode} '
            f'authentication. Supported: {", ".join(allowed_modes)}.'
        )

    if db.find_one({'vendor': vendor, 'name': name}):
        raise SiemIntegrationError(
            f'A {spec["label"]} connection named {name!r} already exists.'
        )

    now = _now()
    doc: dict[str, Any] = {
        'connector_id': _generate_connector_id(),
        'vendor': vendor,
        'name': name,
        'transport': transport,
        'auth_mode': auth_mode,
        'enabled': True,
        'created_at': now,
        'created_by': created_by,
        'updated_at': now,
        'last_seen_at': None,
        'alerts_received': 0,
        'lines_forwarded': 0,
        'not_analysable': 0,
        'duplicates': 0,
        'secret_hash': None,
        'secret_hint': None,
        'secret_rotated_at': None,
        'allowed_cn_pattern': None,
        # Zone for the source's offset-less timestamps; None = UTC.
        'time_zone': clean_time_zone(time_zone),
        'health': {'silence_minutes': clean_silence_minutes(silence_minutes)},
    }

    secret: str | None = None
    if transport in ('webhook', 'agent') and auth_mode in ('bearer', 'hmac'):
        secret = _generate_secret()
        doc['secret_hash'] = hash_secret(secret)
        doc['secret_hint'] = _secret_hint(secret)
        doc['secret_rotated_at'] = now
    if auth_mode == 'mtls':
        # Authenticated by client certificate CN instead of a secret. Default to
        # the vendor id so a fresh connector is not accidentally wide open (an
        # empty pattern is rejected at ingest).
        pattern = (allowed_cn_pattern or '').strip() or f'{vendor}.*'
        _validate_cn_pattern(pattern)
        doc['allowed_cn_pattern'] = pattern

    if transport == 'api_pull':
        config = validate_pull_config(vendor, pull_config)
        creds = validate_pull_credentials(vendor, config, credentials)
        doc['pull'] = {
            'client': pull_spec(vendor)['client'],
            'config': config,
            'interval_seconds': _clean_interval(pull_interval_seconds, vendor),
            'credentials_enc': _encrypt_or_fail(creds),
            'credential_hint': cred_store.hint(creds),
            'credentials_updated_at': now,
        }
        # Due immediately: the first poll runs on the collector's next tick.
        doc['pull_state'] = {'next_run_at': now, 'cursor': None}

    if transport == 'syslog':
        sources = normalise_sources(allowed_sources)
        if auth_mode == 'source_ip' and not sources:
            raise SiemIntegrationError('Add at least one sender address or CIDR range.')
        await _check_source_overlap(db, sources)
        doc['syslog'] = {'allowed_sources': sources}

    db.insert_one(doc)
    invalidate_cache(doc['connector_id'])

    out = _public(doc, base_url=base_url)
    # Returned once, at creation time only. There is no way to read it back.
    out['secret'] = secret
    return out


async def update_integration(
    db: ConnectorStore,
    connector_id: str,
    *,
    name: str | None = None,
    enabled: bool | None = None,
    allowed_cn_pattern: str | None = None,
    base_url: str,
    pull_config: dict[str, Any] | None = None,
    pull_interval_seconds: int | None = None,
    credentials: dict[str, Any] | None = None,
    allowed_sources: list[str] | None = None,
    time_zone: str | None = None,
    silence_minutes: int | None = None,
) -> dict[str, Any]:
    """Partial update. `time_zone=''` clears the zone (UTC); `silence_minutes`
    -1 returns to the learned threshold, 0 turns silence alerting off."""
    doc = db.find_one({'connector_id': connector_id})
    if not doc:
        raise SiemIntegrationError('Connection not found.')

    transport = transport_of(doc)
    vendor = str(doc.get('vendor') or '')
    update: dict[str, Any] = {}

    if time_zone is not None:
        update['time_zone'] = clean_time_zone(time_zone)
    if silence_minutes is not None:
        update['health.silence_minutes'] = clean_silence_minutes(silence_minutes)

    if name is not None:
        new_name = _clean_name(name)
        if new_name != doc.get('name'):
            clash = db.find_one(
                {
                    'vendor': doc.get('vendor'),
                    'name': new_name,
                    'connector_id': {'$ne': connector_id},
                }
            )
            if clash:
                raise SiemIntegrationError(
                    f'A {vendor_label(vendor)} connection named '
                    f'{new_name!r} already exists.'
                )
        update['name'] = new_name

    if enabled is not None:
        update['enabled'] = bool(enabled)
        if enabled and transport == 'api_pull':
            update['pull_state.next_run_at'] = _now()

    if allowed_cn_pattern is not None:
        if doc.get('auth_mode') != 'mtls':
            raise SiemIntegrationError(
                'CN pattern only applies to connections using certificate authentication.'
            )
        pattern = allowed_cn_pattern.strip()
        if not pattern:
            raise SiemIntegrationError('CN pattern cannot be empty.')
        _validate_cn_pattern(pattern)
        update['allowed_cn_pattern'] = pattern

    if pull_config is not None or pull_interval_seconds is not None or credentials is not None:
        if transport != 'api_pull':
            raise SiemIntegrationError('Poll settings only apply to API pull connections.')
        pull = doc.get('pull') or {}
        config = pull.get('config') or {}
        if pull_config is not None:
            new_config = validate_pull_config(vendor, pull_config)
            if new_config != config:
                update['pull.config'] = new_config
                # A different endpoint/resource/filter is a different stream:
                # restart from the initial lookback. Re-reads are deduplicated.
                update['pull_state.cursor'] = None
            config = new_config
        if pull_interval_seconds is not None:
            update['pull.interval_seconds'] = _clean_interval(pull_interval_seconds, vendor)
        if credentials is not None or pull_config is not None:
            try:
                existing = cred_store.decrypt(pull.get('credentials_enc'))
            except cred_store.CredentialConfigError:
                existing = {}  # key changed: the operator must re-enter everything
            creds = validate_pull_credentials(vendor, config, credentials, existing)
            if creds != existing:
                update['pull.credentials_enc'] = _encrypt_or_fail(creds)
                update['pull.credential_hint'] = cred_store.hint(creds)
                update['pull.credentials_updated_at'] = _now()
        update['pull_state.next_run_at'] = _now()
        update['pull_state.consecutive_failures'] = 0

    if allowed_sources is not None:
        if transport != 'syslog':
            raise SiemIntegrationError('Sender addresses only apply to syslog connections.')
        sources = normalise_sources(allowed_sources)
        if doc.get('auth_mode') == 'source_ip' and not sources:
            raise SiemIntegrationError('Add at least one sender address or CIDR range.')
        await _check_source_overlap(db, sources, exclude_id=connector_id)
        update['syslog.allowed_sources'] = sources

    if not update:
        return _public(doc, base_url=base_url)

    update['updated_at'] = _now()
    db.update_one({'connector_id': connector_id}, {'$set': update})
    invalidate_cache(connector_id)
    fresh = db.find_one({'connector_id': connector_id})
    return _public(fresh or doc, base_url=base_url)


async def rotate_secret(
    db: ConnectorStore, connector_id: str, *, base_url: str
) -> dict[str, Any]:
    """Issue a new secret, invalidating the previous one immediately.

    There is no grace period where both secrets work, so the sender will be
    rejected until it is updated with the new value. That is intentional -- a
    rotation that leaves the old credential live is not a rotation.
    """
    doc = db.find_one({'connector_id': connector_id})
    if not doc:
        raise SiemIntegrationError('Connection not found.')
    transport = transport_of(doc)
    if transport == 'api_pull':
        raise SiemIntegrationError(
            'API pull connections have no platform secret. Update the vendor '
            'credentials instead.'
        )
    if transport == 'syslog':
        raise SiemIntegrationError(
            'Syslog connections are authenticated by sender address or certificate, not a secret.'
        )
    if doc.get('auth_mode') not in ('bearer', 'hmac'):
        raise SiemIntegrationError(
            'This connection authenticates with a client certificate, not a secret. '
            'Reissue the certificate from the Certificates tab instead.'
        )

    secret = _generate_secret()
    update = {
        'secret_hash': hash_secret(secret),
        'secret_hint': _secret_hint(secret),
        'secret_rotated_at': _now(),
        'updated_at': _now(),
    }
    db.update_one({'connector_id': connector_id}, {'$set': update})
    invalidate_cache(connector_id)
    doc.update(update)

    out = _public(doc, base_url=base_url)
    out['secret'] = secret
    return out


async def poll_now(db: ConnectorStore, connector_id: str, *, base_url: str) -> dict[str, Any]:
    """Make an API-pull connector due immediately (picked up on the next tick)."""
    doc = db.find_one({'connector_id': connector_id})
    if not doc:
        raise SiemIntegrationError('Connection not found.')
    if transport_of(doc) != 'api_pull':
        raise SiemIntegrationError('Only API pull connections can be polled.')
    if not doc.get('enabled', True):
        raise SiemIntegrationError('Enable the connection before polling it.')
    db.update_one(
        {'connector_id': connector_id},
        {'$set': {'pull_state.next_run_at': _now()}},
    )
    fresh = db.find_one({'connector_id': connector_id})
    return _public(fresh or doc, base_url=base_url)


async def list_agents(db: ConnectorStore, connector_id: str) -> list[dict[str, Any]]:
    """Forwarding agents that sent a heartbeat. killchain has no agent endpoint: always []."""
    return []


async def list_unmatched_syslog_sources(db: ConnectorStore, limit: int = 50) -> list[dict[str, Any]]:
    """Syslog senders that matched no connection (kept in memory by the listener)."""
    try:
        from .syslog_server import unmatched_sources
    except ImportError:
        return []
    return unmatched_sources(limit)


async def delete_integration(db: ConnectorStore, connector_id: str) -> None:
    deleted = db.delete_one({'connector_id': connector_id})
    invalidate_cache(connector_id)
    if deleted == 0:
        raise SiemIntegrationError('Connection not found.')


def ingest_endpoints(base_url: str) -> dict[str, Any]:
    """Global addresses shown in Settings for transports that are not per-URL."""
    s = CollectorSettings()
    host = (os.getenv('SYSLOG_PUBLIC_HOST') or '').strip() or (urlsplit(base_url).hostname or 'localhost')
    return {
        'baseUrl': base_url.rstrip('/'),
        'syslog': {
            'host': host,
            'udpPort': int(os.getenv('SYSLOG_PUBLIC_UDP_PORT') or s.syslog_udp_port),
            'tcpPort': int(os.getenv('SYSLOG_PUBLIC_TCP_PORT') or s.syslog_tcp_port),
            'tlsPort': None,          # no TLS syslog listener in killchain
            'tlsEnabled': False,
            # killchain addition: the listener only runs with KILLCHAIN_SYSLOG=1.
            'enabled': syslog_enabled(),
        },
        'credentialsKeyConfigured': cred_store.is_configured(),
    }


def _observed_status(item: dict[str, Any]) -> str:
    """killchain: 'active' when the connector delivered within the last 24 h."""
    last = item.get('lastSeenAt')
    if not last:
        return 'inactive'
    try:
        seen = datetime.fromisoformat(str(last))
    except ValueError:
        return 'inactive'
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return 'active' if (_now() - seen).total_seconds() < 86_400 else 'inactive'


async def merge_with_observed_sources(
    integrations: list[dict[str, Any]],
    observed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach live ingest stats to configured connectors, and keep unregistered
    sources visible.

    Sources observed in `alerts_processed` that have no registry entry are
    retained as read-only rows. Wazuh alerts ingested before this feature
    existed (and anything sent through the generic `/api/v1/ingest` path) would
    otherwise vanish from the Settings page, which would look like data loss.

    killchain: there is no alerts_processed collection, so `observed` is empty
    and a connector's own counters fill the observed fields.
    """
    by_vendor: dict[str, dict[str, Any]] = {}
    for row in observed:
        key = str(row.get('name', '')).strip().lower()
        if key:
            by_vendor[key] = row

    out: list[dict[str, Any]] = []
    claimed: set[str] = set()

    for item in integrations:
        vendor = str(item.get('vendor', '')).lower()
        stats = by_vendor.get(vendor)
        if stats:
            claimed.add(vendor)
        out.append(
            {
                **item,
                'registered': True,
                'observedStatus': (stats or {}).get('status', _observed_status(item)),
                'alertsToday': (stats or {}).get('alertsToday', 0),
                'totalAlerts': (stats or {}).get('totalAlerts', item.get('alertsReceived', 0)),
                'lastIngestAt': (stats or {}).get('lastIngestAt') or item.get('lastSeenAt'),
            }
        )

    for row in observed:
        key = str(row.get('name', '')).strip().lower()
        if key in claimed:
            continue
        out.append(
            {
                'connectorId': None,
                'vendor': None,
                'vendorLabel': row.get('name'),
                'name': row.get('name'),
                'transport': None,
                'timeZone': None,
                'health': None,
                'authMode': None,
                'enabled': True,
                'webhookUrl': None,
                'agentEndpoint': None,
                'secretHint': None,
                'pull': None,
                'pullState': None,
                'syslog': None,
                'registered': False,
                'sourceKind': row.get('sourceKind', 'unknown'),
                'observedStatus': row.get('status', 'inactive'),
                'alertsToday': row.get('alertsToday', 0),
                'totalAlerts': row.get('totalAlerts', 0),
                'lastIngestAt': row.get('lastIngestAt'),
            }
        )

    return out
