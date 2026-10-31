# Copied from AI-SOC: web_app/backend/app/services/siem_vendors.py
# killchain changes: webhook path is /ingest/webhook/{id}; only the transports
# this app implements are offered (webhook, api_pull, and syslog when
# KILLCHAIN_SYSLOG=1); mTLS auth and the agent transport are not offered (no
# client certificates or forwarding agent here); a FortiGate entry is added.
"""Catalog of supported log sources for Settings -> SIEM Integrations.

This is a declarative table, not code. Adding a new log source means adding an
entry here (plus, optionally, a structural fingerprint in the normalisation
agent's `schema_inspector.py` so `siem_source` is attributed automatically).

Transports
----------
Each vendor lists the transports it can realistically use:

  webhook   The source POSTs JSON to `/ingest/webhook/{connector_id}`
            (killchain: connectors/webhook.py). Authenticated per connector
            (bearer/hmac).
  api_pull  The platform's log collector polls the vendor's API on a schedule
            with credentials stored encrypted on the connector (see
            `connector_credentials.py`). `pull.client` names the collector
            client in `backend/services/collectors/pull_clients.py`.
  syslog    The source sends RFC 5424/3164 syslog (plain, CEF, LEEF or JSON) to
            the collector's UDP/TCP/TLS listener. Attributed by source address
            (allow-listed CIDRs) or, on TLS, by client-certificate CN.
  agent     The first-party forwarding agent (`agent/soar_agent.py`) runs next
            to the source, tails its files / receives its local syslog, and
            forwards over HTTPS to `/api/v1/agent/{connector_id}/...`.

Why there are no vendor-specific webhook signature schemes
----------------------------------------------------------
Each SIEM signs outbound webhooks differently (or not at all), and several of
the products below do not publish a stable signing spec. Rather than ship
per-vendor verification code that cannot be tested against the real sender, the
platform offers three transport-agnostic auth modes that every one of these
products can actually satisfy:

  bearer  Static high-entropy token in a request header.
  hmac    HMAC-SHA256 of the raw request body, sent as `X-SOAR-Signature`.
  mtls    Client certificate, verified at the TLS layer by the ingest proxy and
          again at the application layer against a per-connector CN pattern.

Because the normalisation agent is schema-agnostic (it classifies to OCSF from
whatever fields are present), the payload *shape* each vendor sends does not
need to be declared here.
"""

from __future__ import annotations

from typing import Any

# Webhook/agent auth modes, in descending order of strength.
AUTH_MODES: tuple[str, ...] = ('mtls', 'hmac', 'bearer')

TRANSPORTS: tuple[str, ...] = ('webhook', 'api_pull', 'syslog', 'agent')

# Auth modes valid per transport. `api` is a marker for API-pull connectors:
# they present nothing to the platform, the platform presents credentials to
# the vendor. `source_ip` authenticates syslog by allow-listed sender address.
TRANSPORT_AUTH_MODES: dict[str, tuple[str, ...]] = {
    'webhook': AUTH_MODES,
    'agent': ('hmac', 'bearer', 'mtls'),
    'api_pull': ('api',),
    'syslog': ('source_ip', 'mtls'),
}
TRANSPORT_DEFAULT_AUTH: dict[str, str] = {
    'agent': 'hmac',
    'api_pull': 'api',
    'syslog': 'source_ip',
}

# Envelope keys unwrapped when a sender batches several alerts into one POST.
# Kept in sync with backend/services/ingestion/raw_ingest.py.
BATCH_ENVELOPE_KEYS: tuple[str, ...] = (
    'alerts',
    'events',
    'records',
    'messages',
    'data',
    'items',
    'results',
)

_GENERIC_STEPS = [
    'Copy the webhook URL and secret shown after you create the connector.',
    'In your log source, create an outbound webhook / HTTP notification that '
    'POSTs JSON to that URL.',
    'Add the secret as the request header shown alongside the URL.',
    'Trigger a test alert and confirm it appears in the Alerts page.',
]

_SYSLOG_STEPS = [
    'Allow-list the address(es) your source sends from (use the NAT/egress '
    'address if it is behind a firewall).',
    'Point the source\'s syslog output at the host and port shown for this '
    'connection. TCP is preferred over UDP -- UDP silently drops under load.',
    'CEF, LEEF, RFC 5424, RFC 3164 and JSON-over-syslog are all decoded '
    'automatically; no format needs to be selected.',
    'Send a test event and confirm the connection\'s counters increase. Senders '
    'that match no connection are listed under "Unrecognised syslog senders".',
]

_AGENT_STEPS = [
    'Copy the agent configuration shown after creation (it contains the secret, '
    'which is shown only once) to agent.json on a host that can read the '
    'source\'s logs or receive its syslog.',
    'Copy agent/soar_agent.py from the platform repository to that host '
    '(Python 3.8+, no dependencies).',
    'Edit the "inputs" list: file paths to tail and/or a local syslog listener.',
    'Run: python soar_agent.py --config agent.json --test, then run it without '
    '--test as a service (systemd, NSSM on Windows).',
    'The agent appears under this connection once its first heartbeat arrives.',
]

# ── API pull specs (rendered as the form in Settings) ────────────────────────
# Field types: url | text | number | select | boolean | json | password

_LOOKBACK_FIELD = {
    'key': 'initial_lookback_minutes', 'label': 'Initial lookback (minutes)',
    'type': 'number', 'required': False, 'default': 60,
    'help': 'How far back the first poll reaches. Later polls continue from the last item seen.',
}
_PAGE_SIZE_FIELD = {
    'key': 'page_size', 'label': 'Page size', 'type': 'number',
    'required': False, 'default': 100, 'help': 'Items per API request (max 500).',
}

_PULL_SENTINELONE = {
    'client': 'sentinelone',
    'default_interval_seconds': 300,
    'docs_url': 'https://usea1-partners.sentinelone.net/api-doc/overview',
    'config_fields': [
        {'key': 'base_url', 'label': 'Management console URL', 'type': 'url', 'required': True,
         'placeholder': 'https://usea1-acme.sentinelone.net'},
        {'key': 'resource', 'label': 'Collect', 'type': 'select', 'required': True, 'default': 'threats',
         'options': [{'value': 'threats', 'label': 'Threats'},
                     {'value': 'alerts', 'label': 'Cloud detection (STAR) alerts'}]},
        {'key': 'site_ids', 'label': 'Site IDs (optional)', 'type': 'text', 'required': False,
         'placeholder': 'comma separated', 'help': 'Limit collection to these sites.'},
        {'key': 'account_ids', 'label': 'Account IDs (optional)', 'type': 'text', 'required': False,
         'placeholder': 'comma separated'},
        _PAGE_SIZE_FIELD,
        _LOOKBACK_FIELD,
    ],
    'credential_fields': [
        {'key': 'api_token', 'label': 'API token', 'required': True,
         'help': 'Service user token with Viewer access to the scope being collected.'},
    ],
    'setup_steps': [
        'In the SentinelOne console, create a Service User (Settings > Users > Service Users) '
        'with the Viewer role on the account/site to collect.',
        'Generate an API token for it and paste it below.',
        'Use your console URL as the base URL (the address you log in to).',
    ],
}

_PULL_SUMOLOGIC = {
    'client': 'sumologic',
    'default_interval_seconds': 300,
    'docs_url': 'https://help.sumologic.com/docs/api/cloud-siem-enterprise/',
    'config_fields': [
        {'key': 'base_url', 'label': 'API endpoint', 'type': 'url', 'required': True,
         'placeholder': 'https://api.us2.sumologic.com/api',
         'help': 'The API endpoint for your deployment, including /api.'},
        {'key': 'resource', 'label': 'Collect', 'type': 'select', 'required': True, 'default': 'signals',
         'options': [{'value': 'signals', 'label': 'Cloud SIEM signals'},
                     {'value': 'insights', 'label': 'Cloud SIEM insights'}]},
        {'key': 'query', 'label': 'Extra filter (optional)', 'type': 'text', 'required': False,
         'placeholder': 'severity:>=5', 'help': 'Cloud SIEM query DSL, combined with the time filter.'},
        {'key': 'exclude_records', 'label': 'Omit raw records from signals', 'type': 'boolean',
         'required': False, 'default': False,
         'help': 'Signals can carry large record arrays; omit them to reduce volume.'},
        _PAGE_SIZE_FIELD,
        _LOOKBACK_FIELD,
    ],
    'credential_fields': [
        {'key': 'access_id', 'label': 'Access ID', 'required': True},
        {'key': 'access_key', 'label': 'Access key', 'required': True},
    ],
    'setup_steps': [
        'In Sumo Logic, create an access key (Administration > Security > Access Keys) '
        'for a user or service account that can read Cloud SIEM.',
        'Enter the API endpoint for your deployment region.',
    ],
}

_PULL_USM = {
    'client': 'usm_anywhere',
    'default_interval_seconds': 300,
    'docs_url': 'https://cybersecurity.att.com/documentation/api/usm-anywhere-apis.htm',
    'config_fields': [
        {'key': 'base_url', 'label': 'USM Anywhere URL', 'type': 'url', 'required': True,
         'placeholder': 'https://acme.alienvault.cloud'},
        {'key': 'exclude_suppressed', 'label': 'Skip suppressed alarms', 'type': 'boolean',
         'required': False, 'default': True},
        _PAGE_SIZE_FIELD,
        _LOOKBACK_FIELD,
    ],
    'credential_fields': [
        {'key': 'client_id', 'label': 'API client ID', 'required': True},
        {'key': 'client_secret', 'label': 'API client secret', 'required': True},
    ],
    'setup_steps': [
        'In USM Anywhere, go to Settings > API Clients and create a client.',
        'Paste its client ID and secret below. OSSIM / USM Appliance have no alarm API -- '
        'use the syslog or agent transport for those.',
    ],
}

_GENERIC_REST_FIELDS = [
    {'key': 'url', 'label': 'Endpoint URL', 'type': 'url', 'required': True,
     'placeholder': 'https://siem.example.com/api/v1/alerts'},
    {'key': 'method', 'label': 'Method', 'type': 'select', 'required': True, 'default': 'GET',
     'options': [{'value': 'GET', 'label': 'GET'}, {'value': 'POST', 'label': 'POST'}]},
    {'key': 'auth_type', 'label': 'Authentication', 'type': 'select', 'required': True, 'default': 'bearer',
     'options': [{'value': 'bearer', 'label': 'Bearer token'},
                 {'value': 'header', 'label': 'API key header'},
                 {'value': 'basic', 'label': 'Username / password'},
                 {'value': 'none', 'label': 'None'}]},
    {'key': 'auth_header', 'label': 'API key header name', 'type': 'text', 'required': False,
     'placeholder': 'X-API-Key', 'help': 'Only for "API key header".'},
    {'key': 'query_params', 'label': 'Query parameters (JSON)', 'type': 'json', 'required': False,
     'default': {'since': '{since}', 'limit': '{limit}'},
     'help': 'Placeholders: {since} {since_epoch} {since_epoch_ms} {limit} {cursor} {page} {offset}.'},
    {'key': 'body', 'label': 'Request body (JSON, POST only)', 'type': 'json', 'required': False},
    {'key': 'items_path', 'label': 'Items path', 'type': 'text', 'required': True, 'default': 'data',
     'allow_empty': True,
     'help': 'Dotted path to the list of alerts in the response. Leave empty if the response is the list.'},
    {'key': 'id_field', 'label': 'ID field', 'type': 'text', 'required': True, 'default': 'id'},
    {'key': 'timestamp_field', 'label': 'Timestamp field', 'type': 'text', 'required': False,
     'default': 'timestamp', 'help': 'Used to advance the {since} watermark. ISO 8601 or epoch.'},
    {'key': 'pagination', 'label': 'Pagination', 'type': 'select', 'required': True, 'default': 'none',
     'options': [{'value': 'none', 'label': 'None'}, {'value': 'cursor', 'label': 'Cursor'},
                 {'value': 'page', 'label': 'Page number'}, {'value': 'offset', 'label': 'Offset'}]},
    {'key': 'cursor_path', 'label': 'Next-cursor path', 'type': 'text', 'required': False,
     'placeholder': 'pagination.next', 'help': 'Cursor pagination only.'},
    {'key': 'cursor_param', 'label': 'Cursor parameter', 'type': 'text', 'required': False,
     'placeholder': 'cursor'},
    {'key': 'page_param', 'label': 'Page parameter', 'type': 'text', 'required': False, 'placeholder': 'page'},
    {'key': 'offset_param', 'label': 'Offset parameter', 'type': 'text', 'required': False,
     'placeholder': 'offset'},
    _PAGE_SIZE_FIELD,
    _LOOKBACK_FIELD,
]
_GENERIC_REST_CREDS = [
    {'key': 'token', 'label': 'Token / API key', 'required': False,
     'help': 'For bearer or API key header authentication.'},
    {'key': 'username', 'label': 'Username', 'required': False, 'secret': False},
    {'key': 'password', 'label': 'Password', 'required': False},
]


def _generic_rest(steps: list[str]) -> dict[str, Any]:
    return {
        'client': 'generic_rest',
        'default_interval_seconds': 300,
        'docs_url': None,
        'config_fields': _GENERIC_REST_FIELDS,
        'credential_fields': _GENERIC_REST_CREDS,
        'setup_steps': steps,
    }


VENDOR_CATALOG: list[dict[str, Any]] = [
    {
        'id': 'wazuh',
        'label': 'Wazuh',
        'kind': 'siem',
        'deployment': 'self-hosted',
        'transports': ['webhook', 'syslog', 'agent'],
        # Wazuh runs on infrastructure the customer controls, so it is the one
        # source that can realistically present a client certificate.
        'auth_modes': ['mtls', 'hmac', 'bearer'],
        'default_auth_mode': 'bearer',
        'docs_url': 'https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html',
        'setup_steps': [
            'On the Wazuh manager, add an <integration> block to '
            '/var/ossec/etc/ossec.conf (or install a custom integration script '
            'under /var/ossec/integrations/).',
            'Set hook_url to the webhook URL below.',
            'Pass the secret as the Authorization header from your integration '
            'script, or switch this connector to mTLS and use the client '
            'certificate issued from the Certificates tab.',
            'Restart wazuh-manager, then trigger a rule to confirm delivery.',
        ],
        'syslog_steps': [
            'In ossec.conf add a <syslog_output> block with <server> set to the '
            'syslog host below, <port> 514 and <format>json</format>.',
            'Run: /var/ossec/bin/wazuh-control enable client-syslog, then restart '
            'the manager.',
        ] + _SYSLOG_STEPS,
        'agent_steps': [
            'Install the agent on the Wazuh manager and tail '
            '/var/ossec/logs/alerts/alerts.json with format "json".',
        ] + _AGENT_STEPS,
    },
    {
        'id': 'sentinelone',
        'label': 'SentinelOne',
        'kind': 'edr',
        'deployment': 'saas',
        'transports': ['api_pull', 'webhook', 'syslog'],
        # SaaS sender: cannot present a client cert, so mTLS is not offered.
        'auth_modes': ['bearer'],
        'default_auth_mode': 'bearer',
        'docs_url': 'https://www.sentinelone.com/platform/',
        'setup_steps': [
            'In the SentinelOne management console, open the notification / '
            'webhook integration settings for your scope.',
            'Create an outbound webhook targeting the URL below with method POST '
            'and content type application/json.',
            'Add the secret as a custom request header using the header name '
            'shown with the URL.',
            'Save, then use the console\'s test action to send a sample event.',
        ],
        'syslog_steps': [
            'In the SentinelOne console open Settings > Integrations > Syslog, '
            'enter the syslog host and port below, and choose CEF formatting. '
            'SentinelOne sends syslog over TLS; use the TLS port.',
            'Enable the notification types to forward under Settings > Notifications.',
        ] + _SYSLOG_STEPS,
        'pull': _PULL_SENTINELONE,
    },
    {
        'id': 'sumologic',
        'label': 'Sumo Logic',
        'kind': 'siem',
        'deployment': 'saas',
        'transports': ['api_pull', 'webhook'],
        'auth_modes': ['bearer'],
        'default_auth_mode': 'bearer',
        'docs_url': 'https://help.sumologic.com/docs/alerts/webhook-connections/',
        'setup_steps': [
            'In Sumo Logic, create a Webhook Connection and set the URL to the '
            'value below.',
            'Add the secret as a custom header on the connection.',
            'Attach the connection to the monitors or scheduled searches whose '
            'signals you want forwarded.',
            'Use "Test Connection" to confirm delivery.',
        ],
        # Starter payload only. The pipeline accepts any JSON shape.
        'payload_template': (
            '{\n'
            '  "name": "{{Name}}",\n'
            '  "description": "{{Description}}",\n'
            '  "query": "{{SearchQuery}}",\n'
            '  "fire_time": "{{FireTime}}",\n'
            '  "results": {{AggregateResultsJson}}\n'
            '}'
        ),
        'pull': _PULL_SUMOLOGIC,
    },
    {
        'id': 'alienvault',
        'label': 'AlienVault (USM / OSSIM)',
        'kind': 'siem',
        'deployment': 'hybrid',
        'transports': ['api_pull', 'syslog', 'agent', 'webhook'],
        # USM Anywhere is SaaS; OSSIM is self-hosted and can do mTLS.
        'auth_modes': ['bearer', 'hmac', 'mtls'],
        'default_auth_mode': 'bearer',
        'docs_url': 'https://cybersecurity.att.com/documentation/usm-anywhere/',
        'setup_steps': [
            'USM Anywhere: create a response action / notification that POSTs to '
            'the URL below and add the secret as a custom header.',
            'OSSIM (self-hosted): forward via a script or action that curls the '
            'URL with the Authorization header, or switch this connector to mTLS.',
            'Trigger a matching event to confirm delivery.',
        ],
        'syslog_steps': [
            'OSSIM / USM Appliance: configure log forwarding (Configuration > '
            'Deployment > Components > Servers > Forward Logs) or an rsyslog '
            'rule that forwards to the syslog host and port below.',
            'USM Anywhere: create a syslog server notification pointing at the '
            'host below (use the TLS port where supported).',
        ] + _SYSLOG_STEPS,
        'agent_steps': [
            'OSSIM: install the agent on the OSSIM server and tail the alarm/SIEM '
            'event log files, or have rsyslog forward to the agent\'s local '
            'syslog input.',
        ] + _AGENT_STEPS,
        'pull': _PULL_USM,
    },
    {
        'id': 'cybolt',
        'label': 'Cybolt',
        'kind': 'siem',
        'deployment': 'hybrid',
        'transports': ['api_pull', 'syslog', 'agent', 'webhook'],
        'auth_modes': ['bearer', 'hmac', 'mtls'],
        'default_auth_mode': 'bearer',
        'docs_url': None,
        'setup_steps': _GENERIC_STEPS,
        'syslog_steps': [
            'In the Cybolt console, add a syslog / SIEM forwarding destination '
            'with the host and port below (CEF or JSON).',
        ] + _SYSLOG_STEPS,
        'agent_steps': _AGENT_STEPS,
        # Cybolt publishes no public alert-API specification, so it uses the
        # configurable REST client: fill in the endpoint, item path and fields
        # from the Cybolt API documentation supplied with your tenant.
        'pull': _generic_rest([
            'Obtain API access from Cybolt for your tenant (token or API key) and '
            'the alert/incident listing endpoint from their API documentation.',
            'Set the endpoint URL, the path to the alert list in the response, the '
            'id field and the timestamp field, and how the endpoint paginates.',
            'Use {since} in a query parameter so each poll only asks for new alerts.',
        ]),
    },
    # killchain addition: the pipeline analyses FortiGate key=value lines, so
    # FortiGate is the source whose data actually reaches detection.
    {
        'id': 'fortigate',
        'label': 'Fortinet FortiGate',
        'kind': 'firewall',
        'deployment': 'self-hosted',
        'transports': ['syslog', 'webhook'],
        'auth_modes': ['bearer', 'hmac'],
        'default_auth_mode': 'bearer',
        'docs_url': 'https://docs.fortinet.com/document/fortigate/latest/administration-guide/250999/log-settings-and-targets',
        'setup_steps': [
            'POST JSON to the webhook URL below with the secret in the request header shown.',
            'Put each raw FortiGate log line (date=... time=... logid=...) in a "full_log", "_raw", '
            '"raw", "message" or "log" field, or POST a JSON array of the lines as strings.',
            'Only records that carry a raw FortiGate line reach the analysis pipeline; other JSON '
            'is stored and counted as not analysable.',
        ],
        'syslog_steps': [
            'On the FortiGate CLI: config log syslogd setting; set status enable; set server '
            '<syslog host below>; set port <port below>; set mode reliable (TCP) or udp; '
            'set format default; end.',
        ] + _SYSLOG_STEPS,
    },
    {
        'id': 'custom',
        'label': 'Custom log source',
        'kind': 'custom',
        'deployment': 'any',
        'transports': ['webhook', 'api_pull', 'syslog', 'agent'],
        'auth_modes': ['bearer', 'hmac', 'mtls'],
        'default_auth_mode': 'bearer',
        'docs_url': None,
        'setup_steps': [
            'POST any JSON object to the webhook URL below with the secret in '
            'the request header shown.',
            'To send several alerts in one request, POST a JSON array, or an '
            'object with an "alerts" / "events" / "records" array -- each element '
            'is normalised independently.',
            'No schema registration is required; fields are classified to OCSF '
            'automatically.',
        ],
        'syslog_steps': _SYSLOG_STEPS,
        'agent_steps': _AGENT_STEPS,
        'pull': _generic_rest([
            'Enter the endpoint that lists alerts, how it authenticates, where the '
            'alert list is in the response, and how it paginates.',
        ]),
    },
]

_BY_ID: dict[str, dict[str, Any]] = {v['id']: v for v in VENDOR_CATALOG}

VENDOR_IDS: frozenset[str] = frozenset(_BY_ID)


def get_vendor(vendor_id: str) -> dict[str, Any] | None:
    return _BY_ID.get((vendor_id or '').strip().lower())


def vendor_label(vendor_id: str) -> str:
    v = get_vendor(vendor_id)
    return v['label'] if v else (vendor_id or 'unknown')


# ── killchain: what this app implements ──────────────────────────────────────
# No client certificates (mTLS) and no forwarding agent endpoint here, so those
# are filtered out of everything below rather than deleted from the catalog.
_UNSUPPORTED_AUTH: frozenset[str] = frozenset({'mtls'})


def syslog_enabled() -> bool:
    import os

    return (os.getenv('KILLCHAIN_SYSLOG') or '').strip().lower() in ('1', 'true', 'yes', 'on')


def supported_transports() -> tuple[str, ...]:
    return ('webhook', 'api_pull') + (('syslog',) if syslog_enabled() else ())


def _supported_auth(modes: Any) -> list[str]:
    return [m for m in modes if m not in _UNSUPPORTED_AUTH]


def vendor_transports(vendor_id: str) -> list[str]:
    v = get_vendor(vendor_id)
    if not v:
        return []
    return [t for t in (v.get('transports') or ['webhook']) if t in supported_transports()]


def auth_modes_for(vendor_id: str, transport: str) -> list[str]:
    """Auth modes a connector of this vendor + transport may use."""
    v = get_vendor(vendor_id)
    if not v:
        return []
    if transport == 'webhook':
        return _supported_auth(v['auth_modes'])
    return _supported_auth(TRANSPORT_AUTH_MODES.get(transport, ()))


def default_auth_mode(vendor_id: str, transport: str) -> str:
    v = get_vendor(vendor_id)
    if transport == 'webhook':
        mode = v['default_auth_mode'] if v else 'bearer'
        return mode if mode not in _UNSUPPORTED_AUTH else 'bearer'
    return TRANSPORT_DEFAULT_AUTH[transport]


def is_auth_mode_allowed(vendor_id: str, auth_mode: str, transport: str = 'webhook') -> bool:
    """True when the vendor can actually satisfy the requested auth mode.

    Guards against, for example, configuring mTLS for a SaaS webhook sender that
    has no way to present a client certificate -- which would produce a
    connector that silently never accepts anything.
    """
    return auth_mode in auth_modes_for(vendor_id, transport)


def pull_spec(vendor_id: str) -> dict[str, Any] | None:
    v = get_vendor(vendor_id)
    return v.get('pull') if v else None


def _public_pull(spec: dict[str, Any] | None) -> dict[str, Any] | None:
    if not spec:
        return None
    return {
        'client': spec['client'],
        'defaultIntervalSeconds': spec['default_interval_seconds'],
        'docsUrl': spec.get('docs_url'),
        'configFields': spec['config_fields'],
        'credentialFields': [
            {**f, 'secret': f.get('secret', True)} for f in spec['credential_fields']
        ],
        'setupSteps': spec.get('setup_steps', []),
    }


def public_catalog() -> list[dict[str, Any]]:
    """Catalog shaped for the Settings UI."""
    return [
        {
            'id': v['id'],
            'label': v['label'],
            'kind': v['kind'],
            'deployment': v['deployment'],
            'transports': vendor_transports(v['id']),
            'authModes': _supported_auth(v['auth_modes']),
            'defaultAuthMode': v['default_auth_mode'],
            'docsUrl': v.get('docs_url'),
            'setupSteps': v['setup_steps'],
            'syslogSteps': v.get('syslog_steps') or [],
            'agentSteps': v.get('agent_steps') or [],
            'payloadTemplate': v.get('payload_template'),
            'pull': _public_pull(v.get('pull')),
        }
        for v in VENDOR_CATALOG
    ]
