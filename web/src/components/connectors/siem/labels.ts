// Copied from AI-SOC web_app/frontend/src/components/settings/siem/labels.ts
import axios from 'axios'
import type {
  ConnectorAuthMode,
  ConnectorHealth,
  IngestEndpoints,
  PullConfigField,
  SiemAuthMode,
  SiemIntegrationRow,
  SiemPullSpec,
  SiemTransport,
} from '@/types/connectors'

export function apiError(e: unknown, fallback: string): string {
  if (axios.isAxiosError(e) && e.response?.data != null) {
    const d = e.response.data as { detail?: unknown }
    if (typeof d.detail === 'string') return d.detail
    if (Array.isArray(d.detail)) {
      // FastAPI validation errors: [{loc, msg}, ...]
      return d.detail
        .map((x) => (x && typeof x === 'object' && 'msg' in x ? String((x as { msg: unknown }).msg) : String(x)))
        .join('; ')
    }
    if (d.detail != null) return String(d.detail)
  }
  return e instanceof Error ? e.message : fallback
}

export const AUTH_MODE_LABEL: Record<ConnectorAuthMode, string> = {
  bearer: 'Bearer token',
  hmac: 'HMAC signature',
  mtls: 'Client certificate (mTLS)',
  api: 'Vendor API credentials',
  source_ip: 'Sender address allow-list',
}

export const AUTH_MODE_HELP: Record<SiemAuthMode, string> = {
  bearer:
    'The sender includes the secret in a request header. Works with any log source that lets you add custom headers to an outbound webhook. Best choice for SaaS products.',
  hmac:
    'The sender signs each request body with the secret. Stronger than a bearer token because a captured request cannot be replayed with different content, but the sender must be able to compute an HMAC — usually a self-hosted source, a custom script, or the forwarding agent.',
  mtls:
    'The sender presents a client certificate issued from the Certificates tab. Only possible for self-hosted sources you control.',
}

export const TRANSPORT_LABEL: Record<SiemTransport, string> = {
  webhook: 'Webhook (push)',
  api_pull: 'API pull',
  syslog: 'Syslog / CEF',
  agent: 'Forwarding agent',
}

export const TRANSPORT_SHORT: Record<SiemTransport, string> = {
  webhook: 'Webhook',
  api_pull: 'API pull',
  syslog: 'Syslog',
  agent: 'Agent',
}

export const TRANSPORT_HELP: Record<SiemTransport, string> = {
  webhook:
    'The product sends each alert to a URL generated for this connection. Needs the product to support outbound webhooks and to reach the ingest endpoint.',
  api_pull:
    'The platform logs in to the product’s API on a schedule and collects new alerts. Nothing has to be configured in the product beyond an API credential.',
  syslog:
    'The product sends syslog (plain, CEF, LEEF or JSON) to the platform’s collector. Senders are identified by their IP address, or by client certificate over TLS.',
  agent:
    'A small agent runs next to the product, reads its log files or receives its local syslog, and forwards over HTTPS. For on-prem sources that cannot reach the platform directly.',
}

export const SYSLOG_AUTH_HELP: Record<'source_ip' | 'mtls', string> = {
  source_ip:
    'Messages are accepted from the listed addresses only. Plain syslog addresses can be spoofed on untrusted networks — prefer TLS or the agent across the internet.',
  mtls:
    'The sender connects to the TLS listener with a client certificate whose Common Name matches the pattern below.',
}

export function formatInterval(seconds: number): string {
  if (!seconds) return '—'
  if (seconds % 3600 === 0) return `${seconds / 3600} h`
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}

export const INTERVAL_OPTIONS: { value: number; label: string }[] = [
  { value: 60, label: 'Every minute' },
  { value: 300, label: 'Every 5 minutes' },
  { value: 900, label: 'Every 15 minutes' },
  { value: 1800, label: 'Every 30 minutes' },
  { value: 3600, label: 'Every hour' },
]

/** Values the pull form starts with: the spec defaults, overlaid with `current`. */
export function initialPullConfig(
  spec: SiemPullSpec | null | undefined,
  current?: Record<string, unknown>
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const f of spec?.configFields ?? []) {
    const v = current && f.key in current ? current[f.key] : f.default
    if (v === undefined || v === null) continue
    out[f.key] = f.type === 'json' && typeof v !== 'string' ? JSON.stringify(v, null, 2) : v
  }
  return out
}

/** Which config fields are relevant given the current selections (generic REST). */
export function isFieldVisible(field: PullConfigField, values: Record<string, unknown>): boolean {
  const authType = values.auth_type
  const pagination = values.pagination
  switch (field.key) {
    case 'auth_header':
      return authType === 'header'
    case 'body':
      return values.method === 'POST'
    case 'cursor_path':
    case 'cursor_param':
      return pagination === 'cursor'
    case 'page_param':
      return pagination === 'page'
    case 'offset_param':
      return pagination === 'offset'
    default:
      return true
  }
}

export function isCredentialVisible(
  key: string,
  client: string | undefined,
  values: Record<string, unknown>
): boolean {
  if (client !== 'generic_rest') return true
  const t = values.auth_type ?? 'bearer'
  if (key === 'token') return t === 'bearer' || t === 'header'
  if (key === 'username' || key === 'password') return t === 'basic'
  return true
}

/** Agent config file contents for a freshly created/rotated agent connector. */
export function buildAgentConfig(row: SiemIntegrationRow, secret: string | null): string {
  const endpoint = (row.agentEndpoint ?? '').replace(/\/api\/v1\/agent\/[^/]+$/, '')
  return JSON.stringify(
    {
      endpoint,
      connector_id: row.connectorId,
      auth_mode: row.authMode,
      secret: row.authMode === 'mtls' ? undefined : secret ?? '<set SOAR_AGENT_SECRET>',
      client_cert: row.authMode === 'mtls' ? '/etc/soar-agent/client.crt' : undefined,
      client_key: row.authMode === 'mtls' ? '/etc/soar-agent/client.key' : undefined,
      ca_file: null,
      state_dir: './soar-agent-state',
      inputs: [
        { type: 'file', path: '/var/log/example/alerts*.json', format: 'json', start_at: 'end' },
        { type: 'syslog', protocol: 'udp', bind: '127.0.0.1', port: 5514 },
      ],
    },
    null,
    2
  )
}

export function syslogTargets(endpoints: IngestEndpoints | undefined): { label: string; value: string }[] {
  if (!endpoints) return []
  const s = endpoints.syslog
  const rows = [
    { label: 'TCP (recommended)', value: `${s.host}:${s.tcpPort}` },
    { label: 'UDP', value: `${s.host}:${s.udpPort}` },
  ]
  if (s.tlsEnabled) rows.unshift({ label: 'TLS', value: `${s.host}:${s.tlsPort}` })
  return rows
}

/** Serialise form values for the API: JSON fields are sent as parsed objects. */
export function serialisePullConfig(
  spec: SiemPullSpec,
  values: Record<string, unknown>
): { config: Record<string, unknown>; error: string | null } {
  const out: Record<string, unknown> = {}
  for (const f of spec.configFields) {
    if (!isFieldVisible(f, values)) continue
    const v = values[f.key]
    if (v === undefined) continue
    if (f.type === 'json') {
      const text = typeof v === 'string' ? v.trim() : ''
      if (!text) continue
      try {
        out[f.key] = JSON.parse(text)
      } catch {
        return { config: out, error: `${f.label} is not valid JSON.` }
      }
      continue
    }
    out[f.key] = v
  }
  return { config: out, error: null }
}

export function nonEmptyCredentials(values: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(values)) {
    if (v && v.trim()) out[k] = v.trim()
  }
  return out
}

/** Textarea "one per line / comma separated" -> list. */
export function parseSources(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds)) return '—'
  const s = Math.abs(seconds)
  if (s < 60) return `${Math.round(s)} s`
  if (s < 3600) return `${Math.round(s / 60)} min`
  if (s < 86400) return `${(s / 3600).toFixed(1)} h`
  return `${(s / 86400).toFixed(1)} d`
}

export const HEALTH_KIND_SHORT: Record<string, string> = {
  source_silent: 'Silent',
  clock_skew: 'Clock skew',
  timestamps_missing: 'No timestamps',
  poor_completeness: 'Incomplete data',
  events_lost: 'Alerts lost',
  edge_drops: 'Dropping',
  agent_offline: 'Agent offline',
  pull_failing: 'Poll failing',
}

/** Plain-language description of a connection's silence alerting. */
export function silenceDescription(h: ConnectorHealth | null | undefined): string {
  if (!h) return 'learned from history once the collector has run'
  if (h.silenceMinutes === 0) return 'off'
  const eff = h.effectiveSilenceMinutes
  if (h.silenceMinutes && h.silenceMinutes > 0) return `after ${formatDuration(h.silenceMinutes * 60)} without alerts`
  if (h.silenceThresholdSource === 'baseline' && eff) {
    return `after ${formatDuration(eff * 60)} without alerts (learned from the last 7 days)`
  }
  if (h.silenceThresholdSource === 'insufficient_history') {
    return 'not yet — too few alerts to learn a normal rate; set a threshold in Edit to monitor it now'
  }
  return 'learned from history once the collector has run'
}

export const TIME_ZONE_SUGGESTIONS = [
  'UTC',
  'Asia/Kolkata',
  'Asia/Dubai',
  'Asia/Singapore',
  'Europe/London',
  'Europe/Berlin',
  'America/New_York',
  'America/Chicago',
  'America/Los_Angeles',
  'Australia/Sydney',
  '+05:30',
]
