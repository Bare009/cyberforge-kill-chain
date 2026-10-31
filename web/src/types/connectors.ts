// Copied from AI-SOC web_app/frontend/src/types/settings.ts (SIEM integration types only;
// source-health, quality and unmatched-syslog types dropped). Adds linesForwarded / notAnalysable.

/** How the sending log source proves its identity to the ingest endpoint. */
export type SiemAuthMode = 'mtls' | 'hmac' | 'bearer'

/**
 * How alerts reach the platform:
 *  - `webhook`  the source POSTs to a per-connector URL
 *  - `api_pull` the platform polls the vendor API with stored credentials
 *  - `syslog`   the source sends syslog / CEF / LEEF to the collector
 *  - `agent`    the forwarding agent tails files / local syslog and forwards
 */
export type SiemTransport = 'webhook' | 'api_pull' | 'syslog' | 'agent'

/** Auth mode stored on a connector — webhook/agent modes plus transport markers. */
export type ConnectorAuthMode = SiemAuthMode | 'api' | 'source_ip'

export type PullFieldType = 'url' | 'text' | 'number' | 'select' | 'boolean' | 'json' | 'password'

export interface PullConfigField {
  key: string
  label: string
  type: PullFieldType
  required?: boolean
  default?: unknown
  placeholder?: string
  help?: string
  options?: { value: string; label: string }[]
  allow_empty?: boolean
}

export interface PullCredentialField {
  key: string
  label: string
  required?: boolean
  help?: string
  /** Rendered as a password input when true (the default). */
  secret: boolean
}

export interface SiemPullSpec {
  client: string
  defaultIntervalSeconds: number
  docsUrl: string | null
  configFields: PullConfigField[]
  credentialFields: PullCredentialField[]
  setupSteps: string[]
}

/** One supported log source from the backend catalog (GET /settings/siem-vendors). */
export interface SiemVendor {
  id: string
  label: string
  kind: 'siem' | 'edr' | 'custom'
  deployment: 'self-hosted' | 'saas' | 'hybrid' | 'any'
  transports: SiemTransport[]
  /** Webhook auth modes. */
  authModes: SiemAuthMode[]
  defaultAuthMode: SiemAuthMode
  docsUrl: string | null
  setupSteps: string[]
  syslogSteps: string[]
  agentSteps: string[]
  /** Suggested webhook body template, where the vendor needs one. */
  payloadTemplate: string | null
  pull: SiemPullSpec | null
}

export interface IngestEndpoints {
  baseUrl: string
  syslog: {
    host: string
    udpPort: number
    tcpPort: number
    tlsPort: number
    tlsEnabled: boolean
  }
  /** False when CONNECTOR_CREDENTIALS_KEY is unset — API pull cannot be created. */
  credentialsKeyConfigured: boolean
}

export interface SiemVendorsResponse {
  vendors: SiemVendor[]
  endpoints: IngestEndpoints
}

export interface PullLastRun {
  fetched: number
  queued: number
  duplicates: number
  pages: number
  complete: boolean
  duration_ms: number
  warning?: string
}

export interface PullState {
  nextRunAt: string | null
  lastRunAt: string | null
  lastSuccessAt: string | null
  consecutiveFailures: number
  running: boolean
  watermark: string | null
  lastRun: PullLastRun | null
  lastError: { kind: string; message: string; at: string | null } | null
}

export interface PullSettings {
  client: string
  config: Record<string, unknown>
  intervalSeconds: number
  credentialHint: string | null
  credentialsUpdatedAt: string | null
}

export interface SyslogSettings {
  allowedSources: string[]
  lastMessageAt: string | null
  lastSenderIp: string | null
}

/**
 * A row in the SIEM connections table.
 *
 * Rows come from two places, distinguished by `registered`:
 *  - `registered: true`  — a configured connector, with a webhook URL and credential.
 *  - `registered: false` — a source observed in stored data that has no connector
 *    record. Read-only; cannot be edited or deleted.
 */
export interface SiemIntegrationRow {
  connectorId: string | null
  vendor: string | null
  vendorLabel: string
  name: string
  /** Null only for observed-but-unregistered rows. */
  transport: SiemTransport | null
  authMode: ConnectorAuthMode | null
  enabled: boolean
  webhookUrl: string | null
  /** Agent connectors: base of /events and /heartbeat. */
  agentEndpoint?: string | null
  pull?: PullSettings | null
  pullState?: PullState | null
  syslog?: SyslogSettings | null
  /** Non-reversible display hint, e.g. `soar_A1b2…`. Never the real secret. */
  secretHint: string | null
  allowedCnPattern?: string | null
  registered: boolean
  sourceKind?: 'siem' | 'agent' | 'unknown'
  observedStatus: 'active' | 'idle' | 'inactive'
  alertsToday: number
  totalAlerts: number
  lastIngestAt: string | null
  createdAt?: string | null
  createdBy?: string | null
  secretRotatedAt?: string | null
  /** Registry counter maintained by the ingest paths. */
  alertsReceived?: number
  lastSeenAt?: string | null
  /** Zone of the source's offset-less timestamps (IANA or "+05:30"); null = UTC. */
  timeZone?: string | null
  health?: ConnectorHealth | null
  /** killchain: raw FortiGate log lines written to live mode's data/ingest/live.log. */
  linesForwarded?: number
  /** killchain: records received with no raw log line, so they cannot be analysed. */
  notAnalysable?: number
}

export type SourceHealthKind =
  | 'source_silent'
  | 'clock_skew'
  | 'timestamps_missing'
  | 'poor_completeness'
  | 'events_lost'
  | 'edge_drops'
  | 'agent_offline'
  | 'pull_failing'
  | 'pipeline_backlog'

/** Written by the log collector's health monitor and reconciler. */
export interface ConnectorHealth {
  /** null = learned from history, 0 = off, n = configured minutes. */
  silenceMinutes: number | null
  effectiveSilenceMinutes: number | null
  silenceThresholdSource: 'configured' | 'baseline' | 'disabled' | 'insufficient_history' | null
  checkedAt: string | null
  lastSeenAt: string | null
  openIncidents: SourceHealthKind[]
  quality1h: {
    total: number
    futureDated: number
    withoutTimestamp: number
    poor: number
    incomplete: number
    maxAheadSeconds: number
    meanLagSeconds: number | null
  } | null
  reconciliation: {
    checkedAt: string | null
    windowHours: number | null
    received: number
    accounted: number
    open: number
    lost: number
    replayed: number
    edgeDroppedTotal: number
    byStatus: Record<string, number>
  } | null
}

export interface SiemIntegrationsResponse {
  integrations: SiemIntegrationRow[]
}

/**
 * Create/rotate response. `secret` is present exactly once — at creation and at
 * rotation — and is not retrievable afterwards.
 */
export interface SiemIntegrationSecretResponse extends SiemIntegrationRow {
  secret: string | null
}

export interface PullSettingsPayload {
  config?: Record<string, unknown>
  interval_seconds?: number
}

export interface CreateSiemIntegrationPayload {
  vendor: string
  name: string
  transport?: SiemTransport
  auth_mode?: ConnectorAuthMode
  allowed_cn_pattern?: string
  pull?: PullSettingsPayload
  /** Write-only. Never returned by the API. */
  credentials?: Record<string, string>
  allowed_sources?: string[]
  time_zone?: string
  /** Omit / -1 = learned, 0 = off, n = minutes. */
  silence_minutes?: number
}

export interface UpdateSiemIntegrationPayload {
  name?: string
  enabled?: boolean
  allowed_cn_pattern?: string
  pull?: PullSettingsPayload
  /** Blank / omitted fields keep their stored value. */
  credentials?: Record<string, string>
  allowed_sources?: string[]
  /** '' clears (UTC). */
  time_zone?: string
  /** -1 = learned, 0 = off, n = minutes. */
  silence_minutes?: number
}

export interface IngestAgent {
  agentId: string
  hostname: string
  version: string
  platform: string
  remoteIp: string
  firstSeenAt: string | null
  lastHeartbeatAt: string | null
  status: 'online' | 'offline'
  stats: Partial<Record<
    | 'events_sent'
    | 'events_failed'
    | 'batches_sent'
    | 'batches_failed'
    | 'spool_bytes'
    | 'spool_events'
    | 'uptime_seconds'
    | 'dropped_events',
    number
  >>
  inputs: { type: string; target: string; status: string; error: string }[]
}

export interface IngestAgentsResponse {
  agents: IngestAgent[]
}
