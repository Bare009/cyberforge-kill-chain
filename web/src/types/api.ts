/**
 * Response shapes of killchain/api that are not part of contracts B and C
 * (those live in types/incident.ts and docs/contracts.md).
 */
import type { Enrichment, NodeKind, RiskBand, Tactic, Zone } from '@/types/incident'

/** GET /health */
export interface HealthResponse {
  status: 'ok' | 'degraded'
  run: string
  sample: boolean
  counts: {
    incidents: number
    alerts: number
    events?: number
  }
}

/** One evidence line of GET /incidents/{id}/events. `raw` is null when the log is not on the server. */
export interface EvidenceRow {
  step: number | null
  alert_id: string
  technique: string | null
  role: string | null
  source: string
  line: number
  byte_offset: number
  ts: string | null
  ts_ist: string | null
  raw: string | null
}

/** GET /incidents/{id}/events */
export interface EvidenceResponse {
  incident_number: number
  step: number | null
  total: number
  offset: number
  limit: number
  /** alert_evidence.parquet | evidence_sample.json | incident line samples */
  origin: string
  raw_available: boolean
  lines: EvidenceRow[]
  steps: { step: number; lines: number }[]
}

/** GET /entities/{value} */
export interface EntityView {
  value: string
  kind: NodeKind | 'ip' | 'domain' | 'account'
  label: string
  zone: Zone | null
  importance: number | null
  enrichment: Enrichment | null
  incidents: {
    incident_number: number
    title: string
    risk_score: number
    risk_band: RiskBand
    ts_start_ist: string
    tactics: Tactic[]
    roles: string[]
    steps: number[]
  }[]
  alerts: {
    alert_id: string
    rule_id: string
    title: string
    technique: string
    tactic: Tactic
    severity: number
    ts_start: string
    event_count: number
    success: boolean
    incident_number: number | null
    as: string[]
    summary: string
  }[]
  alerts_total: number
}
