import type { Alert, RiskBand, Tactic, TiVerdict, TriageVerdict } from '@/types/incident'

/** One count bucket of GET /dashboard/summary. */
export interface CoverageRow {
  tactic: Tactic
  name: string
  stage_no: number
  incidents: number
  alerts: number
}

export interface HourRow {
  hour: string            // UTC ISO, start of the hour
  alerts: number
  rule: number
  anomaly: number
}

export interface TopEntity {
  value: string
  alerts: number
  incidents: number[]
  max_severity: number
}

export interface DataQuality {
  lines: number | null
  bytes: number | null
  events: number
  events_good_time: number
  events_frozen_clock: number
  exact_duplicate_rows: number
  rejected_lines: number
  lines_by_class: Record<string, number>
  junk_bytes: number
  junk_ranges: { source: string; start: number; end: number; bytes: number; lines: number }[]
  parse_issues: Record<string, number>
  first_good_ts: string | null
  last_good_ts: string | null
  note?: string
}

export interface StageStats {
  wall_secs?: number | null
  peak_rss_mb?: number | null
  [key: string]: unknown
}

export interface LlmStatus {
  reports: number
  source?: string
  note?: string
  generated_at?: string | null
  model?: string | null
  usage?: Record<string, unknown> | null
}

/** GET /dashboard/summary */
export interface DashboardSummary {
  run: string
  sample: boolean
  /** No run loaded yet (API started with --run none). */
  empty?: boolean
  kpis: {
    events_parsed: number | null
    log_lines: number | null
    alerts: number
    incidents: number
    critical_incidents: number
    critical_severity_incidents: number
    unexplained: number
    log_start: string | null
    log_end: string | null
    incident_start: string | null
    incident_end: string | null
    processing_secs: number | null
    peak_rss_mb: number | null
    /** pipeline: one full `killchain run`, timed end to end; stages: the sum of the stages' own timings */
    processing_timing?: 'pipeline' | 'stages'
    evidence_lines: number | null
  }
  risk_scored: boolean
  incidents_by_band: { band: RiskBand; incidents: number }[]
  incidents_by_severity: { severity: number; incidents: number }[]
  coverage: CoverageRow[]
  alerts_per_hour: HourRow[]
  alerts_by_layer: Record<string, number>
  top_attackers: TopEntity[]
  top_targets: TopEntity[]
  worst_incidents: {
    incident_number: number
    title: string
    risk_score: number
    risk_band: RiskBand
    severity: number
    ts_start: string
    tactics: string[]
    ti_verdict: TiVerdict | null
    triage_verdict: TriageVerdict | null
  }[]
  data_quality: DataQuality | null
  stages: Record<string, StageStats>
  threat_intel: { source: string; offline: boolean; providers: Record<string, string>; indicators: number;
                  verdicts?: Record<string, number>; generated_at: string | null } | null
  llm: LlmStatus | null
}

/** GET /alerts */
export interface AlertList {
  run: string
  total: number
  limit: number
  offset: number
  counts: { all: number; not_in_incident: number; unexplained: number }
  alerts: Alert[]
}

export type UnexplainedAlert = Alert & { reason: string | null; group_id: string | null }

/** GET /unexplained */
export interface UnexplainedList {
  run: string
  total: number
  note: string
  alerts: UnexplainedAlert[]
}

/** A row of GET /rules */
export interface RuleRow {
  id: string
  title: string
  status: string
  layer: 'rule' | 'anomaly'
  kind: string
  logsource: string
  technique: string | null
  technique_name: string | null
  tactic: Tactic | null
  alt_techniques: string[]
  severity: number
  confidence: number
  promote: boolean
  path: string
  alerts: number
  alerts_in_incidents: number
  incidents: number[]
  evidence_lines: number | null
  run_secs: number | null
  ran: boolean
  background_alerts: number | null
  truth_lines: number | null
  last_alert: string | null
  tuning: string | null
}

export interface RuleList {
  total: number
  rules_dir: string
  errors: string[]
  evaluated: boolean
  unknown_rules: { rule_id: string; alerts: number }[]
  rules: RuleRow[]
}

export type RuleDetail = RuleRow & { yaml: string; recent_alerts: Alert[] }
