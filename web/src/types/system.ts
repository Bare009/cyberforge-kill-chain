import type { LlmHealth } from '@/types/api'
import type { DataQuality, StageStats } from '@/types/views'

export type Grade = 'great' | 'good' | 'below' | 'n/a'
export type MetricName =
  | 'detection_recall' | 'label_accuracy' | 'attack_path_rebuilt' | 'false_alarm_share'
  | 'processing_secs' | 'peak_rss_mb' | 'open_time_p95_ms'

export interface MetricTarget {
  label: string
  unit: 'share' | 'seconds' | 'MB' | 'ms' | string
  meaning: string
  good: number
  great: number
  higher_is_better: boolean
}

/** GET /metrics */
export interface MetricsResponse {
  available: boolean
  run: string
  hint?: string
  generated_at?: string | null
  truth?: string
  /** What the scorer had to do or could not do with the truth (e.g. a log not given). */
  truth_notes?: string[]
  targets?: Record<MetricName, MetricTarget>
  metrics?: Record<MetricName, number | null>
  grades?: Record<MetricName, Grade>
  detail?: Record<string, unknown> & {
    truth_lines?: number
    covered_lines?: number
    truth_incidents?: number
    incidents_found?: number
    label_exact?: number
    label_parent?: number
    label_any?: number
    our_incidents?: number
    incidents_without_truth?: number
    multi_step_rebuilt?: string
    open_time_p50_ms?: number | null
    unreviewed?: { incident_number: number; title: string }[]
  }
  per_incident?: { incident_id: number; incident_name: string; class: string; lines: number; found: number; recall: number }[]
  per_class?: { class: string; lines: number; found: number; recall: number }[]
  paths?: { incident_id: number; incident_name: string; steps: number; ordered: boolean; our_incident: number | null;
            rebuilt: boolean; reason: string }[]
  per_rule?: { rule_id: string; alerts: number; layer: string; truth_lines: number; background_alerts: number }[]
}

/** GET /system */
export interface SystemResponse {
  run: string
  run_dir: string
  sample: boolean
  bundled_at: string | null
  stages: Record<string, StageStats>
  totals: { processing_secs?: number; peak_rss_mb?: number }
  counts: Record<string, unknown>
  warnings: string[]
  contract_errors: string[]
  contract_error_count: number
  data_quality: DataQuality | null
  threat_intel: {
    source: string
    offline: boolean
    providers: Record<string, string>
    indicators: number
    verdicts?: Record<string, number>
    generated_at: string | null
    last_run?: { lookups: number; cache_hits: number; failures: number; skipped_private: number; wall_secs: number } | null
    cache?: Record<string, { answers: number; fresh: number }>
    on_demand_per_minute?: number
  }
  llm: LlmHealth
  evidence: { origin: string; raw_dir: string; logs: { source: string; available: boolean }[] }
  rules_dir: string
  rule_test_sandbox: boolean
  files: { name: string; files: number; bytes: number; modified: string | null }[]
  api: { started_at: string; uptime_s: number; loaded_at: string; reloads: number; watching: boolean;
         versions: Record<string, string>; platform: string }
}

export interface LiveAlert {
  alert_id: string
  rule_id: string
  title: string
  severity: number
  ts_start: string
  incident_number: number | null
  src_ip: string | null
  dst_ip: string | null
}

/** One event of GET /live/stream and /live/status. */
export interface LiveEvent {
  id: number
  type: 'hello' | 'bundle' | 'status' | 'run'
  at: string
  /** run: the API now serves this run */
  run?: string
  // bundle
  new_incidents?: number[]
  changed_incidents?: number[]
  removed_incidents?: string[]
  new_alerts?: LiveAlert[]
  counts?: { incidents: number; alerts: number; new_alerts: number; new_incidents: number; changed_incidents: number }
  // status and hello
  state?: string
  previous?: string
  status?: LiveProcess | null
  version?: number
  process_state?: string
  watching?: boolean
}

/** <run>/live/status.json, written by the live process (track A, P15). */
export interface LiveProcess {
  state?: string
  source?: string
  offset?: number
  size?: number
  lines_total?: number
  lines_per_sec?: number
  last_line_ts?: string
  updated_at?: string
  [key: string]: unknown
}

/** GET /live/status */
export interface LiveStatus {
  run: string
  watching: boolean
  interval_s: number
  version: number
  reloads: number
  loaded_at: string
  last_error: string | null
  process_state: 'running' | 'stopped' | 'stale' | 'not started' | string
  process: LiveProcess | null
  counts: { incidents: number; alerts: number }
  how_to_start: string
  events: LiveEvent[]
}
