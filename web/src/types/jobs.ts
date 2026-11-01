/** GET /uploads: logs in the API's raw folder. */
export interface RawFile {
  name: string
  size: number
  modified: string
  /** Runs made from this file. */
  runs: string[]
}

export interface UploadListing {
  enabled: boolean
  raw_dir: string
  files: RawFile[]
  partial: { name: string; received: number }[]
  free_bytes: number | null
  max_chunk: number
  defaults: { workers: number; cpus: number | null }
}

/** GET|POST /uploads/{name} */
export interface UploadStatus {
  name: string
  received: number
  size: number | null
  complete: boolean
  already?: boolean
}

export type JobState = 'running' | 'ok' | 'ok_with_warnings' | 'failed' | 'no_events' | 'cancelled' | 'usage_error'
export type StageStatus = 'pending' | 'running' | 'ok' | 'failed' | 'skipped' | 'degraded' | 'cancelled'

export interface JobStage {
  name: string
  status: StageStatus
  wall_secs: number | null
  reason?: string | null
}

export interface JobResult {
  /** What the schema stage read (run_summary.json `schema`); absent for runs made before it existed. */
  format?: string | null
  parser?: string | null
  products?: Record<string, number>
  categories?: Record<string, number>
  alerts_by_layer?: Record<string, number>
  status: string
  exit_code: number
  wall_secs: number | null
  peak_rss_mb: number | null
  incidents: number | null
  critical_incidents: number | null
  alerts: number | null
  unexplained: number | null
  events: number | null
  lines: number | null
  warnings: string[]
  error: string | null
}

/** GET /jobs/current -> job */
export interface Job {
  id: string
  state: JobState
  file: string
  file_bytes: number
  run: string
  options: { offline: boolean; no_llm: boolean; workers: number; switch: boolean }
  started_at: string
  finished_at: string | null
  elapsed_secs: number
  upload_secs: number | null
  /** The running stage, or "loading" while the API loads the finished run. */
  current: string | null
  stages: JobStage[]
  parse: { phase: 'counting' | 'parsing' | 'done' | null; pct: number; gib: number; secs: number | null }
  tail: string[]
  result: JobResult | null
  switched: boolean
  error: string | null
}

export interface CurrentJob {
  enabled: boolean
  job: Job | null
}

/** GET /runs */
export interface RunInfo {
  name: string
  active: boolean
  sample: boolean
  incidents: number | null
  critical_incidents: number | null
  alerts: number | null
  events: number | null
  processing_secs: number | null
  bundled_at: string | null
  input: string | null
  input_bytes: number | null
}

export interface RunList {
  active: string
  runs: RunInfo[]
}

export interface JobRequest {
  file: string
  run: string
  offline: boolean
  no_llm: boolean
  workers?: number
  replace?: boolean
  upload_secs?: number | null
}
