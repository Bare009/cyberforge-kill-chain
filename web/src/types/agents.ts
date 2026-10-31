import type { Alert } from '@/types/incident'

export interface CitedLine {
  line: number
  step: number | null
  ts_ist: string | null
  raw: string | null
  source: string | null
}

/** POST /incidents/{id}/ask */
export interface AskResponse {
  incident_number: number
  question: string
  answer: string | null
  cited_lines: CitedLine[]
  model: string | null
  cached: boolean
  attempts: number
  lines_given: number
  tokens: number
  rejected: boolean
  problems?: string[]
  note?: string
}

export interface RuleSummary {
  id: string
  title: string
  kind: string
  layer: string
  technique: string | null
  tactic: string | null
  severity: number
}

/** POST /rules/test */
export interface RuleTestResult {
  valid: boolean
  ran: boolean
  errors: string[]
  rule: RuleSummary | null
  alerts?: number
  evidence_lines?: number
  secs?: number
  hits?: Alert[]
}

/** POST /rules/draft */
export interface RuleDraft {
  description: string
  yaml: string | null
  explanation: string | null
  test: RuleTestResult | null
  model: string | null
  cached: boolean
  attempts: number
  problems: string[]
  tokens: number
}

/** POST /rules/save */
export interface RuleSaved {
  saved: boolean
  path: string
  rule: RuleSummary
  next: string
}
