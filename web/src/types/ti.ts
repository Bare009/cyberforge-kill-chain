/** Threat-intel endpoints of killchain/api (killchain/api/ti.py). */
import type { ProviderResult, TiVerdict, Zone } from '@/types/incident'

export type IndicatorKind = 'ip' | 'domain' | 'url' | 'hash'

/** GET /ti/status */
export interface TiStatus {
  source: 'enrichment.json' | 'incident data'
  generated_at: string | null
  offline: boolean
  /** provider -> ok | no key | disabled | offline */
  providers: Record<string, string>
  indicators: number
  verdicts: Partial<Record<TiVerdict, number>>
  last_run: { lookups: number; cache_hits: number; failures: number; skipped_private: number; wall_secs: number } | null
  cache: Record<string, { answers: number; fresh: number }>
  on_demand_per_minute: number
  note: string | null
}

export interface TiIncidentRef {
  incident_number: number
  title: string
}

/** A row of GET /ti/indicators */
export interface TiIndicatorRow {
  value: string
  kind: IndicatorKind
  zone: Zone | null
  verdict: TiVerdict
  reputation: number
  flagged_by: string[]
  answered_by: string[]
  sendable: boolean | null
  pulses: number | null
  tags: string[]
  flags: string[]
  incidents: TiIncidentRef[]
}

/** GET /ti/indicators */
export interface TiIndicatorList {
  total: number
  source: string
  indicators: TiIndicatorRow[]
}

/** GET /ti/indicators/{value} */
export interface TiIndicatorDetail extends TiIndicatorRow {
  providers: ProviderResult[]
}

/** POST /ti/lookup */
export interface TiLookupResult {
  value: string
  kind: IndicatorKind
  zone: Zone
  verdict: TiVerdict
  reputation: number
  providers: ProviderResult[]
  tags: string[]
  flags: string[]
  sendable: boolean
  in_run: boolean
  not_sent_because: string | null
  incidents: TiIncidentRef[]
}
