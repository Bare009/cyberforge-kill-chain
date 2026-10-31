/** MITRE ATT&CK coverage.
 * Mirrors killchain/api/mitre.py, which keeps AI-SOC's mitre_matrix.py shapes. */

export type SeverityBucket = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'
export type SeverityCounts = Record<SeverityBucket, number>
/** Badge labels, as elsewhere in the UI. */
export type SeverityLabel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN'
export type MitrePreset = '24h' | '7d' | '30d' | '90d'

export interface CatalogueInfo {
  attackSpecVersion: string | null
  bundleModified: string | null
  attribution: string
  domain: string
  tacticsTotal: number
  techniquesTotal: number
  subtechniquesTotal: number
}

export interface SubtechniqueCell {
  id: string
  name: string | null
  alerts: number
  maxSeverity: SeverityLabel | null
  lastSeen: string | null
}

/** One technique inside one tactic column. */
export interface TechniqueCell {
  id: string
  name: string
  url: string
  alerts: number
  seen: boolean
  openAlerts: number
  correlatedAlerts: number
  severity: SeverityCounts
  maxSeverity: SeverityLabel | null
  lastSeen: string | null
  subtechniquesTotal: number
  subtechniquesSeen: number
  subtechniques: SubtechniqueCell[]
}

export interface TacticColumn {
  id: string
  shortname: string
  name: string
  url: string
  techniquesTotal: number
  techniquesSeen: number
  /** Alerts for this column's techniques. A technique serving several tactics
   * counts in each, so these do not sum to `summary.alertsMapped`. */
  alerts: number
  severity: SeverityCounts
  maxSeverity: SeverityLabel | null
  techniques: TechniqueCell[]
}

export interface MatrixSummary {
  alertsTotal: number
  alertsMapped: number
  alertsUnmapped: number
  alertsUnknownTechnique: number
  techniquesSeen: number
  techniquesTotal: number
  subtechniquesSeen: number
  subtechniquesTotal: number
  tacticsSeen: number
  tacticsTotal: number
}

export interface TopTechnique {
  id: string
  name: string
  url: string
  tactics: string[]
  alerts: number
  maxSeverity: SeverityLabel | null
  lastSeen: string | null
}

export interface MitreMatrix {
  period: { start: string; end: string; preset: MitrePreset | null }
  filters: {
    severities: string[]
    statuses: string[]
    sources: string[]
    includeFalsePositives: boolean
  }
  catalogue: CatalogueInfo
  summary: MatrixSummary
  tactics: TacticColumn[]
  topTechniques: TopTechnique[]
  unknownTechniques: { id: string; alerts: number }[]
}

export interface TechniqueTrendPoint extends SeverityCounts {
  date: string
  alerts: number
}

export interface TechniqueDetail {
  technique: {
    id: string
    name: string
    url: string
    parent: string | null
    parentName: string | null
    tactics: { id: string; name: string }[]
    subtechniquesTotal: number
  }
  period: { start: string; end: string; preset: MitrePreset | null }
  summary: {
    alerts: number
    openAlerts: number
    correlatedAlerts: number
    alertsOnTechniqueItself: number
    severity: SeverityCounts
    maxSeverity: SeverityLabel | null
    firstSeen: string | null
    lastSeen: string | null
  }
  trend: TechniqueTrendPoint[]
  subtechniques: {
    id: string
    name: string | null
    inCatalogue: boolean
    url: string
    alerts: number
    maxSeverity: SeverityLabel | null
    lastSeen: string | null
  }[]
  bySource: { source: string; alerts: number }[]
  byAsset: { asset: string; alerts: number }[]
  byStatus: { status: string; alerts: number }[]
  recentAlerts: {
    id: string | null
    time: string | null
    severity: SeverityLabel
    status: string | null
    title: string | null
    source: string | null
    subtechniqueId: string | null
    confidence: number | null
    /** KillChain addition: the incident the alert belongs to, or null. */
    incidentNumber?: number | null
  }[]
}

export interface MitreQuery {
  preset?: MitrePreset
  /** An absolute range (ISO instants), e.g. the dashboard's; wins over the preset. */
  start?: string
  end?: string
  severity?: string[]
  status?: string[]
  source?: string[]
  includeFalsePositives?: boolean
}
