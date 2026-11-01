/**
 * Contracts B (alert) and C (incident) as the API returns them.
 * Source of truth: killchain/contracts.py and docs/contracts.md.
 * Times: ts_* are UTC ISO strings ending in Z; *_ist are "YYYY-MM-DD HH:MM:SS" in IST.
 */

export type Tactic =
  | 'reconnaissance' | 'resource-development' | 'initial-access' | 'execution' | 'persistence'
  | 'privilege-escalation' | 'defense-evasion' | 'credential-access' | 'discovery' | 'lateral-movement'
  | 'collection' | 'command-and-control' | 'exfiltration' | 'impact'

export type KillChainStage =
  | 'Reconnaissance' | 'Weaponization' | 'Delivery' | 'Exploitation' | 'Installation'
  | 'Command and Control' | 'Actions on Objectives'

/** vendor: an alert another security product raised (EDR, SIEM ...), rule_id `vendor:<product>:<name>`. */
export type Layer = 'rule' | 'anomaly' | 'vendor'
/** Where a vendor alert's ATT&CK label came from. */
export type TechniqueSource = 'vendor' | 'keyword' | 'llm' | 'unknown'
export type RiskBand = 'critical' | 'high' | 'medium' | 'low'
export type Zone = 'internet' | 'dmz' | 'server' | 'desktop' | 'iot' | 'lan' | 'mgmt' | 'public' | 'unknown'
export type NodeKind = 'external_ip' | 'internal_host' | 'server' | 'firewall' | 'account' | 'domain'
export type EdgeKind = 'step' | 'reach_observed' | 'reach_inferred'
export type ReachKind = 'observed' | 'inferred'
export type TiVerdict = 'known-malicious' | 'suspicious' | 'no-reports' | 'unknown'
export type TriageVerdict = 'looks_real' | 'likely_noise'
export type ReportSource = 'ai' | 'template'
export type RiskPartName = 'severity' | 'stage' | 'breadth' | 'success' | 'asset' | 'reach' | 'threat_intel'

/** A raw log line: seek to byte_offset in source to read it. */
export interface EvidenceLine {
  source: string
  line: number
  byte_offset: number
  ts: string
}

/** Contract B. */
export interface Alert {
  alert_id: string
  rule_id: string
  layer: Layer
  title: string
  technique: string
  alt_techniques: string[]
  technique_name: string | null
  tactic: Tactic
  stage_no: number
  kill_chain_stage: KillChainStage
  severity: number
  confidence: number
  ts_start: string
  ts_end: string
  src_ip: string | null
  dst_ip: string | null
  host: string | null
  user: string | null
  domain: string | null
  url: string | null
  event_count: number
  blocked_share: number
  success: boolean
  summary: string
  action_text: string
  incident_number: number | null
  /** Vendor alerts only. */
  technique_source?: TechniqueSource | null
}

export interface Step {
  n: number
  ts_start: string
  ts_end: string
  ts_start_ist: string
  ts_end_ist: string
  ongoing: boolean
  action: string
  rule_id: string
  alert_id: string
  technique: string
  technique_name: string | null
  tactic: Tactic
  stage_no: number
  kill_chain_stage: KillChainStage
  src: string | null
  dst: string | null
  event_count: number
  success: boolean
  line_sample: EvidenceLine[]
  line_total: number
  enrichment_flags: string[]
  confidence: number
  layer: Layer
}

export interface GraphNode {
  id: string
  label: string
  kind: NodeKind
  zone: Zone
  importance: number
  reach?: ReachKind
}

export interface GraphEdge {
  source: string
  target: string
  step: number | null
  technique: string | null
  tactic: string | null
  label: string
  kind: EdgeKind
  /** true on an edge drawn for a supporting anomaly of step `step` (optional, contract C). */
  supporting?: boolean
}

export interface ReachVia {
  from: string
  edge: string
  count: number
  lines: EvidenceLine[]
}

export interface Reachable {
  host: string
  zone: Zone
  hop: number
  kind: ReachKind
  via: ReachVia[]
}

export interface ProviderResult {
  provider: string
  available: boolean
  malicious: boolean
  score: number | null
  tags: string[]
  detail: Record<string, unknown>
  /** Added by the threat-intel engine. */
  fetched_at?: string
  error?: string
}

export interface Enrichment {
  kind: 'ip' | 'domain' | 'url' | 'hash'
  zone: Zone
  verdict: TiVerdict
  reputation: number
  providers: ProviderResult[]
  /** Added by the threat-intel engine (killchain/enrich). */
  tags?: string[]
  flags?: string[]
  /** False for private, reserved, own and internal values, which are never sent outside. */
  sendable?: boolean
}

export interface RiskPart {
  value: number
  weight: number
  points: number
}

export interface Triage {
  verdict: TriageVerdict
  confidence: number
  reasons: string[]
}

export interface Report {
  source: ReportSource
  markdown: string
  triage: Triage | null
  /** The template report, kept beside an AI report by the bundle step (optional). */
  template_markdown?: string
  /** provider:model that wrote an AI report (optional). */
  model?: string
}

/** Contract C. */
export interface Incident {
  incident_number: number
  incident_id: string
  title: string
  risk_score: number
  risk_band: RiskBand
  risk_parts: Record<RiskPartName, RiskPart>
  severity: number
  ts_start: string
  ts_end: string
  ts_start_ist: string
  ts_end_ist: string
  merged: { alerts: number; events: number }
  entities: { ips: string[]; hosts: string[]; users: string[]; domains: string[] }
  tactics: Tactic[]
  techniques: string[]
  chain_text: string
  chain: Step[]
  gaps: string[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  enrichment: Record<string, Enrichment>
  next: { reachable: Reachable[]; sentence: string; likely_tactics: string[] }
  report: Report
  report_source: ReportSource
  layers: Layer[]
}

/** A row of index.json, as returned by GET /incidents. */
export interface IndexRow {
  incident_number: number
  incident_id: string
  title: string
  risk_score: number
  risk_band: RiskBand
  severity: number
  ts_start: string
  ts_end: string
  ts_start_ist: string
  ts_end_ist: string
  merged: { alerts: number; events: number }
  tactics: Tactic[]
  techniques: string[]
  triage_verdict: TriageVerdict | null
  ti_verdict: TiVerdict | null
}

/** GET /incidents */
export interface IncidentList {
  run: string
  total: number
  limit: number
  offset: number
  incidents: IndexRow[]
}

/** GET /incidents/{id}/path */
export type IncidentPath = Pick<
  Incident,
  'incident_number' | 'incident_id' | 'title' | 'risk_score' | 'risk_band' | 'chain_text' | 'chain' | 'gaps' | 'graph' | 'next'
>
