import type { KillChainStage, RiskBand, Tactic, TiVerdict, TriageVerdict } from '@/types/incident'

/** The 14 ATT&CK tactics in kill chain order (stage_no 1..14). */
export const TACTIC_ORDER: Tactic[] = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
  'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
  'collection', 'command-and-control', 'exfiltration', 'impact',
]

const TACTIC_LABEL: Record<Tactic, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
}

/** One colour per tactic, early stages cool and late stages hot. Tailwind classes for chips. */
const TACTIC_CHIP: Record<Tactic, string> = {
  'reconnaissance': 'bg-sky-50 text-sky-700 border-sky-200',
  'resource-development': 'bg-cyan-50 text-cyan-700 border-cyan-200',
  'initial-access': 'bg-teal-50 text-teal-700 border-teal-200',
  'execution': 'bg-emerald-50 text-emerald-700 border-emerald-200',
  'persistence': 'bg-lime-50 text-lime-800 border-lime-200',
  'privilege-escalation': 'bg-yellow-50 text-yellow-800 border-yellow-200',
  'defense-evasion': 'bg-amber-50 text-amber-800 border-amber-200',
  'credential-access': 'bg-orange-50 text-orange-700 border-orange-200',
  'discovery': 'bg-violet-50 text-violet-700 border-violet-200',
  'lateral-movement': 'bg-purple-50 text-purple-700 border-purple-200',
  'collection': 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200',
  'command-and-control': 'bg-pink-50 text-pink-700 border-pink-200',
  'exfiltration': 'bg-rose-50 text-rose-700 border-rose-200',
  'impact': 'bg-red-50 text-red-700 border-red-200',
}

/** The same order as solid colours (hex), for graphs and timeline dots. */
export const TACTIC_COLOR: Record<Tactic, string> = {
  'reconnaissance': '#0284c7',
  'resource-development': '#0891b2',
  'initial-access': '#0d9488',
  'execution': '#059669',
  'persistence': '#65a30d',
  'privilege-escalation': '#ca8a04',
  'defense-evasion': '#d97706',
  'credential-access': '#ea580c',
  'discovery': '#7c3aed',
  'lateral-movement': '#9333ea',
  'collection': '#c026d3',
  'command-and-control': '#db2777',
  'exfiltration': '#e11d48',
  'impact': '#dc2626',
}

export function isTactic(value: string): value is Tactic {
  return (TACTIC_ORDER as string[]).includes(value)
}

export function tacticLabel(tactic: string): string {
  return isTactic(tactic) ? TACTIC_LABEL[tactic] : tactic
}

export function tacticChipClass(tactic: string): string {
  return isTactic(tactic) ? TACTIC_CHIP[tactic] : 'bg-slate-50 text-slate-600 border-slate-200'
}

export function tacticColor(tactic: string | null | undefined): string {
  return tactic && isTactic(tactic) ? TACTIC_COLOR[tactic] : '#64748b'
}

/** Tactics sorted into kill chain order, without duplicates. */
export function inKillChainOrder(tactics: string[]): string[] {
  const unique = [...new Set(tactics)]
  const rank = (t: string) => (isTactic(t) ? TACTIC_ORDER.indexOf(t) : TACTIC_ORDER.length)
  return unique.sort((a, b) => rank(a) - rank(b))
}

export const KILL_CHAIN_PHASES: KillChainStage[] = [
  'Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation',
  'Command and Control', 'Actions on Objectives',
]

// ── Risk, severity and verdicts ──────────────────────────────────────────────

export const RISK_BAND_CLASS: Record<RiskBand, string> = {
  critical: 'bg-red-50 text-red-700 border-red-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
  low: 'bg-blue-50 text-blue-700 border-blue-200',
}

export const RISK_BAND_BAR: Record<RiskBand, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-500',
  low: 'bg-blue-500',
}

const SEVERITY_LABEL: Record<number, string> = { 1: 'Info', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical' }

export function severityLabel(severity: number): string {
  return SEVERITY_LABEL[severity] ?? `Severity ${severity}`
}

export const TRIAGE_LABEL: Record<TriageVerdict, string> = {
  looks_real: 'Looks real',
  likely_noise: 'Likely noise',
}

export const TI_VERDICT_LABEL: Record<TiVerdict, string> = {
  'known-malicious': 'Known malicious',
  'suspicious': 'Suspicious',
  'no-reports': 'No reports',
  'unknown': 'Not checked',
}

export const TI_VERDICT_CLASS: Record<TiVerdict, string> = {
  'known-malicious': 'bg-red-50 text-red-700 border-red-200',
  'suspicious': 'bg-amber-50 text-amber-700 border-amber-200',
  'no-reports': 'bg-slate-50 text-slate-600 border-slate-200',
  'unknown': 'bg-slate-50 text-slate-400 border-slate-200',
}

/** Names of the risk score parts, in the order the plan's table lists them. */
export const RISK_PART_LABEL: Record<string, string> = {
  severity: 'Severity',
  stage: 'Stage reached',
  breadth: 'Breadth (tactics)',
  success: 'Got through',
  asset: 'Asset importance',
  reach: 'Reach next',
  threat_intel: 'Threat intel',
}

// ── Time ─────────────────────────────────────────────────────────────────────

/** "2026-10-29 01:51:23" (IST from the API) -> "29 Oct 2026, 01:51:23 IST". */
export function formatIst(ist: string | null | undefined): string {
  if (!ist) return '—'
  const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2}:\d{2})$/.exec(ist)
  if (!m) return ist
  const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][Number(m[2]) - 1]
  return `${Number(m[3])} ${month} ${m[1]}, ${m[4]} IST`
}

/** Readable length of a time span between two UTC ISO strings: "45 s", "12 min", "3 h 5 min", "2 d 4 h". */
export function formatSpan(startIso: string, endIso: string): string {
  const s = Math.max(0, Math.round((Date.parse(endIso) - Date.parse(startIso)) / 1000))
  if (Number.isNaN(s)) return '—'
  if (s < 60) return `${s} s`
  const min = Math.round(s / 60)
  if (min < 60) return `${min} min`
  const h = Math.floor(min / 60)
  if (h < 24) return min % 60 ? `${h} h ${min % 60} min` : `${h} h`
  const d = Math.floor(h / 24)
  return h % 24 ? `${d} d ${h % 24} h` : `${d} d`
}
