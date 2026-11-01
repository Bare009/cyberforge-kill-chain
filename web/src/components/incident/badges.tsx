import { cn } from '@/lib/utils'
import {
  RISK_BAND_BAR,
  RISK_BAND_CLASS,
  TI_VERDICT_CLASS,
  TI_VERDICT_LABEL,
  TRIAGE_LABEL,
  inKillChainOrder,
  severityLabel,
  tacticChipClass,
  tacticLabel,
  vendorProduct,
} from '@/lib/killchain'
import type { RiskBand, TechniqueSource, TiVerdict, TriageVerdict } from '@/types/incident'

export function TacticChip({ tactic, className }: { tactic: string; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap',
        tacticChipClass(tactic),
        className
      )}
    >
      {tacticLabel(tactic)}
    </span>
  )
}

/** Tactic chips in kill chain order. */
export function TacticChips({ tactics, max }: { tactics: string[]; max?: number }) {
  const ordered = inKillChainOrder(tactics)
  const shown = max ? ordered.slice(0, max) : ordered
  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((t) => (
        <TacticChip key={t} tactic={t} />
      ))}
      {max && ordered.length > max && <span className="text-[10px] text-slate-400">+{ordered.length - max}</span>}
    </div>
  )
}

export function RiskBandBadge({ band }: { band: RiskBand }) {
  return (
    <span className={cn('rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase', RISK_BAND_CLASS[band])}>
      {band}
    </span>
  )
}

/** Score out of 100 as a bar, coloured by band. */
export function RiskBar({ score, band, className }: { score: number; band: RiskBand; className?: string }) {
  const width = Math.max(0, Math.min(100, score))
  return (
    <div className={cn('flex items-center gap-2', className)} title={`Risk ${score.toFixed(1)} of 100`}>
      <span className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-100">
        <span className={cn('block h-full rounded-full', RISK_BAND_BAR[band])} style={{ width: `${width}%` }} />
      </span>
      <span className="font-mono text-xs font-semibold text-slate-800">{Math.round(score)}</span>
    </div>
  )
}

export function SeverityText({ severity }: { severity: number }) {
  const tone =
    severity >= 5 ? 'text-red-600' : severity >= 4 ? 'text-orange-600' : severity >= 3 ? 'text-amber-600' : 'text-slate-500'
  return <span className={cn('text-xs font-medium', tone)}>{severityLabel(severity)}</span>
}

export function TriageBadge({ verdict }: { verdict: TriageVerdict | null | undefined }) {
  if (!verdict) return null
  const cls =
    verdict === 'looks_real'
      ? 'bg-red-50 text-red-700 border-red-200'
      : 'bg-slate-50 text-slate-500 border-slate-200'
  return (
    <span
      className={cn('rounded border px-1.5 py-0.5 text-[10px] font-medium', cls)}
      title="AI triage opinion; it never hides or reorders an incident"
    >
      AI: {TRIAGE_LABEL[verdict]}
    </span>
  )
}

export function TiVerdictBadge({ verdict }: { verdict: TiVerdict | null | undefined }) {
  if (!verdict) return null
  return (
    <span
      className={cn('rounded border px-1.5 py-0.5 text-[10px] font-medium', TI_VERDICT_CLASS[verdict])}
      title="External threat-intel reputation of the incident's entities"
    >
      TI: {TI_VERDICT_LABEL[verdict]}
    </span>
  )
}

const TECHNIQUE_SOURCE_TEXT: Record<TechniqueSource, string> = {
  vendor: "ATT&CK label from the product's own fields",
  keyword: 'ATT&CK label from a keyword in the alert name',
  llm: 'ATT&CK label suggested by the LLM',
  unknown: 'no ATT&CK label: the product gave none and no keyword matched',
}

/** "Vendor" badge for an alert another security product raised. */
export function VendorBadge({ ruleId, techniqueSource }: { ruleId?: string | null; techniqueSource?: TechniqueSource | null }) {
  const product = vendorProduct(ruleId)
  const how = techniqueSource ? TECHNIQUE_SOURCE_TEXT[techniqueSource] : null
  return (
    <span
      className="rounded border border-teal-200 bg-teal-50 px-1 text-[10px] text-teal-700"
      title={[`Alert raised by ${product ?? 'another security product'}`, how].filter(Boolean).join('; ')}
    >
      Vendor{product ? ` · ${product}` : ''}
      {techniqueSource && techniqueSource !== 'vendor' ? ` · label: ${techniqueSource}` : ''}
    </span>
  )
}
