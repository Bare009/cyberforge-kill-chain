import { CheckCircle2, ShieldX, Sparkles } from 'lucide-react'
import { TacticChip } from '@/components/incident/badges'
import { cn } from '@/lib/utils'
import { formatIst, formatSpan, tacticColor } from '@/lib/killchain'
import type { Step } from '@/types/incident'

/** True when two IST strings fall on the same calendar day. */
function sameDay(a: string, b: string) {
  return a.slice(0, 10) === b.slice(0, 10)
}

function StepItem({ step, last }: { step: Step; last: boolean }) {
  const color = tacticColor(step.tactic)
  return (
    <li className="relative flex gap-4 pb-5" aria-label={`Step ${step.n}`}>
      {!last && <span className="absolute left-[15px] top-8 bottom-0 w-px bg-slate-200" aria-hidden="true" />}
      <span
        className="relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full font-mono text-sm font-bold text-white"
        style={{ background: color }}
      >
        {step.n}
      </span>

      <div className="min-w-0 flex-1 space-y-1.5 rounded-lg border border-slate-200 bg-white p-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <span className="font-mono text-slate-700">{formatIst(step.ts_start_ist)}</span>
          {step.ts_end_ist !== step.ts_start_ist && (
            <span>
              to {sameDay(step.ts_start_ist, step.ts_end_ist) ? step.ts_end_ist.slice(11) : formatIst(step.ts_end_ist)} (
              {formatSpan(step.ts_start, step.ts_end)})
            </span>
          )}
          {step.ongoing && (
            <span className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-700">
              continues past later steps
            </span>
          )}
        </div>

        <p className="text-sm font-medium leading-snug text-slate-900">{step.action}</p>

        <div className="flex flex-wrap items-center gap-2">
          <TacticChip tactic={step.tactic} />
          <span className="rounded border border-red-100 bg-red-50 px-1.5 py-0.5 font-mono text-[10px] text-red-600">
            {step.technique}
          </span>
          {step.technique_name && <span className="text-xs text-slate-600">{step.technique_name}</span>}
          <span className="text-[10px] uppercase tracking-wider text-slate-400" title="7-phase kill chain">
            {step.kill_chain_stage}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
          <span className={cn('inline-flex items-center gap-1 font-medium', step.success ? 'text-red-600' : 'text-emerald-700')}>
            {step.success ? <CheckCircle2 className="h-3.5 w-3.5" /> : <ShieldX className="h-3.5 w-3.5" />}
            {step.success ? 'Got through' : 'Blocked'}
          </span>
          {(step.src || step.dst) && (
            <span className="font-mono">
              {step.src ?? '?'} → {step.dst ?? '?'}
            </span>
          )}
          <span>
            {step.line_total.toLocaleString()} log line{step.line_total === 1 ? '' : 's'} of evidence
          </span>
          <span>confidence {Math.round(step.confidence * 100)}%</span>
          {step.layer === 'anomaly' && (
            <span className="inline-flex items-center gap-1 text-violet-700" title="Found by a generic anomaly detector, not a specific rule">
              <Sparkles className="h-3.5 w-3.5" /> anomaly
            </span>
          )}
        </div>

        {step.enrichment_flags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {step.enrichment_flags.map((f) => (
              <span key={f} className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600">
                {f}
              </span>
            ))}
          </div>
        )}
      </div>
    </li>
  )
}

/** The numbered attack chain, steps 1..N in time order, then the phases with no evidence. */
export function AttackTimeline({ chain, gaps }: { chain: Step[]; gaps: string[] }) {
  return (
    <div className="space-y-3">
      {chain.length === 0 ? (
        <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">This incident has no steps.</p>
      ) : (
        <ol className="list-none">
          {chain.map((s, i) => (
            <StepItem key={s.n} step={s} last={i === chain.length - 1} />
          ))}
        </ol>
      )}
      {gaps.length > 0 && (
        <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 px-3 py-2">
          <p className="mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">Not observed</p>
          <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-600">
            {gaps.map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
