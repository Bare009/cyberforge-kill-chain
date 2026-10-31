import { RISK_PART_LABEL } from '@/lib/killchain'
import type { RiskPart } from '@/types/incident'

const ORDER = ['severity', 'stage', 'breadth', 'success', 'asset', 'reach', 'threat_intel']

/** Each part of the risk score (B-1): its value, its weight, and the points it adds. */
export function RiskBreakdown({ parts, score }: { parts: Record<string, RiskPart>; score: number }) {
  const keys = [...ORDER.filter((k) => k in parts), ...Object.keys(parts).filter((k) => !ORDER.includes(k))]
  return (
    <div className="space-y-1.5">
      <ul className="space-y-1">
        {keys.map((k) => {
          const p = parts[k]
          const max = p.weight * 100
          return (
            <li key={k} className="flex items-center gap-2 text-xs" title={`value ${p.value.toFixed(2)} × weight ${p.weight}`}>
              <span className="w-32 shrink-0 text-slate-600">{RISK_PART_LABEL[k] ?? k}</span>
              <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-100">
                <span className="block h-full rounded-full bg-slate-700" style={{ width: `${Math.min(100, p.value * 100)}%` }} />
              </span>
              <span className="w-20 shrink-0 text-right font-mono text-slate-700">
                {p.points.toFixed(1)} / {max.toFixed(0)}
              </span>
            </li>
          )
        })}
      </ul>
      <p className="text-right font-mono text-xs font-semibold text-slate-900">Total {score.toFixed(1)} / 100</p>
    </div>
  )
}
