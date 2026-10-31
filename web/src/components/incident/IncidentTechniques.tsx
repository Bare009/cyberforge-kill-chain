import { Link } from 'react-router-dom'
import { TacticChip } from '@/components/incident/badges'
import { inKillChainOrder } from '@/lib/killchain'
import type { Step } from '@/types/incident'

/** This incident's techniques, one column per tactic in kill chain order (a small ATT&CK matrix). */
export function IncidentTechniques({ chain }: { chain: Step[] }) {
  const tactics = inKillChainOrder(chain.map((s) => s.tactic))
  return (
    <div className="flex gap-3 overflow-x-auto pb-1">
      {tactics.map((tactic) => {
        const techniques = new Map<string, { name: string | null; steps: number[] }>()
        for (const s of chain.filter((x) => x.tactic === tactic)) {
          const t = techniques.get(s.technique) ?? { name: s.technique_name, steps: [] }
          t.steps.push(s.n)
          techniques.set(s.technique, t)
        }
        return (
          <div key={tactic} className="w-48 shrink-0 space-y-1.5">
            <TacticChip tactic={tactic} className="w-full justify-center py-1" />
            {[...techniques.entries()].map(([id, t]) => (
              <div key={id} className="rounded-md border border-red-100 bg-red-50/60 px-2 py-1.5">
                <div className="font-mono text-[11px] font-semibold text-red-700">{id}</div>
                {t.name && <div className="text-[11px] leading-snug text-slate-700">{t.name}</div>}
                <div className="mt-0.5 flex items-center justify-between text-[10px] text-slate-500">
                  <span>step {t.steps.join(', ')}</span>
                  <Link to={`/mitre?technique=${encodeURIComponent(id)}`} className="text-blue-600 hover:underline">
                    matrix
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )
      })}
    </div>
  )
}
