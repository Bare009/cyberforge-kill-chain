import { Gauge } from 'lucide-react'
import { useHealth } from '@/hooks/useHealth'
import { cn } from '@/lib/utils'

/** Tokens used today per model against the free-tier daily limit (from GET /health). */
export function BudgetMeter({ compact = false }: { compact?: boolean }) {
  const { data } = useHealth()
  const llm = data?.llm
  if (!llm) return null
  if (llm.configured.length === 0) {
    return (
      <p className="flex items-center gap-1.5 text-xs text-slate-500">
        <Gauge className="h-3.5 w-3.5" /> No LLM configured: add a Groq key (LLM_PRIMARY_API_KEY) to .env.
      </p>
    )
  }
  const rows = llm.budget.length
    ? llm.budget
    : llm.configured.map((name) => ({ endpoint: name, tokens: 0, tokens_per_day: 0, requests: 0, paused: false }))
  return (
    <div aria-label="LLM budget today" className={cn('space-y-1.5', compact && 'space-y-1')}>
      {!compact && <p className="flex items-center gap-1.5 text-xs font-medium text-slate-700"><Gauge className="h-3.5 w-3.5" /> LLM budget today</p>}
      {rows.map((r) => {
        const share = r.tokens_per_day ? Math.min(1, r.tokens / r.tokens_per_day) : 0
        return (
          <div key={r.endpoint} className="text-xs">
            <div className="flex justify-between gap-2 text-slate-600">
              <span className="truncate font-mono" title={r.endpoint}>{r.endpoint}</span>
              <span className="shrink-0 font-mono text-slate-500">
                {r.paused ? 'paused (key refused)' : r.tokens_per_day
                  ? `${r.tokens.toLocaleString()} / ${r.tokens_per_day.toLocaleString()} tokens`
                  : 'not used today'}
              </span>
            </div>
            {r.tokens_per_day > 0 && (
              <div className="mt-0.5 h-1.5 overflow-hidden rounded-full bg-slate-100">
                <div className={cn('h-full rounded-full', share > 0.85 ? 'bg-red-500' : share > 0.6 ? 'bg-amber-500' : 'bg-emerald-500')}
                  style={{ width: `${Math.max(2, share * 100)}%` }} />
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
