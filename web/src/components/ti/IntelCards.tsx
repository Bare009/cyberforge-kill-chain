import { ExternalLink, ShieldCheck, ShieldOff } from 'lucide-react'
import { TiVerdictBadge } from '@/components/incident/badges'
import { cn } from '@/lib/utils'
import { otxView, providerHighlights, providerLabel } from '@/lib/threatIntel'
import type { Enrichment, ProviderResult, TiVerdict, Zone } from '@/types/incident'

function TagList({ items, max = 10 }: { items: string[]; max?: number }) {
  if (items.length === 0) return null
  const shown = items.slice(0, max)
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((t) => (
        <span key={t} className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[10px] text-amber-900">
          {t}
        </span>
      ))}
      {items.length > max && <span className="self-center text-[10px] text-slate-500">+{items.length - max} more</span>}
    </div>
  )
}

/** One provider's answer for one indicator. */
export function ProviderCard({ result }: { result: ProviderResult }) {
  const otx = otxView(result)
  return (
    <div
      className={cn(
        'space-y-1.5 rounded-lg border p-2.5 text-xs',
        result.malicious ? 'border-red-200 bg-red-50/40' : 'border-slate-200 bg-white',
        !result.available && 'border-dashed bg-slate-50'
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-slate-800">{providerLabel(result.provider)}</span>
        {result.malicious && <span className="text-[10px] font-semibold uppercase text-red-700">flagged</span>}
        {result.score != null && <span className="font-mono text-[11px] text-slate-500">score {result.score.toFixed(2)}</span>}
        {otx?.url && (
          <a href={otx.url} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 text-blue-600 hover:underline">
            OTX page <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>
      <p className="leading-snug text-slate-700">{providerHighlights(result).join(' · ')}</p>
      {otx && otx.topPulses.length > 0 && (
        <ul className="space-y-0.5">
          {otx.topPulses.map((p, i) => (
            <li key={p.id ?? i} className="truncate">
              {p.url ? (
                <a href={p.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                  {p.name ?? p.id}
                </a>
              ) : (
                <span>{p.name ?? p.id}</span>
              )}
              {p.created && <span className="text-slate-400"> · {p.created.slice(0, 10)}</span>}
            </li>
          ))}
        </ul>
      )}
      {otx && <TagList items={otx.tags} />}
      {otx && otx.validation.length > 0 && <p className="text-[11px] text-slate-500">OTX: {otx.validation.join('; ')}</p>}
    </div>
  )
}

interface EntityProps {
  value: string
  kind: Enrichment['kind']
  zone: Zone | null
  verdict: TiVerdict
  reputation: number
  providers: ProviderResult[]
  flags?: string[]
  sendable?: boolean | null
  notSentBecause?: string | null
  onOpen?: (value: string) => void
}

/** An indicator with its verdict and every provider's answer. */
export function EntityIntelCard({ value, kind, zone, verdict, reputation, providers, flags = [], sendable, notSentBecause, onOpen }: EntityProps) {
  const reason =
    notSentBecause ??
    (providers.find((p) => p.provider === 'local')?.detail.not_sent_because as string | null | undefined) ??
    null
  return (
    <div className="space-y-2 rounded-lg border border-slate-200 bg-white p-3" aria-label={`Threat intel for ${value}`}>
      <div className="flex flex-wrap items-center gap-2">
        {onOpen ? (
          <button type="button" onClick={() => onOpen(value)} className="break-all font-mono text-sm font-semibold text-blue-700 hover:underline">
            {value}
          </button>
        ) : (
          <span className="break-all font-mono text-sm font-semibold text-slate-900">{value}</span>
        )}
        <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600">
          {kind}
          {zone ? ` · ${zone}` : ''}
        </span>
        <TiVerdictBadge verdict={verdict} />
        <span className="flex items-center gap-1.5 text-[11px] text-slate-500" title="Highest score from an outside provider">
          <span className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-100">
            <span className="block h-full rounded-full bg-red-500" style={{ width: `${Math.round(reputation * 100)}%` }} />
          </span>
          {reputation.toFixed(2)}
        </span>
        {sendable === false ? (
          <span className="ml-auto inline-flex items-center gap-1 text-[11px] text-slate-500" title={reason ?? undefined}>
            <ShieldOff className="h-3.5 w-3.5" /> kept local{reason ? `: ${reason}` : ''}
          </span>
        ) : sendable ? (
          <span className="ml-auto inline-flex items-center gap-1 text-[11px] text-slate-500">
            <ShieldCheck className="h-3.5 w-3.5" /> checked outside
          </span>
        ) : null}
      </div>
      {flags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {flags.map((f) => (
            <span key={f} className="rounded bg-red-50 px-1.5 py-0.5 text-[10px] font-medium text-red-700">
              {f}
            </span>
          ))}
        </div>
      )}
      <div className="grid gap-2 md:grid-cols-2">
        {providers.map((p) => (
          <ProviderCard key={p.provider} result={p} />
        ))}
      </div>
    </div>
  )
}
