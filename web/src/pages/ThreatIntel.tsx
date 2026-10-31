import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import { AlertCircle, Globe, Info, Search, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { TiVerdictBadge } from '@/components/incident/badges'
import { EntityIntelCard } from '@/components/ti/IntelCards'
import { useTiIndicator, useTiIndicators, useTiLookup, useTiStatus } from '@/hooks/useThreatIntel'
import { apiErrorMessage } from '@/lib/api'
import { TI_VERDICT_LABEL } from '@/lib/killchain'
import { providerLabel } from '@/lib/threatIntel'
import { cn, formatFullTime } from '@/lib/utils'
import type { TiVerdict } from '@/types/incident'

const VERDICTS: TiVerdict[] = ['known-malicious', 'suspicious', 'no-reports', 'unknown']
const PROVIDER_STATE: Record<string, { text: string; tone: string }> = {
  ok: { text: 'on', tone: 'text-emerald-700' },
  offline: { text: 'offline (cache only)', tone: 'text-amber-700' },
  'no key': { text: 'no API key', tone: 'text-amber-700' },
  disabled: { text: 'disabled', tone: 'text-slate-500' },
}

function StatusCard() {
  const { data } = useTiStatus()
  if (!data) return <Skeleton className="h-20 w-full rounded-xl" />
  return (
    <Card>
      <CardContent className="grid gap-4 p-4 md:grid-cols-[1fr_1fr_1.4fr]">
        <div className="space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-slate-500">Providers</p>
          {Object.entries(data.providers).map(([name, state]) => (
            <p key={name} className="text-sm">
              <span className="font-medium text-slate-800">{providerLabel(name)}</span>{' '}
              <span className={PROVIDER_STATE[state]?.tone ?? 'text-slate-500'}>{PROVIDER_STATE[state]?.text ?? state}</span>
            </p>
          ))}
        </div>
        <div className="space-y-1 text-sm">
          <p className="text-[11px] uppercase tracking-wider text-slate-500">Results</p>
          <p className="text-slate-700">
            {data.indicators} indicators from {data.source === 'enrichment.json' ? 'the last engine run' : 'the incident files'}
          </p>
          {data.generated_at && <p className="text-xs text-slate-500">Looked up {formatFullTime(data.generated_at)}</p>}
          {data.last_run && (
            <p className="text-xs text-slate-500">
              {data.last_run.lookups} {data.last_run.lookups === 1 ? 'lookup' : 'lookups'}, {data.last_run.cache_hits} from cache, {data.last_run.skipped_private} kept local
            </p>
          )}
        </div>
        <div className="flex gap-2 text-xs text-slate-600">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            External reputation only. Private, reserved and internal values are never sent outside. The data set's
            addresses are synthetic, so most come back with no reports; a hit may be unrelated history of a reused real
            address. Threat intel never changes which incidents or steps exist.
          </span>
        </div>
      </CardContent>
    </Card>
  )
}

function IndicatorDrawer({ value, onClose }: { value: string | null; onClose: () => void }) {
  const { data, isLoading, isError, error } = useTiIndicator(value)
  return (
    <Dialog open={!!value} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="left-auto right-0 top-0 h-full max-w-xl translate-x-0 translate-y-0 content-start gap-3 overflow-y-auto rounded-none sm:rounded-none">
        <DialogTitle className="break-all pr-6 font-mono text-base">{value}</DialogTitle>
        <DialogDescription className="text-xs">Every provider's answer for this indicator.</DialogDescription>
        {isLoading ? (
          <Skeleton className="h-40 w-full" />
        ) : isError || !data ? (
          <p role="alert" className="text-sm text-red-700">{apiErrorMessage(error, 'Could not load this indicator')}</p>
        ) : (
          <>
            <EntityIntelCard
              value={data.value}
              kind={data.kind}
              zone={data.zone}
              verdict={data.verdict}
              reputation={data.reputation}
              providers={data.providers}
              flags={data.flags}
              sendable={data.sendable}
            />
            {data.incidents.length > 0 && (
              <div className="space-y-1">
                <p className="text-[11px] uppercase tracking-wider text-slate-500">In incidents</p>
                {data.incidents.map((i) => (
                  <Link key={i.incident_number} to={`/incidents/${i.incident_number}?tab=intel`} onClick={onClose} className="block text-sm text-blue-700 hover:underline">
                    #{i.incident_number} {i.title}
                  </Link>
                ))}
              </div>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function LookupBox() {
  const [value, setValue] = useState('')
  const lookup = useTiLookup()
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (value.trim()) lookup.mutate(value.trim())
  }
  const err = lookup.error
  const status = axios.isAxiosError(err) ? err.response?.status : undefined
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[16rem] flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              aria-label="Look up an indicator"
              placeholder="Look up an IP, domain, URL or file hash"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className="h-9 pl-8 font-mono text-xs"
            />
          </div>
          <Button type="submit" size="sm" disabled={!value.trim() || lookup.isPending}>
            {lookup.isPending ? 'Looking up…' : 'Look up'}
          </Button>
        </form>
        {err && (
          <p role="alert" className={cn('text-sm', status === 429 ? 'text-amber-700' : 'text-red-700')}>
            {apiErrorMessage(err, 'Lookup failed')}
          </p>
        )}
        {lookup.data && (
          <div className="space-y-2">
            <EntityIntelCard
              value={lookup.data.value}
              kind={lookup.data.kind}
              zone={lookup.data.zone}
              verdict={lookup.data.verdict}
              reputation={lookup.data.reputation}
              providers={lookup.data.providers}
              flags={lookup.data.flags}
              sendable={lookup.data.sendable}
              notSentBecause={lookup.data.not_sent_because}
            />
            <p className="text-xs text-slate-500">
              {lookup.data.in_run
                ? `Seen in this run, in ${lookup.data.incidents.map((i) => `incident ${i.incident_number}`).join(', ') || 'no incident'}.`
                : 'Not seen in this run.'}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function ThreatIntel() {
  const [sp, setSp] = useSearchParams()
  const [open, setOpen] = useState<string | null>(null)
  const filters = {
    verdict: sp.get('verdict') ?? undefined,
    kind: sp.get('kind') ?? undefined,
    q: sp.get('q') ?? undefined,
    sendable: sp.get('sendable') === 'true' ? true : undefined,
  }
  const { data, isLoading, isError, error } = useTiIndicators(filters)
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(sp)
    if (v) next.set(k, v)
    else next.delete(k)
    setSp(next, { replace: true })
  }
  const anyFilter = ['verdict', 'kind', 'q', 'sendable'].some((k) => sp.get(k))

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 text-blue-600">
          <Globe className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Threat Intel</h1>
          <p className="text-sm text-slate-500">Every IP, domain, URL and hash in the incidents, with local context and AlienVault OTX.</p>
        </div>
      </div>

      <StatusCard />
      <LookupBox />

      <div className="rounded-xl border border-slate-200 bg-white">
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-3 py-2">
          <Input aria-label="Search indicators" placeholder="Search value or tag" value={sp.get('q') ?? ''} onChange={(e) => set('q', e.target.value)} className="h-8 w-56 text-xs" />
          <select aria-label="Verdict" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600" value={sp.get('verdict') ?? ''} onChange={(e) => set('verdict', e.target.value)}>
            <option value="">Any verdict</option>
            {VERDICTS.map((v) => (
              <option key={v} value={v}>
                {TI_VERDICT_LABEL[v]}
              </option>
            ))}
          </select>
          <select aria-label="Kind" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600" value={sp.get('kind') ?? ''} onChange={(e) => set('kind', e.target.value)}>
            <option value="">Any kind</option>
            {['ip', 'domain', 'url', 'hash'].map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-xs text-slate-700">
            <Checkbox checked={sp.get('sendable') === 'true'} onCheckedChange={(v) => set('sendable', v === true ? 'true' : '')} />
            Only values checked outside
          </label>
          {anyFilter && (
            <Button variant="ghost" size="sm" onClick={() => setSp(new URLSearchParams(), { replace: true })}>
              <X className="mr-1 h-3.5 w-3.5" /> Clear
            </Button>
          )}
          <span className="ml-auto font-mono text-xs text-slate-400">{data ? `${data.total} indicators` : ''}</span>
        </div>

        {isError ? (
          <p role="alert" className="flex items-center gap-2 px-4 py-6 text-sm text-red-700">
            <AlertCircle className="h-4 w-4" /> Could not load indicators: {apiErrorMessage(error)}
          </p>
        ) : isLoading || !data ? (
          <div className="space-y-2 p-3">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : data.indicators.length === 0 ? (
          <p className="py-10 text-center text-sm text-slate-400">{anyFilter ? 'No indicator matches these filters.' : 'No indicators in this run.'}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-slate-50 text-left text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Indicator</th>
                  <th className="px-3 py-2 font-medium">Kind</th>
                  <th className="px-3 py-2 font-medium">Verdict</th>
                  <th className="px-3 py-2 font-medium">OTX pulses</th>
                  <th className="px-3 py-2 font-medium">Flags</th>
                  <th className="px-3 py-2 font-medium">Incidents</th>
                </tr>
              </thead>
              <tbody>
                {data.indicators.map((r) => (
                  <tr key={r.value} className="border-t border-slate-100 align-top hover:bg-slate-50">
                    <td className="px-3 py-2">
                      <button type="button" onClick={() => setOpen(r.value)} className="break-all text-left font-mono font-semibold text-blue-700 hover:underline">
                        {r.value}
                      </button>
                      {r.sendable === false && <div className="text-[10px] text-slate-400">kept local</div>}
                    </td>
                    <td className="px-3 py-2 text-slate-600">
                      {r.kind}
                      {r.zone ? ` · ${r.zone}` : ''}
                    </td>
                    <td className="px-3 py-2">
                      <TiVerdictBadge verdict={r.verdict} />
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-700">{r.pulses ?? '—'}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {r.flags.map((f) => (
                          <span key={f} className="rounded bg-red-50 px-1.5 py-0.5 text-[10px] text-red-700">
                            {f}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      {r.incidents.map((i) => (
                        <Link key={i.incident_number} to={`/incidents/${i.incident_number}?tab=intel`} className="mr-2 text-blue-700 hover:underline" title={i.title}>
                          #{i.incident_number}
                        </Link>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <IndicatorDrawer value={open} onClose={() => setOpen(null)} />
    </div>
  )
}
