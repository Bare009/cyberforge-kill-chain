import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { AlertCircle, Bell, ChevronLeft, ChevronRight, Search, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { AlertTable, PageTitle } from '@/components/views/shared'
import { useAlerts, useUnexplained, type AlertFilters } from '@/hooks/useViews'
import { apiErrorMessage } from '@/lib/api'
import { TACTIC_ORDER, tacticLabel } from '@/lib/killchain'
import { cn } from '@/lib/utils'

const PAGE = 50
const TABS = [
  { id: 'all', label: 'All' },
  { id: 'none', label: 'Not in an incident' },
  { id: 'unexplained', label: 'Unexplained' },
] as const
type TabId = (typeof TABS)[number]['id']

/** Filters in the URL, so /alerts?technique=T1190 from the MITRE page and rule links work. */
const FILTER_KEYS = ['q', 'technique', 'tactic', 'rule', 'layer', 'severity', 'entity', 'incident'] as const

function ErrorRow({ error, retry }: { error: unknown; retry: () => void }) {
  return (
    <div role="alert" className="flex items-center gap-3 px-4 py-6 text-sm text-red-700">
      <AlertCircle className="h-4 w-4 shrink-0" />
      <span className="flex-1">Could not load alerts: {apiErrorMessage(error)}</span>
      <Button variant="outline" size="sm" onClick={retry}>Retry</Button>
    </div>
  )
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-slate-400">
      <AlertCircle className="h-7 w-7 opacity-40" />
      <span className="text-sm">{text}</span>
    </div>
  )
}

function Unexplained() {
  const { data, isLoading, isError, error, refetch } = useUnexplained()
  if (isError) return <ErrorRow error={error} retry={() => void refetch()} />
  if (isLoading || !data) return <Skeleton className="m-3 h-24" />
  return (
    <div>
      <p className="border-b border-slate-100 px-4 py-2 text-xs text-slate-500">
        {data.note} They may be early signs or noise; nothing here changes an incident.
      </p>
      {data.alerts.length === 0 ? (
        <Empty text="No unexplained activity in this run." />
      ) : (
        <AlertTable
          alerts={data.alerts}
          extra={{
            header: 'Why not an incident',
            cell: (a) => <span className="text-slate-600">{(a as (typeof data.alerts)[number]).reason ?? '—'}</span>,
          }}
        />
      )}
    </div>
  )
}

export function Alerts() {
  const [sp, setSp] = useSearchParams()
  const tab: TabId = (TABS.find((t) => t.id === sp.get('tab'))?.id ?? 'all') as TabId
  const page = Math.max(0, Number(sp.get('page') ?? 0) || 0)

  const filters = useMemo<AlertFilters>(() => {
    const sev = Number(sp.get('severity'))
    return {
      q: sp.get('q') ?? undefined,
      technique: sp.get('technique') ?? undefined,
      tactic: sp.get('tactic') ?? undefined,
      rule: sp.get('rule') ?? undefined,
      layer: sp.get('layer') ?? undefined,
      entity: sp.get('entity') ?? undefined,
      severity: sev >= 1 && sev <= 5 ? sev : undefined,
      incident: tab === 'none' ? 'none' : sp.get('incident') ?? undefined,
      sort: sp.get('sort') ?? undefined,
      limit: PAGE,
      offset: page * PAGE,
    }
  }, [sp, tab, page])

  const { data, isLoading, isError, error, refetch, isFetching } = useAlerts(filters, tab !== 'unexplained')
  // The tab badges come from any list response; the unexplained tab still needs them.
  const counts = useAlerts({ limit: 1 }, tab === 'unexplained').data?.counts ?? data?.counts
  const active = FILTER_KEYS.filter((key) => sp.get(key))

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(sp)
    if (value) next.set(key, value)
    else next.delete(key)
    if (key !== 'page') next.delete('page')
    setSp(next, { replace: true })
  }
  const clear = () => {
    const next = new URLSearchParams()
    if (tab !== 'all') next.set('tab', tab)
    setSp(next, { replace: true })
  }

  const total = data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE))
  const tabCount = (id: TabId) =>
    counts ? (id === 'all' ? counts.all : id === 'none' ? counts.not_in_incident : counts.unexplained) : null

  return (
    <div className="space-y-5">
      <PageTitle
        icon={<Bell className="h-5 w-5" />}
        title="Alerts"
        subtitle="Every rule and anomaly hit in this run, with its technique, entities and incident."
      />

      <div className="rounded-xl border border-slate-200 bg-white">
        <div role="tablist" aria-label="Alert lists" className="flex gap-1 border-b border-slate-100 px-3 pt-2">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => set('tab', t.id === 'all' ? '' : t.id)}
              className={cn(
                '-mb-px border-b-2 px-3 py-2 text-sm',
                tab === t.id ? 'border-blue-600 font-medium text-slate-900' : 'border-transparent text-slate-500 hover:text-slate-800'
              )}
            >
              {t.label}
              {tabCount(t.id) != null && <span className="ml-1.5 font-mono text-xs text-slate-400">{tabCount(t.id)}</span>}
            </button>
          ))}
        </div>

        {tab === 'unexplained' ? (
          <Unexplained />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-3 py-2">
              <div className="relative min-w-[14rem] flex-1">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                <Input aria-label="Search alerts" placeholder="Search title, rule, IP, user or domain"
                  value={sp.get('q') ?? ''} onChange={(e) => set('q', e.target.value)} className="h-8 pl-8 text-xs" />
              </div>
              <select aria-label="Tactic" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
                value={sp.get('tactic') ?? ''} onChange={(e) => set('tactic', e.target.value)}>
                <option value="">All tactics</option>
                {TACTIC_ORDER.map((t) => <option key={t} value={t}>{tacticLabel(t)}</option>)}
              </select>
              <Input aria-label="Technique" placeholder="Technique, e.g. T1190" value={sp.get('technique') ?? ''}
                onChange={(e) => set('technique', e.target.value)} className="h-8 w-40 text-xs" />
              <select aria-label="Layer" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
                value={sp.get('layer') ?? ''} onChange={(e) => set('layer', e.target.value)}>
                <option value="">Rules and anomalies</option>
                <option value="rule">Rules only</option>
                <option value="anomaly">Anomalies only</option>
              </select>
              <select aria-label="Minimum severity" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
                value={sp.get('severity') ?? ''} onChange={(e) => set('severity', e.target.value)}>
                <option value="">Any severity</option>
                <option value="5">Critical</option>
                <option value="4">High or above</option>
                <option value="3">Medium or above</option>
              </select>
              <select aria-label="Sort" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
                value={sp.get('sort') ?? 'newest'} onChange={(e) => set('sort', e.target.value === 'newest' ? '' : e.target.value)}>
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
                <option value="severity">Worst first</option>
              </select>
              {active.length > 0 && (
                <Button variant="ghost" size="sm" onClick={clear}><X className="mr-1 h-3.5 w-3.5" /> Clear filters</Button>
              )}
              <span className="ml-auto font-mono text-xs text-slate-400">{isFetching ? 'Loading…' : `${total} alerts`}</span>
            </div>
            {(sp.get('rule') || sp.get('entity') || sp.get('incident')) && (
              <div className="flex flex-wrap gap-2 border-b border-slate-100 px-3 py-1.5 text-xs text-slate-600">
                {(['rule', 'entity', 'incident'] as const).filter((k) => sp.get(k)).map((k) => (
                  <span key={k} className="flex items-center gap-1 rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5">
                    {k}: <span className="font-mono">{sp.get(k)}</span>
                    <button aria-label={`Remove ${k} filter`} onClick={() => set(k, '')}><X className="h-3 w-3" /></button>
                  </span>
                ))}
              </div>
            )}

            {isError ? (
              <ErrorRow error={error} retry={() => void refetch()} />
            ) : isLoading ? (
              <div className="space-y-2 p-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
            ) : (data?.alerts.length ?? 0) === 0 ? (
              <Empty text={active.length ? 'No alert matches these filters.' : tab === 'none' ? 'Every alert belongs to an incident.' : 'No alerts in this run.'} />
            ) : (
              <>
                <AlertTable alerts={data!.alerts} />
                {pages > 1 && (
                  <div className="flex items-center justify-end gap-2 px-3 py-2 text-xs text-slate-500">
                    <Button variant="outline" size="sm" disabled={page === 0} onClick={() => set('page', String(page - 1))} aria-label="Previous page">
                      <ChevronLeft className="h-3.5 w-3.5" />
                    </Button>
                    <span>Page {page + 1} of {pages}</span>
                    <Button variant="outline" size="sm" disabled={page + 1 >= pages} onClick={() => set('page', String(page + 1))} aria-label="Next page">
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>
    </div>
  )
}
