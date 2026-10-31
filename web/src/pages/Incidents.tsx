import { useMemo, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { AlertCircle, Layers, ListOrdered, Search, ShieldAlert, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { RiskBandBadge, RiskBar, SeverityText, TacticChips, TiVerdictBadge, TriageBadge } from '@/components/incident/badges'
import { useIncidents, type IncidentFilters } from '@/hooks/useIncidents'
import { apiErrorMessage } from '@/lib/api'
import { TACTIC_ORDER, formatIst, formatSpan, tacticLabel } from '@/lib/killchain'
import { useLiveStore } from '@/store/useLiveStore'
import type { IndexRow } from '@/types/incident'

/** Filters live in the URL so links like /incidents?technique=T1190 (from the MITRE page) work. */
const FILTER_KEYS = ['q', 'tactic', 'technique', 'entity', 'severity'] as const

function StatCard({ label, value, icon, loading }: { label: string; value: string; icon: ReactNode; loading: boolean }) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-white p-4">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-slate-50">{icon}</div>
      <div>
        {loading ? <Skeleton className="mb-1 h-7 w-12" /> : <div className="text-2xl font-bold text-slate-900">{value}</div>}
        <div className="text-xs uppercase tracking-wider text-slate-500">{label}</div>
      </div>
    </div>
  )
}

function IncidentRow({ row }: { row: IndexRow }) {
  const live = useLiveStore((s) => s.changed[row.incident_number])
  return (
    <Link
      to={`/incidents/${row.incident_number}`}
      className="grid grid-cols-[3rem_1fr] gap-x-3 gap-y-1.5 border-b border-slate-100 px-4 py-3 transition-colors hover:bg-slate-50 md:grid-cols-[3rem_minmax(0,1fr)_9rem_11rem]"
      aria-label={`Incident ${row.incident_number}: ${row.title}`}
    >
      <span className="row-span-2 self-start font-mono text-lg font-bold text-slate-400">#{row.incident_number}</span>

      <div className="min-w-0 space-y-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-sm font-semibold text-slate-900">{row.title}</span>
          {live && (
            <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-bold uppercase text-emerald-700"
              title={`Changed by live mode at ${live}`}>
              Live
            </span>
          )}
          <RiskBandBadge band={row.risk_band} />
          <TriageBadge verdict={row.triage_verdict} />
          <TiVerdictBadge verdict={row.ti_verdict} />
        </div>
        <TacticChips tactics={row.tactics} />
      </div>

      <div className="col-start-2 space-y-1 md:col-start-auto">
        <RiskBar score={row.risk_score} band={row.risk_band} />
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <SeverityText severity={row.severity} />
          <span title="Raw alerts and log events merged into this incident (B-3)">
            {row.merged.alerts} alerts · {row.merged.events.toLocaleString()} events
          </span>
        </div>
      </div>

      <div className="col-start-2 text-xs text-slate-500 md:col-start-auto">
        <div>{formatIst(row.ts_start_ist)}</div>
        <div className="text-slate-400">
          to {formatIst(row.ts_end_ist)} ({formatSpan(row.ts_start, row.ts_end)})
        </div>
      </div>
    </Link>
  )
}

export function Incidents() {
  const [searchParams, setSearchParams] = useSearchParams()

  const filters = useMemo<IncidentFilters>(() => {
    const sev = Number(searchParams.get('severity'))
    return {
      q: searchParams.get('q') ?? undefined,
      tactic: searchParams.get('tactic') ?? undefined,
      technique: searchParams.get('technique') ?? undefined,
      entity: searchParams.get('entity') ?? undefined,
      severity: sev >= 1 && sev <= 5 ? sev : undefined,
      limit: 500,
    }
  }, [searchParams])

  const { data, isLoading, isError, error, refetch, isFetching } = useIncidents(filters)
  const rows = data?.incidents ?? []
  const active = FILTER_KEYS.filter((k) => searchParams.get(k))

  const setFilter = (key: (typeof FILTER_KEYS)[number], value: string) => {
    const next = new URLSearchParams(searchParams)
    if (value) next.set(key, value)
    else next.delete(key)
    setSearchParams(next, { replace: true })
  }

  const critical = rows.filter((r) => r.risk_band === 'critical' || r.risk_band === 'high').length
  const alerts = rows.reduce((n, r) => n + r.merged.alerts, 0)
  const events = rows.reduce((n, r) => n + r.merged.events, 0)

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 text-blue-600">
          <ListOrdered className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Incidents</h1>
          <p className="text-sm text-slate-500">
            Linked attack steps, worst first. Open one to read its numbered attack chain.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Incidents" value={String(data?.total ?? 0)} loading={isLoading} icon={<ShieldAlert className="h-5 w-5 text-red-500" />} />
        <StatCard label="Critical or high" value={String(critical)} loading={isLoading} icon={<AlertCircle className="h-5 w-5 text-orange-500" />} />
        <StatCard label="Alerts merged" value={alerts.toLocaleString()} loading={isLoading} icon={<Layers className="h-5 w-5 text-blue-500" />} />
        <StatCard label="Log events merged" value={events.toLocaleString()} loading={isLoading} icon={<Layers className="h-5 w-5 text-slate-500" />} />
      </div>

      <div className="rounded-xl border border-slate-200 bg-white">
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-3 py-2">
          <div className="relative min-w-[14rem] flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              aria-label="Search incidents"
              placeholder="Search title, IP, host, user or domain"
              value={searchParams.get('q') ?? ''}
              onChange={(e) => setFilter('q', e.target.value)}
              className="h-8 pl-8 text-xs"
            />
          </div>
          <select
            aria-label="Tactic"
            className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
            value={searchParams.get('tactic') ?? ''}
            onChange={(e) => setFilter('tactic', e.target.value)}
          >
            <option value="">All tactics</option>
            {TACTIC_ORDER.map((t) => (
              <option key={t} value={t}>
                {tacticLabel(t)}
              </option>
            ))}
          </select>
          <Input
            aria-label="Technique"
            placeholder="Technique, e.g. T1190"
            value={searchParams.get('technique') ?? ''}
            onChange={(e) => setFilter('technique', e.target.value)}
            className="h-8 w-40 text-xs"
          />
          <Input
            aria-label="Entity"
            placeholder="Exact IP, host or user"
            value={searchParams.get('entity') ?? ''}
            onChange={(e) => setFilter('entity', e.target.value)}
            className="h-8 w-44 text-xs"
          />
          <select
            aria-label="Minimum severity"
            className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
            value={searchParams.get('severity') ?? ''}
            onChange={(e) => setFilter('severity', e.target.value)}
          >
            <option value="">Any severity</option>
            <option value="5">Critical</option>
            <option value="4">High or above</option>
            <option value="3">Medium or above</option>
          </select>
          {active.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}>
              <X className="mr-1 h-3.5 w-3.5" /> Clear filters
            </Button>
          )}
          <span className="ml-auto font-mono text-xs text-slate-400">{isFetching ? 'Loading…' : `${rows.length} shown`}</span>
        </div>

        {isError ? (
          <div role="alert" className="flex items-center gap-3 px-4 py-6 text-sm text-red-700">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span className="flex-1">Could not load incidents: {apiErrorMessage(error)}</span>
            <Button variant="outline" size="sm" onClick={() => void refetch()}>
              Retry
            </Button>
          </div>
        ) : isLoading ? (
          <div className="space-y-2 p-3">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-16 w-full rounded-lg" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-12 text-slate-400">
            <AlertCircle className="h-7 w-7 opacity-40" />
            <span className="text-sm">{active.length ? 'No incident matches these filters.' : 'No incidents in this run.'}</span>
          </div>
        ) : (
          <div>
            {rows.map((row) => (
              <IncidentRow key={row.incident_id} row={row} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
