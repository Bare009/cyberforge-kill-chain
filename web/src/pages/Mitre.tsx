import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { Info, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { AttackMatrix } from '@/components/mitre/AttackMatrix'
import { TechniqueDetailPanel } from '@/components/mitre/TechniqueDetailPanel'
import { SEVERITY_TEXT, pct } from '@/components/mitre/heat'
import { exportMatrix, fetchMitreMatrix, incidentsLink } from '@/lib/mitre-api'
import { cn, getDisplayTimeZone } from '@/lib/utils'
import { describeWindow } from '@/lib/timeRange'
import type { MitrePreset, MitreQuery, SeverityLabel } from '@/types/mitre'

/** A range passed in the URL (?start=&end=, ISO instants), e.g. by the dashboard's Matrix link. */
function urlWindow(sp: URLSearchParams): { start: string; end: string } | null {
  const s = Date.parse(sp.get('start') ?? '')
  const e = Date.parse(sp.get('end') ?? '')
  if (Number.isNaN(s) || Number.isNaN(e) || e <= s) return null
  return { start: new Date(s).toISOString(), end: new Date(e).toISOString() }
}

/** A technique id passed in the URL (?technique=T1190), normalised; null when absent or invalid. */
function urlTechnique(sp: URLSearchParams): string | null {
  const t = (sp.get('technique') ?? '').trim().toUpperCase()
  return /^T\d{4}(\.\d{3})?$/.test(t) ? t : null
}

const PRESETS: { value: MitrePreset; label: string }[] = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: '90d', label: '90d' },
]

function Kpi({ value, label, hint, tone }: { value: string; label: string; hint?: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
      <div className={cn('font-mono text-xl font-semibold text-slate-900', tone)}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
      {hint && <div className="text-[11px] text-slate-400">{hint}</div>}
    </div>
  )
}

export function Mitre() {
  const [preset, setPreset] = useState<MitrePreset>('30d')
  const [searchParams, setSearchParams] = useSearchParams()
  // The dashboard's range, when the page was opened from it. A preset button replaces it.
  const [custom, setCustom] = useState(() => urlWindow(searchParams))
  const [onlyObserved, setOnlyObserved] = useState(true)
  // ?technique=T1190 (from an incident's ATT&CK tab) opens that technique's detail.
  const [selected, setSelected] = useState<string | null>(() => urlTechnique(searchParams))
  const zone = getDisplayTimeZone()

  // Taken into state above; drop them from the address bar so they do not come back on reload.
  useEffect(() => {
    if (searchParams.has('start') || searchParams.has('end') || searchParams.has('technique')) {
      setSearchParams(new URLSearchParams(), { replace: true })
    }
  }, [searchParams, setSearchParams])

  const query = useMemo<MitreQuery>(
    () => (custom ? { start: custom.start, end: custom.end } : { preset }),
    [custom, preset]
  )
  const { data, isLoading, isError, error, isFetching } = useQuery({
    queryKey: ['mitre', 'matrix', query],
    queryFn: () => fetchMitreMatrix(query),
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  })

  const s = data?.summary

  if (isError) {
    return (
      <div className="space-y-4">
        <h1 className="font-semibold text-2xl text-slate-900">MITRE ATT&amp;CK</h1>
        <Card>
          <CardContent className="py-8 text-center text-sm text-red-600">
            {(error as Error)?.message ?? 'Could not load the ATT&CK matrix.'}
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-2xl text-slate-900">MITRE ATT&amp;CK</h1>
          <p className="text-sm text-slate-500">
            Every enterprise tactic and technique, shaded by the alerts mapped to it. Click a cell for
            the detail and a way into the matching incidents.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex gap-1" role="group" aria-label="Period">
            {custom && (
              <span className="inline-flex items-center gap-1 rounded-md border border-blue-200 bg-blue-50 px-2 text-xs text-blue-900">
                {describeWindow(custom.start, custom.end, zone)} ({zone})
                <button
                  type="button"
                  className="text-blue-500 hover:text-blue-800"
                  aria-label="Clear the range from the dashboard"
                  onClick={() => setCustom(null)}
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            )}
            {PRESETS.map((p) => (
              <Button
                key={p.value}
                size="sm"
                variant={!custom && preset === p.value ? 'default' : 'ghost'}
                aria-pressed={!custom && preset === p.value}
                onClick={() => { setPreset(p.value); setCustom(null) }}
              >
                {p.label}
              </Button>
            ))}
          </div>
          <Button size="sm" variant="outline" disabled={!data} onClick={() => data && exportMatrix(data, 'csv')}>
            ↓ CSV
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!data}
            title="ATT&CK Navigator layer, to open at mitre-attack.github.io/attack-navigator"
            onClick={() => data && exportMatrix(data, 'navigator', 'KillChain')}
          >
            ↓ Navigator layer
          </Button>
          <Button size="sm" variant="outline" disabled={!data} onClick={() => data && exportMatrix(data, 'json')}>
            ↓ JSON
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi
          value={isLoading || !s ? '—' : `${s.techniquesSeen}/${s.techniquesTotal}`}
          label="Techniques observed"
          hint={s ? `${pct(s.techniquesSeen, s.techniquesTotal)}% of ATT&CK enterprise` : undefined}
        />
        <Kpi
          value={isLoading || !s ? '—' : `${s.tacticsSeen}/${s.tacticsTotal}`}
          label="Tactics observed"
        />
        <Kpi
          value={isLoading || !s ? '—' : `${s.subtechniquesSeen}/${s.subtechniquesTotal}`}
          label="Sub-techniques observed"
        />
        <Kpi
          value={isLoading || !s ? '—' : s.alertsMapped.toLocaleString()}
          label="Alerts mapped"
          hint={s ? `of ${s.alertsTotal.toLocaleString()} in this period` : undefined}
        />
        <Kpi
          value={isLoading || !s ? '—' : s.alertsUnmapped.toLocaleString()}
          label="Alerts not mapped"
          hint={s && s.alertsTotal ? `${pct(s.alertsUnmapped, s.alertsTotal)}% of the period` : undefined}
          tone={s && s.alertsUnmapped > 0 ? 'text-amber-700' : undefined}
        />
        <Kpi
          value={isLoading || !s ? '—' : (data?.topTechniques[0]?.id ?? '—')}
          label="Busiest technique"
          hint={data?.topTechniques[0] ? `${data.topTechniques[0].alerts.toLocaleString()} alerts` : undefined}
        />
      </div>

      <p className="flex gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>
          &ldquo;Observed&rdquo; means alerts were mapped to the technique in this period. A technique with
          no alerts may be well defended, out of scope, or simply not detected &mdash; nothing here tells
          those apart, so this is not detection coverage. Cell shade is the alert volume (log scale) and
          the hue is the worst severity in the cell. A technique serving several tactics appears in each
          of its columns, which is why column totals are not added up. The logs are historical, so a
          period counts back from the last event in the run, not from today.
        </span>
      </p>

      <Card>
        <CardContent className="space-y-3 pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-xs text-slate-700">
                <Checkbox checked={onlyObserved} onCheckedChange={(v) => setOnlyObserved(v === true)} />
                Only techniques with alerts
              </label>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-slate-500">
              {isFetching && <span>Refreshing…</span>}
              <span className="flex items-center gap-1">
                Volume
                <span className="inline-block h-2.5 w-6 rounded-sm" style={{ background: 'rgba(37,99,235,0.2)' }} />
                <span className="inline-block h-2.5 w-6 rounded-sm" style={{ background: 'rgba(37,99,235,0.55)' }} />
                <span className="inline-block h-2.5 w-6 rounded-sm" style={{ background: 'rgba(37,99,235,0.9)' }} />
              </span>
            </div>
          </div>

          {isLoading || !data ? (
            <div className="py-16 text-center text-sm text-slate-500">Loading the matrix…</div>
          ) : (
            <AttackMatrix
              matrix={data}
              onlyObserved={onlyObserved}
              selectedId={selected}
              onSelect={(id) => setSelected((prev) => (prev === id ? null : id))}
            />
          )}
        </CardContent>
      </Card>

      {selected && (
        <TechniqueDetailPanel
          techniqueId={selected}
          query={query}
          onSelect={setSelected}
          onClose={() => setSelected(null)}
        />
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <div>
          <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-slate-500">
            Busiest techniques
          </h2>
          <Card>
            <CardContent className="pt-4">
              {isLoading ? (
                <p className="py-6 text-center text-sm text-slate-500">Loading…</p>
              ) : (data?.topTechniques.length ?? 0) === 0 ? (
                <p className="py-6 text-center text-sm text-slate-400">
                  No alerts were mapped to a technique in this period.
                </p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {data!.topTechniques.map((t) => (
                    <li key={t.id} className="flex flex-wrap items-center gap-2 py-2 text-xs">
                      <button
                        type="button"
                        className="rounded border border-red-100 bg-red-50 px-1.5 py-0.5 font-mono text-red-600 hover:underline"
                        onClick={() => setSelected(t.id)}
                      >
                        {t.id}
                      </button>
                      <span className="min-w-0 flex-1 truncate text-slate-800">{t.name}</span>
                      <span className="hidden shrink-0 text-slate-400 sm:inline">{t.tactics.join(', ')}</span>
                      {t.maxSeverity && (
                        <span className={cn('shrink-0 font-medium', SEVERITY_TEXT[t.maxSeverity as SeverityLabel])}>
                          {t.maxSeverity}
                        </span>
                      )}
                      <span className="w-14 shrink-0 text-right font-mono text-slate-700">
                        {t.alerts.toLocaleString()}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <div>
          <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-slate-500">
            Coverage by tactic
          </h2>
          <Card>
            <CardContent className="pt-4">
              <ul className="space-y-1.5">
                {(data?.tactics ?? []).map((t) => (
                  <li key={t.id} className="flex items-center gap-2 text-xs">
                    <Link
                      to={incidentsLink({ tactic: t.shortname })}
                      className="w-36 shrink-0 truncate text-slate-700 hover:text-blue-700 hover:underline"
                      title={`Incidents with a ${t.name} step`}
                    >
                      {t.name}
                    </Link>
                    <span className="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
                      <span
                        className="block h-full rounded-full bg-blue-500"
                        style={{ width: `${pct(t.techniquesSeen, t.techniquesTotal)}%` }}
                      />
                    </span>
                    <span className="w-16 shrink-0 text-right font-mono text-slate-500">
                      {t.techniquesSeen}/{t.techniquesTotal}
                    </span>
                    <span className="w-14 shrink-0 text-right font-mono text-slate-700">
                      {t.alerts.toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
              {!isLoading && (
                <p className="mt-3 text-[11px] text-slate-400">
                  Bars are techniques observed out of the techniques ATT&amp;CK lists for that tactic; the
                  last column is alerts.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {(data?.unknownTechniques.length ?? 0) > 0 && (
        <Card>
          <CardContent className="pt-4 text-xs text-slate-600">
            <span className="font-medium text-slate-800">Technique ids not in the shipped ATT&amp;CK release: </span>
            {data!.unknownTechniques.map((u) => `${u.id} (${u.alerts})`).join(', ')}. These alerts are
            counted in the period total but have no cell. Either a rule names a wrong id, or ATT&amp;CK has
            moved on and killchain/attack/data/attack_catalogue.json needs updating.
          </CardContent>
        </Card>
      )}

      {data && (
        <p className="text-[11px] text-slate-400">
          ATT&amp;CK Enterprise, spec {data.catalogue.attackSpecVersion ?? 'unknown'}
          {data.catalogue.bundleModified && ` (${data.catalogue.bundleModified.slice(0, 10)})`}.{' '}
          {data.catalogue.attribution}
        </p>
      )}
    </div>
  )
}
