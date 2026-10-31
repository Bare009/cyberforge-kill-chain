import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from 'recharts'
import { ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { alertsLink, fetchTechniqueDetail } from '@/lib/mitre-api'
import { cn } from '@/lib/utils'
import type { MitreQuery, SeverityLabel } from '@/types/mitre'
import { SEVERITY_COLOURS, SEVERITY_ORDER, SEVERITY_TEXT, fmtDateTime } from './heat'

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 px-2.5 py-1.5">
      <div className={cn('font-mono text-lg font-semibold text-slate-900', tone)}>{value}</div>
      <div className="text-[11px] text-slate-500">{label}</div>
    </div>
  )
}

function Bars({ rows, label }: { rows: { name: string; alerts: number }[]; label: string }) {
  const max = Math.max(1, ...rows.map((r) => r.alerts))
  if (rows.length === 0) return null
  return (
    <div className="space-y-1">
      <h4 className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</h4>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.name} className="flex items-center gap-2 text-xs">
            <span className="w-32 shrink-0 truncate text-slate-700" title={r.name}>
              {r.name}
            </span>
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
              <span
                className="block h-full rounded-full bg-blue-500"
                style={{ width: `${(100 * r.alerts) / max}%` }}
              />
            </span>
            <span className="w-10 shrink-0 text-right font-mono text-slate-600">{r.alerts}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

interface Props {
  techniqueId: string
  query: MitreQuery
  onSelect: (techniqueId: string) => void
  onClose: () => void
}

export function TechniqueDetailPanel({ techniqueId, query, onSelect, onClose }: Props) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['mitre', 'technique', techniqueId, query],
    queryFn: () => fetchTechniqueDetail(techniqueId, query),
    staleTime: 30_000,
  })

  if (isLoading) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-sm text-slate-500">Loading {techniqueId}…</CardContent>
      </Card>
    )
  }
  if (isError || !data) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-sm text-red-600">
          {(error as Error)?.message ?? `Could not load ${techniqueId}.`}
        </CardContent>
      </Card>
    )
  }

  const t = data.technique
  const s = data.summary
  const trendHasData = data.trend.some((p) => p.alerts > 0)

  return (
    <Card>
      <CardContent className="space-y-4 pt-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded border border-red-100 bg-red-50 px-1.5 py-0.5 font-mono text-xs text-red-600">
                {t.id}
              </span>
              <h3 className="text-base font-semibold text-slate-900">{t.name}</h3>
              <a
                href={t.url}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
              >
                attack.mitre.org <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </a>
            </div>
            <p className="mt-0.5 text-xs text-slate-500">
              {t.parent && (
                <>
                  Sub-technique of{' '}
                  <button type="button" className="text-blue-600 hover:underline" onClick={() => onSelect(t.parent!)}>
                    {t.parent} {t.parentName}
                  </button>
                  {' · '}
                </>
              )}
              {t.tactics.map((x) => x.name).join(', ')}
              {t.subtechniquesTotal > 0 && ` · ${t.subtechniquesTotal} sub-technique(s) in ATT&CK`}
            </p>
          </div>
          <div className="flex shrink-0 gap-1.5">
            <Button asChild size="sm" variant="outline">
              <Link to={alertsLink({ technique: t.id, preset: query.preset, start: query.start, end: query.end })}>View alerts</Link>
            </Button>
            <Button size="sm" variant="ghost" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>

        {s.alerts === 0 ? (
          <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">
            No alerts for this technique in the selected period. That is not evidence it cannot
            happen here, only that nothing was recorded.
          </p>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="Alerts" value={s.alerts.toLocaleString()} />
              <Stat label="Still open" value={s.openAlerts} tone={s.openAlerts ? 'text-amber-700' : undefined} />
              <Stat label="In incidents" value={s.correlatedAlerts} />
              <Stat
                label="Worst severity"
                value={s.maxSeverity ?? '—'}
                tone={s.maxSeverity ? SEVERITY_TEXT[s.maxSeverity as SeverityLabel] : undefined}
              />
            </div>
            <p className="text-xs text-slate-500">
              First seen {fmtDateTime(s.firstSeen)} · last seen {fmtDateTime(s.lastSeen)}
              {t.subtechniquesTotal > 0 &&
                ` · ${s.alertsOnTechniqueItself} alert(s) recorded against the technique itself rather than a sub-technique`}
            </p>

            {trendHasData && (
              <div className="h-40">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data.trend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                    <XAxis dataKey="date" tick={{ fontSize: 10 }} tickFormatter={(v: string) => v.slice(5)} />
                    <YAxis tick={{ fontSize: 10 }} allowDecimals={false} />
                    <RTooltip />
                    {SEVERITY_ORDER.map((k) => (
                      <Area
                        key={k}
                        type="monotone"
                        dataKey={k}
                        stackId="1"
                        name={k}
                        stroke={SEVERITY_COLOURS[k]}
                        fill={SEVERITY_COLOURS[k]}
                        fillOpacity={0.7}
                      />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}

            {data.subtechniques.length > 0 && (
              <>
                <Separator />
                <div className="space-y-1">
                  <h4 className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    Sub-techniques observed
                  </h4>
                  <ul className="divide-y divide-slate-100">
                    {data.subtechniques.map((sub) => (
                      <li key={sub.id} className="flex flex-wrap items-center gap-2 py-1.5 text-xs">
                        <button
                          type="button"
                          className="font-mono text-blue-600 hover:underline"
                          onClick={() => onSelect(sub.id)}
                        >
                          {sub.id}
                        </button>
                        <span className="min-w-0 flex-1 truncate text-slate-700">
                          {sub.name ?? (sub.inCatalogue ? '' : 'Not in the shipped ATT&CK release')}
                        </span>
                        {sub.maxSeverity && (
                          <span className={cn('font-medium', SEVERITY_TEXT[sub.maxSeverity])}>
                            {sub.maxSeverity}
                          </span>
                        )}
                        <span className="w-12 text-right font-mono text-slate-600">{sub.alerts}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            )}

            <Separator />
            <div className="grid gap-4 sm:grid-cols-3">
              <Bars label="Log sources" rows={data.bySource.map((r) => ({ name: r.source, alerts: r.alerts }))} />
              <Bars label="Assets" rows={data.byAsset.map((r) => ({ name: r.asset, alerts: r.alerts }))} />
              <Bars label="Status" rows={data.byStatus.map((r) => ({ name: r.status, alerts: r.alerts }))} />
            </div>

            {data.recentAlerts.length > 0 && (
              <>
                <Separator />
                <div className="space-y-1">
                  <h4 className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
                    Most recent alerts
                  </h4>
                  <ul className="divide-y divide-slate-100">
                    {data.recentAlerts.map((a, i) => (
                      <li key={a.id ?? i} className="flex flex-wrap items-center gap-2 py-1.5 text-xs">
                        <span className={cn('w-16 shrink-0 font-medium', SEVERITY_TEXT[a.severity])}>
                          {a.severity}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-slate-700" title={a.title ?? ''}>
                          {a.title ?? a.id ?? 'Alert'}
                        </span>
                        {a.subtechniqueId && (
                          <span className="shrink-0 font-mono text-[10px] text-slate-500">{a.subtechniqueId}</span>
                        )}
                        <span className="shrink-0 text-slate-400">{fmtDateTime(a.time)}</span>
                        {a.id && (
                          <Button asChild size="sm" variant="ghost" className="h-6 px-2 text-[11px]">
                            <Link to={`/alerts/${encodeURIComponent(a.id)}`}>Open</Link>
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
