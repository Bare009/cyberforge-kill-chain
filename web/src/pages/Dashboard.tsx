import { useRef } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, Tooltip as RTooltip, XAxis, YAxis } from 'recharts'
import { AlertCircle, Bell, Clock, Cpu, Database, FileText, Globe, LayoutDashboard, ShieldAlert, Sparkles } from 'lucide-react'
import { AnalyseLog } from '@/components/analyse/AnalyseLog'
import { RunPicker } from '@/components/analyse/RunPicker'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { RiskBandBadge, SeverityText, TacticChips, TiVerdictBadge, TriageBadge } from '@/components/incident/badges'
import { BarList, KpiTile, PageTitle } from '@/components/views/shared'
import { useDashboard } from '@/hooks/useViews'
import { useElementWidth } from '@/hooks/useElementWidth'
import { apiErrorMessage } from '@/lib/api'
import { formatBytes, formatSecs } from '@/lib/format'
import { RISK_BAND_BAR, severityLabel, tacticColor } from '@/lib/killchain'
import { providerLabel } from '@/lib/threatIntel'
import { cn, formatFullTime } from '@/lib/utils'
import type { DashboardSummary } from '@/types/views'

function fmt(n: number | null | undefined): string {
  return n == null ? '—' : n.toLocaleString()
}

const IST_DAY = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short' })
const formatDay = (iso: string) => IST_DAY.format(new Date(iso))

const IST_HOUR = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })

function Panel({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-800">{title}</h2>
          {action}
        </div>
        {children}
      </CardContent>
    </Card>
  )
}

function AlertsPerHour({ data }: { data: DashboardSummary }) {
  const ref = useRef<HTMLDivElement>(null)
  const width = useElementWidth(ref, 700)
  const rows = data.alerts_per_hour.map((h) => ({ ...h, label: IST_HOUR.format(new Date(h.hour)) }))
  if (rows.length === 0) return <p className="text-sm text-slate-400">No alerts in this run.</p>
  return (
    <div ref={ref} aria-label="Alerts per hour chart">
      <BarChart width={width} height={200} data={rows} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
        <XAxis dataKey="label" tick={{ fontSize: 10 }} minTickGap={40} />
        <YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
        <RTooltip contentStyle={{ fontSize: 12 }} labelFormatter={(l) => `${l} IST`} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <Bar dataKey="rule" stackId="a" name="Rule alerts" fill="#2563eb" isAnimationActive={false} />
        <Bar dataKey="anomaly" stackId="a" name="Anomaly alerts" fill="#8b5cf6" isAnimationActive={false} />
      </BarChart>
      <p className="text-xs text-slate-400">By start hour, IST. {rows.length} hours from the first alert to the last.</p>
    </div>
  )
}

function Coverage({ data }: { data: DashboardSummary }) {
  const max = Math.max(1, ...data.coverage.map((c) => c.incidents))
  return (
    <div className="space-y-2">
      <ul className="space-y-1" aria-label="Kill chain coverage">
        {data.coverage.map((c) => (
          <li key={c.tactic}>
            <Link
              to={`/incidents?tactic=${c.tactic}`}
              title={`${c.incidents} incidents, ${c.alerts} alerts`}
              aria-label={`${c.name}: ${c.incidents} incidents`}
              className={cn('flex items-center gap-2 rounded text-xs hover:bg-slate-50', !c.incidents && 'opacity-50')}
            >
              <span className="w-40 shrink-0 truncate text-slate-700">
                <span className="font-mono text-slate-400">{c.stage_no}.</span> {c.name}
              </span>
              <span className="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
                <span className="block h-full rounded-full" style={{ width: `${(100 * c.incidents) / max}%`, background: tacticColor(c.tactic) }} />
              </span>
              <span className="w-6 shrink-0 text-right font-mono text-slate-600">{c.incidents}</span>
            </Link>
          </li>
        ))}
      </ul>
      <p className="text-xs text-slate-400">
        {data.coverage.filter((c) => c.incidents).length} of 14 ATT&CK tactics reached by at least one incident. Click a bar to list them.
      </p>
    </div>
  )
}

function Severity({ data }: { data: DashboardSummary }) {
  if (data.risk_scored) {
    return (
      <BarList
        rows={data.incidents_by_band.map((b) => ({
          key: b.band, label: <RiskBandBadge band={b.band} />, value: b.incidents, colour: RISK_BAND_BAR[b.band],
        }))}
      />
    )
  }
  return (
    <div className="space-y-2">
      <p className="flex items-start gap-1.5 rounded-lg bg-amber-50 px-2.5 py-1.5 text-xs text-amber-800">
        <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        Risk scores are not in this run yet, so incidents are grouped by severity (their worst alert).
      </p>
      <BarList
        rows={data.incidents_by_severity.filter((s) => s.incidents).map((s) => ({
          key: String(s.severity), label: <SeverityText severity={s.severity} />, value: s.incidents,
          colour: s.severity >= 5 ? 'bg-red-500' : s.severity >= 4 ? 'bg-orange-500' : 'bg-amber-500',
          to: `/incidents?severity=${s.severity}`, title: severityLabel(s.severity),
        }))}
      />
    </div>
  )
}

function DataQualityCard({ data }: { data: DashboardSummary }) {
  const dq = data.data_quality
  if (!dq) return <p className="text-sm text-slate-400">No parser statistics in this run.</p>
  const good = dq.events ? (100 * dq.events_good_time) / dq.events : 0
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
      <div><dt className="text-slate-500">Log lines</dt><dd className="font-mono text-slate-800">{fmt(dq.lines)}</dd></div>
      <div><dt className="text-slate-500">Log size</dt><dd className="font-mono text-slate-800">{formatBytes(dq.bytes)}</dd></div>
      <div><dt className="text-slate-500">Events with a good clock</dt><dd className="font-mono text-slate-800">{fmt(dq.events_good_time)} ({good.toFixed(0)}%)</dd></div>
      <div>
        <dt className="text-slate-500">Frozen-clock events</dt>
        <dd className="font-mono text-amber-700" title="Kept with their line numbers, left out of time-window rules">{fmt(dq.events_frozen_clock)}</dd>
      </div>
      <div><dt className="text-slate-500">Exact duplicate rows</dt><dd className="font-mono text-slate-800">{fmt(dq.exact_duplicate_rows)}</dd></div>
      <div><dt className="text-slate-500">Rejected lines</dt><dd className="font-mono text-slate-800">{fmt(dq.rejected_lines)}</dd></div>
      <div className="col-span-2">
        <dt className="text-slate-500">Junk data (not parsed)</dt>
        <dd className="font-mono text-slate-800">
          {formatBytes(dq.junk_bytes)} in {dq.junk_ranges.length} range{dq.junk_ranges.length === 1 ? '' : 's'}
          {dq.junk_ranges[0] && (
            <span className="text-slate-500"> (from byte {dq.junk_ranges[0].start.toLocaleString()} of {dq.junk_ranges[0].source})</span>
          )}
        </dd>
      </div>
      <div className="col-span-2">
        <dt className="text-slate-500">Good clock range</dt>
        <dd className="text-slate-800">{formatFullTime(dq.first_good_ts)} to {formatFullTime(dq.last_good_ts)}</dd>
      </div>
    </dl>
  )
}

function StatusCard({ data }: { data: DashboardSummary }) {
  const ti = data.threat_intel
  const llm = data.llm
  return (
    <div className="space-y-3 text-xs">
      <div className="space-y-1">
        <p className="flex items-center gap-1.5 font-medium text-slate-700"><Globe className="h-3.5 w-3.5" /> Threat intel</p>
        {ti ? (
          <>
            <p className="text-slate-600">
              {Object.entries(ti.providers).map(([k, v]) => `${providerLabel(k)} ${v === 'ok' ? 'on' : v}`).join(' · ')}
            </p>
            <p className="text-slate-500">
              {ti.indicators} indicators
              {ti.verdicts ? `: ${Object.entries(ti.verdicts).map(([k, v]) => `${v} ${k}`).join(', ')}` : ''}
            </p>
          </>
        ) : (
          <p className="text-slate-400">Not run.</p>
        )}
        <Link to="/threat-intel" className="text-blue-700 hover:underline">Open Threat Intel</Link>
      </div>
      <div className="space-y-1">
        <p className="flex items-center gap-1.5 font-medium text-slate-700"><Sparkles className="h-3.5 w-3.5" /> Reports</p>
        <p className="text-slate-600">
          {llm && llm.reports > 0
            ? `${llm.reports} written by the AI narrator${llm.model ? ` (${llm.model})` : ''}; the rest use the template.`
            : 'Every incident uses the template report (no AI narrator output in this run).'}
        </p>
      </div>
    </div>
  )
}

function Stages({ data }: { data: DashboardSummary }) {
  const rows = Object.entries(data.stages).filter(([, s]) => s.wall_secs != null)
  if (rows.length === 0) return <p className="text-sm text-slate-400">No stage timings in this run.</p>
  return (
    <BarList
      colour="bg-slate-400"
      rows={rows.map(([name, s]) => ({
        key: name,
        label: (
          <span>
            {name} <span className="text-slate-400">{formatSecs(s.wall_secs)}{s.peak_rss_mb ? ` · ${s.peak_rss_mb.toLocaleString()} MB` : ''}</span>
          </span>
        ),
        value: Math.round((s.wall_secs ?? 0) * 10) / 10,
      }))}
    />
  )
}

export function Dashboard() {
  const { data, isLoading, isError, error, refetch } = useDashboard()

  if (isError) {
    return (
      <div className="space-y-5">
        <PageTitle icon={<LayoutDashboard className="h-5 w-5" />} title="Dashboard" subtitle="What this run found, at a glance." />
        <div role="alert" className="flex items-center gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-4 text-sm text-red-700">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="flex-1">Could not load the dashboard: {apiErrorMessage(error)}</span>
          <Button variant="outline" size="sm" onClick={() => void refetch()}>Retry</Button>
        </div>
      </div>
    )
  }

  const k = data?.kpis
  return (
    <div className="space-y-5">
      <PageTitle
        icon={<LayoutDashboard className="h-5 w-5" />}
        title="Dashboard"
        subtitle={data ? `What run ${data.run} found, at a glance. Times in IST.` : 'What this run found, at a glance.'}
      >
        {data?.sample && (
          <span className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-xs text-amber-800">Sample run</span>
        )}
        <RunPicker />
      </PageTitle>

      <AnalyseLog />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiTile loading={isLoading} label="Events parsed" value={fmt(k?.events_parsed)} icon={<Database className="h-4 w-4 text-slate-500" />}
          hint={k?.log_lines ? `${k.log_lines.toLocaleString()} log lines` : undefined} />
        <KpiTile loading={isLoading} label="Alerts" value={fmt(k?.alerts)} icon={<Bell className="h-4 w-4 text-blue-500" />}
          hint={k ? `${k.unexplained} unexplained` : undefined} />
        <KpiTile loading={isLoading} label="Incidents" value={fmt(k?.incidents)} icon={<ShieldAlert className="h-4 w-4 text-red-500" />} />
        <KpiTile loading={isLoading} label={data?.risk_scored ? 'Critical risk' : 'Critical severity'} tone="text-red-600"
          value={fmt(data?.risk_scored ? k?.critical_incidents : k?.critical_severity_incidents)}
          icon={<AlertCircle className="h-4 w-4 text-red-500" />} />
        <KpiTile loading={isLoading} label="Log time span" icon={<Clock className="h-4 w-4 text-slate-500" />}
          value={k?.log_start && k.log_end ? `${Math.round((Date.parse(k.log_end) - Date.parse(k.log_start)) / 86_400_000)} days` : '—'}
          hint={k?.log_start && k.log_end ? `${formatDay(k.log_start)} to ${formatDay(k.log_end)}` : undefined} />
        <KpiTile loading={isLoading} label="Run time" value={formatSecs(k?.processing_secs)} icon={<FileText className="h-4 w-4 text-slate-500" />}
          hint={k?.processing_timing === 'pipeline' ? 'parse to bundle, end to end' : 'all stages'} />
        <KpiTile loading={isLoading} label="Peak memory" value={k?.peak_rss_mb ? `${(k.peak_rss_mb / 1024).toFixed(1)} GB` : '—'}
          icon={<Cpu className="h-4 w-4 text-slate-500" />} hint="largest stage" />
      </div>

      {isLoading || !data ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-56 w-full rounded-xl" />)}
        </div>
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="Kill chain coverage"><Coverage data={data} /></Panel>
            <Panel title={data.risk_scored ? 'Incidents by risk band' : 'Incidents by severity'}><Severity data={data} /></Panel>
            <Panel title="Worst incidents" action={<Link to="/incidents" className="text-xs text-blue-700 hover:underline">All incidents</Link>}>
              <ul className="space-y-2">
                {data.worst_incidents.map((i) => (
                  <li key={i.incident_number}>
                    <Link to={`/incidents/${i.incident_number}`} className="block rounded-lg px-2 py-1 hover:bg-slate-50">
                      <span className="flex flex-wrap items-center gap-1.5 text-xs">
                        <span className="font-mono font-bold text-slate-400">#{i.incident_number}</span>
                        <span className="font-medium text-slate-900">{i.title}</span>
                        {data.risk_scored && <RiskBandBadge band={i.risk_band} />}
                        <TriageBadge verdict={i.triage_verdict} />
                        <TiVerdictBadge verdict={i.ti_verdict} />
                      </span>
                      <span className="mt-1 block"><TacticChips tactics={i.tactics} max={4} /></span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>

          <Panel title="Alerts per hour"><AlertsPerHour data={data} /></Panel>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Top attackers (outside sources)">
              <BarList
                empty="No outside sources in the alerts."
                colour="bg-red-400"
                rows={data.top_attackers.map((e) => ({
                  key: e.value, label: <span className="font-mono">{e.value}</span>, value: e.alerts,
                  to: `/incidents?entity=${encodeURIComponent(e.value)}`,
                  title: `${e.alerts} alerts in ${e.incidents.length} incident(s), worst severity ${e.max_severity}`,
                }))}
              />
              <p className="text-xs text-slate-400">Alerts per source; click to see its incidents.</p>
            </Panel>
            <Panel title="Top targets (inside)">
              <BarList
                empty="No internal targets in the alerts."
                colour="bg-blue-400"
                rows={data.top_targets.map((e) => ({
                  key: e.value, label: <span className="font-mono">{e.value}</span>, value: e.alerts,
                  to: `/incidents?entity=${encodeURIComponent(e.value)}`,
                  title: `${e.alerts} alerts in ${e.incidents.length} incident(s)`,
                }))}
              />
              <p className="text-xs text-slate-400">Alerts per destination; click to see its incidents.</p>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="Data quality"><DataQualityCard data={data} /></Panel>
            <Panel title="Pipeline stages"><Stages data={data} /></Panel>
            <Panel title="Threat intel and reports"><StatusCard data={data} /></Panel>
          </div>
        </>
      )}
    </div>
  )
}
