import { Link } from 'react-router-dom'
import { AlertCircle, CheckCircle2, Gauge, XCircle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { PageTitle } from '@/components/views/shared'
import { useMetrics, useSystem } from '@/hooks/useSystem'
import { apiErrorMessage } from '@/lib/api'
import { formatMetric, formatSecs } from '@/lib/format'
import { cn, formatFullTime } from '@/lib/utils'
import type { Grade, MetricName, MetricTarget, MetricsResponse } from '@/types/system'

const ORDER: MetricName[] = ['detection_recall', 'label_accuracy', 'attack_path_rebuilt', 'false_alarm_share',
  'processing_secs', 'peak_rss_mb', 'open_time_p95_ms']

const GRADE: Record<Grade, { label: string; tone: string }> = {
  great: { label: 'Great', tone: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
  good: { label: 'Good', tone: 'bg-blue-50 text-blue-700 border-blue-200' },
  below: { label: 'Below target', tone: 'bg-red-50 text-red-700 border-red-200' },
  'n/a': { label: 'Not measured', tone: 'bg-slate-50 text-slate-500 border-slate-200' },
}

const pct = (v: number) => formatMetric(v, 'share')

function MetricCard({ name, t, value, grade }: { name: MetricName; t: MetricTarget; value: number | null; grade: Grade }) {
  const g = GRADE[grade] ?? GRADE['n/a']
  const dir = t.higher_is_better ? '≥' : '≤'
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4" aria-label={t.label} data-metric={name}>
      <div className="flex items-start justify-between gap-2">
        <span className="text-[11px] uppercase tracking-wider text-slate-500">{t.label}</span>
        <span className={cn('rounded border px-1.5 py-0.5 text-[10px] font-semibold', g.tone)}>{g.label}</span>
      </div>
      <div className="mt-1 text-2xl font-bold text-slate-900">{formatMetric(value, t.unit)}</div>
      <div className="mt-1 text-xs text-slate-500">
        Good {dir} {formatMetric(t.good, t.unit)} · Great {dir} {formatMetric(t.great, t.unit)}
      </div>
      <p className="mt-1 text-xs text-slate-400">{t.meaning}</p>
    </div>
  )
}

function Table({ head, rows, label }: { head: string[]; rows: React.ReactNode[][]; label: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs" aria-label={label}>
        <thead className="border-b border-slate-100 text-[11px] uppercase tracking-wider text-slate-500">
          <tr>{head.map((h, i) => <th key={h} className={cn('px-3 py-2 font-medium', i > 1 && 'text-right')}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-slate-50">
              {r.map((c, j) => <td key={j} className={cn('px-3 py-1.5', j > 1 && 'text-right font-mono')}>{c}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Ok({ ok }: { ok: boolean }) {
  return ok ? <CheckCircle2 className="inline h-4 w-4 text-emerald-600" aria-label="yes" />
    : <XCircle className="inline h-4 w-4 text-red-500" aria-label="no" />
}

function Body({ m }: { m: MetricsResponse }) {
  const d = m.detail ?? {}
  const { data: sys, isLoading: sysLoading } = useSystem()
  const stages = Object.entries(sys?.stages ?? {}).filter(([, s]) => s.wall_secs != null)
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border border-slate-200 bg-white px-4 py-2 text-xs text-slate-600">
        <span>Truth: <span className="font-medium text-slate-800">{m.truth}</span></span>
        {m.generated_at && <span>Scored {formatFullTime(m.generated_at)}</span>}
        <span>{(d.covered_lines ?? 0).toLocaleString()} of {(d.truth_lines ?? 0).toLocaleString()} planted lines covered</span>
        <span>{d.incidents_found} of {d.truth_incidents} planted incidents found</span>
        {d.multi_step_rebuilt && <span>multi-step chains in order: {d.multi_step_rebuilt}</span>}
      </div>
      {(m.truth_notes ?? []).length > 0 && (
        <ul aria-label="Truth notes" className="space-y-0.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600">
          {m.truth_notes!.map((n) => (
            <li key={n} className="flex items-start gap-1.5">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
              {n}
            </li>
          ))}
        </ul>
      )}
      {m.truth?.startsWith('silver') && (
        <p className="flex items-start gap-1.5 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          Scored against our silver truth: the planted attacks as we identified them in this log (eval/silver_truth.yaml),
          not an organisers' answer key. With their manifest, run eval score --manifest.
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {ORDER.filter((k) => m.targets?.[k]).map((k) => (
          <MetricCard key={k} name={k} t={m.targets![k]} value={m.metrics?.[k] ?? null} grade={m.grades?.[k] ?? 'n/a'} />
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardContent className="space-y-2 p-4">
            <h2 className="text-sm font-semibold text-slate-800">Planted incidents</h2>
            <Table label="Per incident" head={['#', 'Planted incident', 'Class', 'Lines', 'Found', 'Recall', 'Path', 'Our incident']}
              rows={(m.per_incident ?? []).map((r) => {
                const p = (m.paths ?? []).find((x) => x.incident_id === r.incident_id)
                return [
                  r.incident_id, r.incident_name, r.class, r.lines.toLocaleString(), r.found.toLocaleString(), pct(r.recall),
                  p ? <span title={p.reason}><Ok ok={p.rebuilt} />{p.steps > 1 ? ` ${p.steps} steps` : ''}</span> : '—',
                  p?.our_incident != null ? <Link to={`/incidents/${p.our_incident}`} className="text-blue-700 hover:underline">#{p.our_incident}</Link> : '—',
                ]
              })} />
          </CardContent>
        </Card>
        <div className="space-y-4">
          <Card>
            <CardContent className="space-y-2 p-4">
              <h2 className="text-sm font-semibold text-slate-800">Labels and false alarms</h2>
              <Table label="Labels" head={['Measure', 'Detail', 'Value']} rows={[
                ['Label exact', 'same technique as planted', pct(Number(d.label_exact ?? 0))],
                ['Label parent', 'same parent technique', pct(Number(d.label_parent ?? 0))],
                ['Label accepted', 'exact, parent or an accepted alternate', pct(Number(d.label_any ?? 0))],
                ['Our incidents', 'in this run', String(d.our_incidents ?? '—')],
                ['Without planted lines', 'possible false alarms', String(d.incidents_without_truth ?? '—')],
              ]} />
              {(m.per_class ?? []).length > 0 && (
                <Table label="Per class" head={['Class', '', 'Lines', 'Found', 'Recall']}
                  rows={m.per_class!.map((c) => [c.class, '', c.lines.toLocaleString(), c.found.toLocaleString(), pct(c.recall)])} />
              )}
              {(d.unreviewed ?? []).length > 0 && (
                <p className="text-xs text-amber-800">
                  Unreviewed: {d.unreviewed!.map((u) => `#${u.incident_number}`).join(', ')}. Mark each real or false in eval/reviewed.yml.
                </p>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="space-y-2 p-4">
              <h2 className="text-sm font-semibold text-slate-800">Time and memory per stage</h2>
              {sysLoading ? <Skeleton className="h-24 w-full" /> : stages.length ? (
                <Table label="Stages" head={['Stage', '', 'Time', 'Peak memory']}
                  rows={stages.map(([n, s]) => [n, '', formatSecs(s.wall_secs), s.peak_rss_mb ? `${s.peak_rss_mb.toLocaleString()} MB` : '—'])} />
              ) : <p className="text-sm text-slate-400">No stage timings.</p>}
            </CardContent>
          </Card>
        </div>
      </div>

      <Card>
        <CardContent className="space-y-2 p-4">
          <h2 className="text-sm font-semibold text-slate-800">Per rule</h2>
          <Table label="Per rule" head={['Rule', 'Layer', 'Alerts', 'Planted lines found', 'Background alerts']}
            rows={(m.per_rule ?? []).map((r) => [
              <Link to={`/rules?rule=${encodeURIComponent(r.rule_id)}`} className="font-mono text-blue-700 hover:underline">{r.rule_id}</Link>,
              r.layer, r.alerts, r.truth_lines.toLocaleString(),
              <span className={r.background_alerts ? 'text-amber-700' : ''}>{r.background_alerts}</span>,
            ])} />
        </CardContent>
      </Card>
    </>
  )
}

export function Evaluation() {
  const { data, isLoading, isError, error } = useMetrics()
  return (
    <div className="space-y-5">
      <PageTitle icon={<Gauge className="h-5 w-5" />} title="Evaluation"
        subtitle="The seven PRD metrics for this run against their Good and Great targets." />
      {isError ? (
        <div role="alert" className="flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          <AlertCircle className="h-4 w-4" /> Could not load the evaluation: {apiErrorMessage(error)}
        </div>
      ) : isLoading || !data ? (
        <div className="grid gap-3 sm:grid-cols-4">{[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-32" />)}</div>
      ) : !data.available ? (
        <Card><CardContent className="space-y-1 p-6 text-sm text-slate-600">
          <p>This run has not been scored yet.</p>
          <p className="text-xs text-slate-500">{data.hint}</p>
        </CardContent></Card>
      ) : (
        <Body m={data} />
      )}
    </div>
  )
}
