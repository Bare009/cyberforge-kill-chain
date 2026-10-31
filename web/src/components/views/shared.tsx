import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { SeverityText, TacticChip } from '@/components/incident/badges'
import { Skeleton } from '@/components/ui/skeleton'
import { cn, exactTimeParts, timeTooltip } from '@/lib/utils'
import type { Alert } from '@/types/incident'

export function PageTitle({ icon, title, subtitle, children }: { icon: ReactNode; title: string; subtitle: string; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 text-blue-600">{icon}</div>
      <div className="min-w-0 flex-1">
        <h1 className="text-xl font-semibold text-slate-900">{title}</h1>
        <p className="text-sm text-slate-500">{subtitle}</p>
      </div>
      {children}
    </div>
  )
}

export function KpiTile({ label, value, hint, icon, loading, tone }: {
  label: string; value: ReactNode; hint?: ReactNode; icon?: ReactNode; loading?: boolean; tone?: string
}) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-4" aria-label={label}>
      {icon && <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-50">{icon}</div>}
      <div className="min-w-0">
        {loading ? <Skeleton className="mb-1 h-7 w-16" /> : <div className={cn('text-2xl font-bold text-slate-900', tone)}>{value}</div>}
        <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
        {hint && <div className="mt-0.5 text-xs text-slate-400">{hint}</div>}
      </div>
    </div>
  )
}

/** Horizontal bars with a label, a value and an optional link per row. */
export function BarList({ rows, colour = 'bg-blue-500', empty = 'Nothing to show.' }: {
  rows: { key: string; label: ReactNode; value: number; to?: string; colour?: string; title?: string }[]
  colour?: string
  empty?: string
}) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  if (rows.length === 0) return <p className="text-sm text-slate-400">{empty}</p>
  return (
    <ul className="space-y-1.5">
      {rows.map((r) => {
        const label = <span className="w-40 shrink-0 truncate text-slate-700" title={r.title}>{r.label}</span>
        return (
          <li key={r.key} className="flex items-center gap-2 text-xs">
            {r.to ? <Link to={r.to} className="w-40 shrink-0 truncate text-blue-700 hover:underline" title={r.title}>{r.label}</Link> : label}
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
              <span className={cn('block h-full rounded-full', r.colour ?? colour)} style={{ width: `${(100 * r.value) / max}%` }} />
            </span>
            <span className="w-10 shrink-0 text-right font-mono text-slate-600">{r.value.toLocaleString()}</span>
          </li>
        )
      })}
    </ul>
  )
}

export function TimeCell({ iso }: { iso: string | null | undefined }) {
  const t = exactTimeParts(iso)
  if (!t) return <span className="text-slate-400">—</span>
  return (
    <span className="whitespace-nowrap" title={timeTooltip(iso)}>
      <span className="text-slate-700">{t.date}</span> <span className="font-mono text-slate-500">{t.time}</span>
    </span>
  )
}

function Entities({ a }: { a: Alert }) {
  const parts = [
    a.src_ip && { k: 'src', v: a.src_ip },
    a.dst_ip && { k: 'dst', v: a.dst_ip },
    a.user && { k: 'user', v: a.user },
    a.host && { k: 'host', v: a.host },
    a.domain && { k: 'domain', v: a.domain },
  ].filter(Boolean) as { k: string; v: string }[]
  if (parts.length === 0) return <span className="text-slate-400">—</span>
  return (
    <span className="flex flex-wrap gap-x-2 gap-y-0.5">
      {parts.map((p) => (
        <span key={p.k} className="whitespace-nowrap">
          <span className="text-slate-400">{p.k} </span>
          <span className="font-mono text-slate-700">{p.v}</span>
        </span>
      ))}
    </span>
  )
}

/** Alerts as a table: time, rule, technique, entities, events, incident. `extra` adds a last column. */
export function AlertTable({ alerts, extra }: { alerts: Alert[]; extra?: { header: string; cell: (a: Alert) => ReactNode } }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="border-b border-slate-100 text-[11px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="px-3 py-2 font-medium">Started</th>
            <th className="px-3 py-2 font-medium">Alert</th>
            <th className="px-3 py-2 font-medium">Technique</th>
            <th className="px-3 py-2 font-medium">Entities</th>
            <th className="px-3 py-2 text-right font-medium">Events</th>
            <th className="px-3 py-2 font-medium">Incident</th>
            {extra && <th className="px-3 py-2 font-medium">{extra.header}</th>}
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.alert_id} className="border-b border-slate-50 align-top hover:bg-slate-50">
              <td className="px-3 py-2"><TimeCell iso={a.ts_start} /></td>
              <td className="max-w-[22rem] px-3 py-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-medium text-slate-900">{a.title}</span>
                  <SeverityText severity={a.severity} />
                  {a.layer === 'anomaly' && (
                    <span className="rounded border border-violet-200 bg-violet-50 px-1 text-[10px] text-violet-700">anomaly</span>
                  )}
                </div>
                <div className="mt-0.5 text-slate-500">{a.summary}</div>
                <Link to={`/rules?rule=${encodeURIComponent(a.rule_id)}`} className="font-mono text-[11px] text-slate-400 hover:text-blue-700">
                  {a.rule_id}
                </Link>
              </td>
              <td className="px-3 py-2">
                <div className="font-mono text-slate-700">{a.technique}</div>
                <div className="text-slate-500">{a.technique_name ?? ''}</div>
                <TacticChip tactic={a.tactic} className="mt-1" />
              </td>
              <td className="px-3 py-2"><Entities a={a} /></td>
              <td className="px-3 py-2 text-right font-mono text-slate-700">{a.event_count.toLocaleString()}</td>
              <td className="px-3 py-2">
                {a.incident_number != null ? (
                  <Link to={`/incidents/${a.incident_number}`} className="font-mono text-blue-700 hover:underline">
                    #{a.incident_number}
                  </Link>
                ) : (
                  <span className="text-slate-400">none</span>
                )}
              </td>
              {extra && <td className="px-3 py-2">{extra.cell(a)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
