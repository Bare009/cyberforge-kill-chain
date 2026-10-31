import { Link, useSearchParams } from 'react-router-dom'
import { AlertCircle, FileCode2, Search, X } from 'lucide-react'
import { RuleWriter } from '@/components/agents/RuleWriter'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { SeverityText, TacticChip } from '@/components/incident/badges'
import { AlertTable, PageTitle, TimeCell } from '@/components/views/shared'
import { useRule, useRules } from '@/hooks/useViews'
import { apiErrorMessage } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { RuleRow } from '@/types/views'

/** Light YAML colouring: comments, keys and quoted strings. */
function YamlView({ text }: { text: string }) {
  return (
    <pre aria-label="Rule YAML" className="max-h-[28rem] overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-[11px] leading-relaxed text-slate-100">
      {text.split('\n').map((line, i) => {
        const hash = line.search(/(^|\s)#/)
        const code = hash >= 0 ? line.slice(0, hash) : line
        const comment = hash >= 0 ? line.slice(hash) : ''
        const m = /^(\s*-?\s*)([\w.-]+)(:)(.*)$/.exec(code)
        return (
          <div key={i}>
            <span className="mr-3 inline-block w-6 select-none text-right text-slate-500">{i + 1}</span>
            {m ? (
              <>
                {m[1]}<span className="text-sky-300">{m[2]}</span>{m[3]}<span className="text-amber-200">{m[4]}</span>
              </>
            ) : (
              <span className="text-amber-200">{code}</span>
            )}
            {comment && <span className="text-slate-500">{comment}</span>}
          </div>
        )
      })}
    </pre>
  )
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className="text-sm text-slate-800">{children}</dd>
    </div>
  )
}

function RuleDetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, isError, error } = useRule(id)
  return (
    <Card aria-label={`Rule ${id}`}>
      <CardContent className="space-y-4 p-4">
        <div className="flex items-start justify-between gap-2">
          <div>
            <h2 className="font-mono text-sm font-semibold text-slate-900">{id}</h2>
            {data && <p className="text-sm text-slate-600">{data.title}</p>}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close rule"><X className="h-4 w-4" /></Button>
        </div>
        {isLoading ? (
          <Skeleton className="h-64 w-full" />
        ) : isError || !data ? (
          <p role="alert" className="text-sm text-red-700">{apiErrorMessage(error, 'Could not load this rule')}</p>
        ) : (
          <>
            <dl className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
              <Fact label="Technique">
                <span className="font-mono">{data.technique ?? 'unknown'}</span>
                {data.technique_name && <span className="block text-xs text-slate-500">{data.technique_name}</span>}
              </Fact>
              <Fact label="Tactic">{data.tactic ? <TacticChip tactic={data.tactic} /> : '—'}</Fact>
              <Fact label="Kind">{data.layer} · {data.kind} · {data.logsource}</Fact>
              <Fact label="Severity, confidence"><SeverityText severity={data.severity} /> · {data.confidence}</Fact>
              <Fact label="Alerts in this run">{data.alerts} ({data.alerts_in_incidents} in incidents)</Fact>
              <Fact label="Background alerts">{data.background_alerts ?? 'needs eval'}</Fact>
              <Fact label="Run time">{data.run_secs != null ? `${data.run_secs.toFixed(2)} s` : 'not run'}</Fact>
              <Fact label="Status">{data.status}{data.promote ? ' · promotes alone' : ''}</Fact>
            </dl>
            {data.tuning && <p className="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600"><span className="font-medium">Tuning: </span>{data.tuning}</p>}
            <div className="space-y-1">
              <p className="text-xs text-slate-500">File <span className="font-mono">{data.path}</span></p>
              <YamlView text={data.yaml} />
            </div>
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-800">Most recent alerts</h3>
                {data.alerts > 0 && (
                  <Link to={`/alerts?rule=${encodeURIComponent(data.id)}`} className="text-xs text-blue-700 hover:underline">
                    All {data.alerts} alerts
                  </Link>
                )}
              </div>
              {data.recent_alerts.length ? <AlertTable alerts={data.recent_alerts} /> : <p className="text-sm text-slate-400">No alerts from this rule in this run.</p>}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function RuleTableRow({ r, selected, onSelect, evaluated }: { r: RuleRow; selected: boolean; onSelect: () => void; evaluated: boolean }) {
  return (
    <tr className={cn('cursor-pointer border-b border-slate-50 align-top hover:bg-slate-50', selected && 'bg-blue-50/60')} onClick={onSelect}>
      <td className="px-3 py-2">
        <button className="whitespace-nowrap text-left font-mono text-xs font-medium text-blue-700 hover:underline" onClick={onSelect}>{r.id}</button>
        <div className="text-xs text-slate-600">{r.title}</div>
      </td>
      <td className="px-3 py-2 text-xs">
        <span className={cn('rounded border px-1 text-[10px]', r.layer === 'anomaly' ? 'border-violet-200 bg-violet-50 text-violet-700' : 'border-slate-200 bg-slate-50 text-slate-600')}>
          {r.layer}
        </span>
        <div className="mt-0.5 text-slate-500">{r.kind}</div>
      </td>
      <td className="px-3 py-2 text-xs">
        <div className="font-mono text-slate-700">{r.technique ?? 'unknown'}</div>
        {r.tactic && <TacticChip tactic={r.tactic} className="mt-1" />}
      </td>
      <td className="px-3 py-2 text-xs"><SeverityText severity={r.severity} /></td>
      <td className="px-3 py-2 text-right font-mono text-xs text-slate-800">{r.alerts}</td>
      <td className="px-3 py-2 text-xs">
        {r.incidents.length ? (
          <span className="flex flex-wrap gap-1">
            {r.incidents.slice(0, 6).map((n) => (
              <Link key={n} to={`/incidents/${n}`} onClick={(e) => e.stopPropagation()} className="font-mono text-blue-700 hover:underline">#{n}</Link>
            ))}
            {r.incidents.length > 6 && <span className="text-slate-400">+{r.incidents.length - 6}</span>}
          </span>
        ) : (
          <span className="text-slate-400">—</span>
        )}
      </td>
      {evaluated && <td className="px-3 py-2 text-right font-mono text-xs text-slate-700">{r.background_alerts ?? '—'}</td>}
      <td className="px-3 py-2 text-right font-mono text-xs text-slate-500">{r.run_secs != null ? `${r.run_secs.toFixed(2)} s` : '—'}</td>
      <td className="px-3 py-2 text-xs"><TimeCell iso={r.last_alert} /></td>
    </tr>
  )
}

export function Rules() {
  const [sp, setSp] = useSearchParams()
  const { data, isLoading, isError, error, refetch } = useRules({ layer: sp.get('layer') ?? undefined, q: sp.get('q') ?? undefined })
  const selected = sp.get('rule')

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(sp)
    if (value) next.set(key, value)
    else next.delete(key)
    setSp(next, { replace: true })
  }

  const rows = data?.rules ?? []
  const firing = rows.filter((r) => r.alerts > 0).length

  return (
    <div className="space-y-5">
      <PageTitle icon={<FileCode2 className="h-5 w-5" />} title="Rules"
        subtitle="Detection rules and anomaly detectors in rules/, with what each found in this run." />

      <RuleWriter />

      <div className="space-y-4">
        {selected && <RuleDetailPanel id={selected} onClose={() => set('rule', '')} />}
        <div className="rounded-xl border border-slate-200 bg-white">
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-3 py-2">
            <div className="relative min-w-[12rem] flex-1">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
              <Input aria-label="Search rules" placeholder="Search id, title or technique" value={sp.get('q') ?? ''}
                onChange={(e) => set('q', e.target.value)} className="h-8 pl-8 text-xs" />
            </div>
            <select aria-label="Layer" className="h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs text-slate-600"
              value={sp.get('layer') ?? ''} onChange={(e) => set('layer', e.target.value)}>
              <option value="">Rules and anomaly detectors</option>
              <option value="rule">Rules only</option>
              <option value="anomaly">Anomaly detectors only</option>
            </select>
            <span className="ml-auto font-mono text-xs text-slate-400">
              {data ? `${rows.length} rules, ${firing} fired` : ''}
            </span>
          </div>

          {data && data.errors.length > 0 && (
            <div role="alert" className="border-b border-red-100 bg-red-50 px-3 py-2 text-xs text-red-700">
              {data.errors.length} rule file problem(s): {data.errors[0]}
            </div>
          )}
          {data && data.unknown_rules.length > 0 && (
            <div className="border-b border-amber-100 bg-amber-50 px-3 py-2 text-xs text-amber-800">
              Alerts from rules no longer in rules/: {data.unknown_rules.map((u) => `${u.rule_id} (${u.alerts})`).join(', ')}
            </div>
          )}

          {isError ? (
            <div role="alert" className="flex items-center gap-3 px-4 py-6 text-sm text-red-700">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span className="flex-1">Could not load rules: {apiErrorMessage(error)}</span>
              <Button variant="outline" size="sm" onClick={() => void refetch()}>Retry</Button>
            </div>
          ) : isLoading ? (
            <div className="space-y-2 p-3">{[1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : rows.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-400">No rule matches.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="border-b border-slate-100 text-[11px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Kind</th>
                    <th className="px-3 py-2 font-medium">Technique</th>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 text-right font-medium">Alerts</th>
                    <th className="px-3 py-2 font-medium">Incidents</th>
                    {data!.evaluated && <th className="px-3 py-2 text-right font-medium" title="Alerts with no planted-attack lines">Background</th>}
                    <th className="px-3 py-2 text-right font-medium">Run time</th>
                    <th className="px-3 py-2 font-medium">Last alert</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <RuleTableRow key={r.id} r={r} evaluated={data!.evaluated} selected={selected === r.id} onSelect={() => set('rule', r.id)} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
