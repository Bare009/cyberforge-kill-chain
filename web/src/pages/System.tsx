import { Activity, AlertCircle, CheckCircle2, XCircle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { BudgetMeter } from '@/components/agents/BudgetMeter'
import { BarList, PageTitle } from '@/components/views/shared'
import { useSystem } from '@/hooks/useSystem'
import { apiErrorMessage } from '@/lib/api'
import { formatBytes, formatSecs } from '@/lib/format'
import { providerLabel } from '@/lib/threatIntel'
import { formatFullTime } from '@/lib/utils'
import type { SystemResponse } from '@/types/system'

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card aria-label={title}>
      <CardContent className="space-y-3 p-4">
        <h2 className="text-sm font-semibold text-slate-800">{title}</h2>
        {children}
      </CardContent>
    </Card>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-3 border-b border-slate-50 py-1 text-xs last:border-0">
      <dt className="text-slate-500">{k}</dt>
      <dd className="text-right text-slate-800">{v}</dd>
    </div>
  )
}

function Yes({ ok, text }: { ok: boolean; text: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      {ok ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" /> : <XCircle className="h-3.5 w-3.5 text-slate-400" />}
      {text}
    </span>
  )
}

const KEYS = ['alerts', 'incidents', 'steps', 'evidence_lines', 'indicators', 'lines', 'rules', 'unexplained'] as const

function Stages({ s }: { s: SystemResponse }) {
  const rows = Object.entries(s.stages)
  if (!rows.length) return <p className="text-sm text-slate-400">No stage timings in this run.</p>
  return (
    <div className="space-y-3">
      <table className="w-full text-left text-xs" aria-label="Stage timings">
        <thead className="border-b border-slate-100 text-[11px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="py-1.5 font-medium">Stage</th>
            <th className="py-1.5 text-right font-medium">Time</th>
            <th className="py-1.5 text-right font-medium">Peak memory</th>
            <th className="py-1.5 pl-3 font-medium">Output</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([name, st]) => (
            <tr key={name} className="border-b border-slate-50">
              <td className="py-1.5 font-medium text-slate-800">{name}</td>
              <td className="py-1.5 text-right font-mono">{formatSecs(st.wall_secs ?? null)}</td>
              <td className="py-1.5 text-right font-mono">{st.peak_rss_mb ? `${Number(st.peak_rss_mb).toLocaleString()} MB` : '—'}</td>
              <td className="py-1.5 pl-3 text-slate-500">
                {KEYS.filter((k) => typeof st[k] === 'number').map((k) => `${Number(st[k]).toLocaleString()} ${k.replace('_', ' ')}`).join(', ')}
              </td>
            </tr>
          ))}
        </tbody>
        {s.totals.processing_secs != null && (
          <tfoot>
            <tr className="font-medium">
              <td className="py-1.5">Total</td>
              <td className="py-1.5 text-right font-mono">{formatSecs(s.totals.processing_secs)}</td>
              <td className="py-1.5 text-right font-mono">{s.totals.peak_rss_mb ? `${s.totals.peak_rss_mb.toLocaleString()} MB` : '—'}</td>
              <td />
            </tr>
          </tfoot>
        )}
      </table>
      <BarList colour="bg-slate-400" rows={rows.filter(([, st]) => st.wall_secs != null)
        .map(([n, st]) => ({ key: n, label: n, value: Math.round((st.wall_secs ?? 0) * 10) / 10 }))} />
    </div>
  )
}

export function System() {
  const { data: s, isLoading, isError, error } = useSystem()
  return (
    <div className="space-y-5">
      <PageTitle icon={<Activity className="h-5 w-5" />} title="System"
        subtitle="How this run was made and what the API is serving: stages, data quality, threat intel and LLM status." />
      {isError ? (
        <div role="alert" className="flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          <AlertCircle className="h-4 w-4" /> Could not load the system status: {apiErrorMessage(error)}
        </div>
      ) : isLoading || !s ? (
        <div className="grid gap-4 lg:grid-cols-2">{[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-48" />)}</div>
      ) : (
        <>
          {(s.contract_error_count > 0 || s.warnings.length > 0) && (
            <div role="alert" className="space-y-1 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-900">
              {s.contract_error_count > 0 && <p>{s.contract_error_count} contract problem(s) in the run, e.g. {s.contract_errors[0]}</p>}
              {s.warnings.map((w) => <p key={w}>Bundle warning: {w}</p>)}
            </div>
          )}
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <Panel title="Pipeline stages"><Stages s={s} /></Panel>
            <Panel title="Run">
              <dl>
                <Row k="Run" v={<span className="font-mono">{s.run}{s.sample ? ' (sample)' : ''}</span>} />
                <Row k="Folder" v={<span className="break-all font-mono">{s.run_dir}</span>} />
                <Row k="Bundled" v={formatFullTime(s.bundled_at)} />
                <Row k="Loaded by the API" v={`${formatFullTime(s.api.loaded_at)}${s.api.reloads ? ` (${s.api.reloads} reloads)` : ''}`} />
                <Row k="Watching for changes" v={<Yes ok={s.api.watching} text={s.api.watching ? 'yes' : 'no'} />} />
                <Row k="Evidence from" v={s.evidence.origin} />
                {s.evidence.logs.map((l) => (
                  <Row key={l.source} k={`Raw log ${l.source}`}
                    v={<Yes ok={l.available} text={l.available ? 'found' : `not in ${s.evidence.raw_dir}`} />} />
                ))}
                <Row k="Rule tests" v={<Yes ok={s.rule_test_sandbox} text={s.rule_test_sandbox ? 'events.duckdb ready' : 'no events.duckdb'} />} />
              </dl>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="Data quality">
              {s.data_quality ? (
                <dl>
                  <Row k="Log lines" v={s.data_quality.lines?.toLocaleString() ?? '—'} />
                  <Row k="Events parsed" v={s.data_quality.events.toLocaleString()} />
                  <Row k="Good clock" v={s.data_quality.events_good_time.toLocaleString()} />
                  <Row k="Frozen clock" v={s.data_quality.events_frozen_clock.toLocaleString()} />
                  <Row k="Exact duplicates" v={s.data_quality.exact_duplicate_rows.toLocaleString()} />
                  <Row k="Rejected lines" v={s.data_quality.rejected_lines.toLocaleString()} />
                  <Row k="Junk data" v={formatBytes(s.data_quality.junk_bytes)} />
                  {Object.entries(s.data_quality.parse_issues).map(([k, v]) => <Row key={k} k={`Parse issue: ${k}`} v={v.toLocaleString()} />)}
                </dl>
              ) : <p className="text-sm text-slate-400">No parser statistics in this run.</p>}
            </Panel>
            <Panel title="Threat intel">
              <dl>
                {Object.entries(s.threat_intel.providers).map(([k, v]) => <Row key={k} k={providerLabel(k)} v={<Yes ok={v === 'ok'} text={v === 'ok' ? 'on' : v} />} />)}
                <Row k="Indicators" v={s.threat_intel.indicators} />
                <Row k="Results from" v={s.threat_intel.source} />
                {s.threat_intel.last_run && <Row k="Last enrich" v={`${s.threat_intel.last_run.lookups} lookups, ${s.threat_intel.last_run.cache_hits} cached, ${s.threat_intel.last_run.failures} failed`} />}
                {Object.entries(s.threat_intel.cache ?? {}).map(([k, c]) => <Row key={k} k={`${providerLabel(k)} cache`} v={`${c.answers} answers (${c.fresh} fresh)`} />)}
                <Row k="Network" v={s.threat_intel.offline ? 'offline (cache only)' : 'on'} />
              </dl>
            </Panel>
            <Panel title="LLM agents">
              <dl>
                <Row k="Batch narrator" v={s.llm.enabled ? 'on (LLM_ENABLED)' : 'off'} />
                <Row k="Models" v={s.llm.configured.length ? s.llm.configured.join(', ') : 'none (no key in .env)'} />
                <Row k="Reports" v={`${s.llm.ai_reports} AI, ${s.llm.template_reports} template`} />
              </dl>
              <BudgetMeter compact />
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Run files">
              <table className="w-full text-left text-xs" aria-label="Run file list">
                <tbody>
                  {s.files.map((f) => (
                    <tr key={f.name} className="border-b border-slate-50">
                      <td className="py-1 font-mono text-slate-700">{f.name}</td>
                      <td className="py-1 text-right font-mono text-slate-500">{f.files > 1 ? `${f.files} files` : ''}</td>
                      <td className="py-1 text-right font-mono text-slate-700">{formatBytes(f.bytes)}</td>
                      <td className="py-1 pl-3 text-right text-slate-400">{formatFullTime(f.modified)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
            <Panel title="API">
              <dl>
                <Row k="Started" v={formatFullTime(s.api.started_at)} />
                <Row k="Uptime" v={formatSecs(s.api.uptime_s)} />
                <Row k="Platform" v={s.api.platform} />
                <Row k="Rules folder" v={<span className="break-all font-mono">{s.rules_dir}</span>} />
                {Object.entries(s.api.versions).map(([k, v]) => <Row key={k} k={k} v={<span className="font-mono">{v}</span>} />)}
              </dl>
            </Panel>
          </div>
        </>
      )}
    </div>
  )
}
