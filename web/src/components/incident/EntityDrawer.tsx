import { Link } from 'react-router-dom'
import { AlertCircle, ExternalLink } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { RiskBandBadge, SeverityText, TacticChip, TacticChips, TiVerdictBadge } from '@/components/incident/badges'
import { useEntity } from '@/hooks/useIncidents'
import { apiErrorMessage } from '@/lib/api'
import { formatIst } from '@/lib/killchain'
import { NODE_KIND_LABEL } from '@/lib/pathGraph'
import { formatExactTime } from '@/lib/utils'
import type { NodeKind } from '@/types/incident'

const KIND_LABEL: Record<string, string> = { ...NODE_KIND_LABEL, ip: 'IP address', domain: 'Domain', account: 'Account' }

interface Props {
  value: string | null
  onClose: () => void
}

/** Everything the run knows about one IP, host, account or domain, opened from the graph or a list. */
export function EntityDrawer({ value, onClose }: Props) {
  const { data, isLoading, isError, error } = useEntity(value)

  return (
    <Dialog open={!!value} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="left-auto right-0 top-0 h-full max-w-md translate-x-0 translate-y-0 content-start gap-4 overflow-y-auto rounded-none sm:rounded-none">
        <div className="space-y-1 pr-6">
          <DialogTitle className="break-all font-mono text-base">{data?.label ?? value}</DialogTitle>
          <DialogDescription className="text-xs">
            {data ? (
              <>
                {KIND_LABEL[data.kind as NodeKind] ?? data.kind}
                {data.zone && ` · zone ${data.zone}`}
                {data.importance != null && ` · importance ${data.importance.toFixed(2)}`}
              </>
            ) : (
              'Entity'
            )}
          </DialogDescription>
        </div>

        {isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        ) : isError || !data ? (
          <div role="alert" className="flex items-center gap-2 text-sm text-red-700">
            <AlertCircle className="h-4 w-4 shrink-0" /> {apiErrorMessage(error, 'Could not load this entity')}
          </div>
        ) : (
          <>
            <section className="space-y-1.5">
              <h3 className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Threat intel</h3>
              {data.enrichment ? (
                <div className="space-y-1.5 rounded-lg border border-slate-200 p-2.5">
                  <div className="flex items-center gap-2">
                    <TiVerdictBadge verdict={data.enrichment.verdict} />
                    <span className="text-xs text-slate-500">reputation {data.enrichment.reputation.toFixed(2)}</span>
                  </div>
                  <ul className="space-y-0.5 text-xs text-slate-600">
                    {data.enrichment.providers.map((p) => (
                      <li key={p.provider} className="flex flex-wrap gap-1.5">
                        <span className="font-medium text-slate-800">{p.provider}</span>
                        <span>{!p.available ? 'not checked' : p.malicious ? 'flagged' : 'no reports'}</span>
                        {p.tags.length > 0 && <span className="text-slate-400">{p.tags.join(', ')}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-xs text-slate-500">Not looked up for this run.</p>
              )}
            </section>

            <section className="space-y-1.5">
              <div className="flex items-center justify-between">
                <h3 className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
                  Incidents ({data.incidents.length})
                </h3>
                <Link to={`/incidents?entity=${encodeURIComponent(data.value)}`} onClick={onClose} className="text-xs text-blue-600 hover:underline">
                  Filter the list
                </Link>
              </div>
              <ul className="space-y-1.5">
                {data.incidents.map((i) => (
                  <li key={i.incident_number} className="rounded-lg border border-slate-200 p-2.5">
                    <Link to={`/incidents/${i.incident_number}`} onClick={onClose} className="flex items-start gap-2 hover:text-blue-700">
                      <span className="font-mono text-sm font-bold text-slate-400">#{i.incident_number}</span>
                      <span className="flex-1 text-sm font-medium text-slate-900">{i.title}</span>
                      <RiskBandBadge band={i.risk_band} />
                    </Link>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                      {i.roles.map((r) => (
                        <span key={r} className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700">
                          {r}
                        </span>
                      ))}
                      {i.steps.length > 0 && <span>step {i.steps.join(', ')}</span>}
                      <span>{formatIst(i.ts_start_ist)}</span>
                    </div>
                    <div className="mt-1">
                      <TacticChips tactics={i.tactics} max={4} />
                    </div>
                  </li>
                ))}
              </ul>
            </section>

            <section className="space-y-1.5">
              <h3 className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
                Alerts ({data.alerts_total}
                {data.alerts_total > data.alerts.length && `, first ${data.alerts.length} shown`})
              </h3>
              {data.alerts.length === 0 ? (
                <p className="text-xs text-slate-500">No alert names this value directly.</p>
              ) : (
                <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200">
                  {data.alerts.map((a) => (
                    <li key={a.alert_id} className="space-y-1 p-2.5 text-xs">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <TacticChip tactic={a.tactic} />
                        <span className="font-mono text-red-600">{a.technique}</span>
                        <SeverityText severity={a.severity} />
                        <span className="ml-auto text-slate-400">{formatExactTime(a.ts_start)}</span>
                      </div>
                      <p className="text-slate-700">{a.summary}</p>
                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                        <span className="font-mono">{a.rule_id}</span>
                        <span>as {a.as.join(', ')}</span>
                        <span>{a.event_count.toLocaleString()} events</span>
                        {a.incident_number != null ? (
                          <Link to={`/incidents/${a.incident_number}`} onClick={onClose} className="text-blue-600 hover:underline">
                            incident {a.incident_number}
                          </Link>
                        ) : (
                          <span>not in an incident</span>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {data.kind === 'external_ip' || data.kind === 'ip' ? (
              <a
                href={`https://otx.alienvault.com/indicator/ip/${encodeURIComponent(data.value)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
              >
                Look up on AlienVault OTX <ExternalLink className="h-3 w-3" />
              </a>
            ) : null}
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
