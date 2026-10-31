// Copied from AI-SOC web_app/frontend/src/components/settings/siem/ConnectionDetailsDialog.tsx
import type { ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { formatRelativeTime } from '@/lib/utils'
import { useIngestAgentsQuery } from '@/hooks/useConnectors'
import type { IngestEndpoints, SiemIntegrationRow } from '@/types/connectors'
import { AUTH_MODE_LABEL, TRANSPORT_LABEL, formatInterval, syslogTargets } from './labels'
import { ReadOnlyField } from './common'

function rel(v: string | null | undefined): string {
  return v ? formatRelativeTime(v) : '—'
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2 text-xs py-1 border-b border-slate-100 last:border-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-800 break-words">{children}</dd>
    </div>
  )
}

function AgentsTable({ connectorId }: { connectorId: string }) {
  const q = useIngestAgentsQuery(connectorId, true)
  if (q.isLoading) return <p className="text-xs text-slate-500">Loading agents…</p>
  if (q.isError) return <p className="text-xs text-red-600">Could not load agents.</p>
  const agents = q.data?.agents ?? []
  if (!agents.length) {
    return (
      <p className="text-xs text-slate-500">
        No agent has checked in yet. Run the agent with <span className="font-mono">--test</span> to
        send a first heartbeat.
      </p>
    )
  }
  return (
    <table className="w-full text-xs">
      <caption className="sr-only">Forwarding agents for this connection</caption>
      <thead>
        <tr className="text-left text-slate-500 border-b border-slate-200">
          <th scope="col" className="pb-1.5 pr-3">Host</th>
          <th scope="col" className="pb-1.5 pr-3">Status</th>
          <th scope="col" className="pb-1.5 pr-3">Last heartbeat</th>
          <th scope="col" className="pb-1.5 pr-3">Sent</th>
          <th scope="col" className="pb-1.5 pr-3">Spool</th>
          <th scope="col" className="pb-1.5">Inputs</th>
        </tr>
      </thead>
      <tbody>
        {agents.map((a) => (
          <tr key={a.agentId} className="border-b border-slate-100 align-top">
            <td className="py-2 pr-3">
              <div className="font-medium text-slate-800">{a.hostname || a.agentId}</div>
              <div className="text-[11px] text-slate-400">
                v{a.version} · {a.platform} · {a.remoteIp}
              </div>
            </td>
            <td className="py-2 pr-3">
              {a.status === 'online' ? (
                <span className="text-green-600">● Online</span>
              ) : (
                <span className="text-red-600">● Offline</span>
              )}
            </td>
            <td className="py-2 pr-3 font-mono">{rel(a.lastHeartbeatAt)}</td>
            <td className="py-2 pr-3 tabular-nums">
              {a.stats.events_sent ?? 0}
              {a.stats.dropped_events ? (
                <span className="text-red-600"> ({a.stats.dropped_events} dropped)</span>
              ) : null}
            </td>
            <td className="py-2 pr-3 tabular-nums">
              {Math.round((a.stats.spool_bytes ?? 0) / 1024)} KB
            </td>
            <td className="py-2">
              {a.inputs.map((i) => (
                <div key={`${i.type}-${i.target}`} title={i.error || undefined}>
                  <span className={i.status === 'ok' ? 'text-green-700' : i.status === 'error' ? 'text-red-600' : 'text-slate-500'}>
                    {i.status}
                  </span>{' '}
                  <span className="font-mono text-[11px]">{i.target}</span>
                </div>
              ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function ConnectionDetailsDialog({
  row,
  endpoints,
  onClose,
}: {
  row: SiemIntegrationRow
  endpoints: IngestEndpoints | undefined
  onClose: () => void
}) {
  const st = row.pullState
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{row.name}</DialogTitle>
          <DialogDescription>
            {row.vendorLabel} · {row.transport ? TRANSPORT_LABEL[row.transport] : ''}
          </DialogDescription>
        </DialogHeader>

        <dl>
          <Row label="Connector ID">
            <span className="font-mono">{row.connectorId}</span>
          </Row>
          <Row label="Authentication">{row.authMode ? AUTH_MODE_LABEL[row.authMode] : '—'}</Row>
          <Row label="Alerts received">{row.alertsReceived ?? 0}</Row>
          {row.linesForwarded != null && (
            <Row label="Forwarded to live">
              {row.linesForwarded} raw log line(s) written to{' '}
              <span className="font-mono">data/ingest/live.log</span>
            </Row>
          )}
          {row.notAnalysable != null && (
            <Row label="Not analysable">{row.notAnalysable} record(s) with no raw log line</Row>
          )}
          <Row label="Last alert">{rel(row.lastIngestAt)}</Row>
          <Row label="Created">
            {rel(row.createdAt)}
            {row.createdBy ? ` by ${row.createdBy}` : ''}
          </Row>

          {row.transport === 'api_pull' && row.pull && (
            <>
              <Row label="Poll frequency">{formatInterval(row.pull.intervalSeconds)}</Row>
              <Row label="Credentials">
                {row.pull.credentialHint || '—'} (updated {rel(row.pull.credentialsUpdatedAt)})
              </Row>
              <Row label="Last poll">{rel(st?.lastRunAt)}</Row>
              <Row label="Last successful poll">{rel(st?.lastSuccessAt)}</Row>
              <Row label="Next poll">{st?.running ? 'Running now' : rel(st?.nextRunAt)}</Row>
              <Row label="Collected up to">{st?.watermark ?? '—'}</Row>
              {st?.lastRun && (
                <Row label="Last run">
                  {st.lastRun.fetched} fetched, {st.lastRun.queued} new, {st.lastRun.duplicates} already
                  seen, {st.lastRun.pages} page(s) in {st.lastRun.duration_ms} ms
                  {st.lastRun.complete ? '' : ' — more pending, continuing shortly'}
                  {st.lastRun.warning ? ` — ${st.lastRun.warning}` : ''}
                </Row>
              )}
              {st?.lastError && (
                <Row label="Last error">
                  <span className="text-red-600">
                    [{st.lastError.kind}] {st.lastError.message}
                  </span>{' '}
                  ({rel(st.lastError.at)}; {st.consecutiveFailures} consecutive)
                </Row>
              )}
            </>
          )}

          {row.transport === 'syslog' && (
            <>
              <Row label="Allowed senders">
                <span className="font-mono">{row.syslog?.allowedSources.join(', ') || '—'}</span>
              </Row>
              {row.allowedCnPattern && (
                <Row label="Certificate CN">
                  <span className="font-mono">{row.allowedCnPattern}</span>
                </Row>
              )}
              <Row label="Last message">{rel(row.syslog?.lastMessageAt)}</Row>
              <Row label="Last sender">
                <span className="font-mono">{row.syslog?.lastSenderIp ?? '—'}</span>
              </Row>
            </>
          )}
        </dl>

        {row.transport === 'webhook' && row.webhookUrl && (
          <ReadOnlyField label="Webhook URL" value={row.webhookUrl} />
        )}

        {row.transport === 'syslog' && (
          <div className="space-y-2">
            {syslogTargets(endpoints).map((x) => (
              <ReadOnlyField key={x.label} label={`Syslog ${x.label}`} value={x.value} />
            ))}
          </div>
        )}

        {row.transport === 'agent' && row.connectorId && (
          <div className="space-y-3">
            {row.agentEndpoint && <ReadOnlyField label="Agent endpoint" value={row.agentEndpoint} />}
            <h4 className="text-xs font-semibold text-slate-800">Agents</h4>
            <AgentsTable connectorId={row.connectorId} />
          </div>
        )}

        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
