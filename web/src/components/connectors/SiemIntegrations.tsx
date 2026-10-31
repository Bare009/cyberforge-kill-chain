// Copied from AI-SOC web_app/frontend/src/components/settings/SiemIntegrations.tsx
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Info, Loader2, Pencil, Play, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useAppStore } from '@/store/useAppStore'
import { formatRelativeTime } from '@/lib/utils'
import {
  deleteSiemIntegration,
  pollSiemIntegrationNow,
  rotateSiemIntegrationSecret,
  updateSiemIntegration,
} from '@/lib/connectors-api'
import {
  SIEM_INTEGRATIONS_KEY,
  useSiemIntegrationsQuery,
  useSiemVendorsQuery,
} from '@/hooks/useConnectors'
import type { SiemIntegrationRow, SiemIntegrationSecretResponse } from '@/types/connectors'
import { AUTH_MODE_LABEL, TRANSPORT_SHORT, apiError, formatInterval } from './siem/labels'
import { PullSummary, StatusPill } from './siem/common'
import { AddConnectionDialog } from './siem/AddConnectionDialog'
import { ResultDialog } from './siem/ResultDialog'
import { EditConnectionDialog } from './siem/EditConnectionDialog'
import { ConnectionDetailsDialog } from './siem/ConnectionDetailsDialog'

function canRotate(r: SiemIntegrationRow): boolean {
  return (
    (r.transport === 'webhook' || r.transport === 'agent' || r.transport == null) &&
    (r.authMode === 'bearer' || r.authMode === 'hmac')
  )
}

function Subtitle({ row }: { row: SiemIntegrationRow }) {
  if (row.transport === 'webhook' && row.webhookUrl) {
    return <div className="font-mono text-[11px] text-slate-400 mt-0.5 break-all">{row.webhookUrl}</div>
  }
  if (row.transport === 'api_pull') {
    return (
      <>
        <div className="text-[11px] text-slate-400 mt-0.5">
          Every {formatInterval(row.pull?.intervalSeconds ?? 0)}
        </div>
        <PullSummary row={row} />
      </>
    )
  }
  if (row.transport === 'syslog') {
    const src = row.syslog?.allowedSources ?? []
    return (
      <div className="font-mono text-[11px] text-slate-400 mt-0.5 break-all">
        {src.length ? `from ${src.slice(0, 3).join(', ')}${src.length > 3 ? ` +${src.length - 3}` : ''}` : row.allowedCnPattern ? `CN ${row.allowedCnPattern}` : ''}
      </div>
    )
  }
  if (row.transport === 'agent' && row.agentEndpoint) {
    return <div className="font-mono text-[11px] text-slate-400 mt-0.5 break-all">{row.agentEndpoint}</div>
  }
  return null
}

// killchain: no login, so every connection is manageable (AI-SOC's canManage gate removed).
export function SiemIntegrations() {
  const addNotification = useAppStore((s) => s.addNotification)
  const queryClient = useQueryClient()

  const rowsQ = useSiemIntegrationsQuery()
  const vendorsQ = useSiemVendorsQuery()

  const [adding, setAdding] = useState(false)
  const [result, setResult] = useState<SiemIntegrationSecretResponse | null>(null)
  const [editing, setEditing] = useState<SiemIntegrationRow | null>(null)
  const [details, setDetails] = useState<SiemIntegrationRow | null>(null)
  const [pendingDelete, setPendingDelete] = useState<SiemIntegrationRow | null>(null)

  const vendors = vendorsQ.data?.vendors ?? []
  const endpoints = vendorsQ.data?.endpoints
  const vendorFor = (id: string | null | undefined) => vendors.find((v) => v.id === id)

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: SIEM_INTEGRATIONS_KEY })
  }

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateSiemIntegration(id, { enabled }),
    onSuccess: (_d, v) => {
      invalidate()
      addNotification({
        type: 'success',
        message: v.enabled
          ? 'Connection enabled. It will collect alerts again.'
          : 'Connection disabled. It will stop collecting alerts.',
      })
    },
    onError: (e) =>
      addNotification({ type: 'error', message: apiError(e, 'Could not update the connection.') }),
  })

  const rotate = useMutation({
    mutationFn: (id: string) => rotateSiemIntegrationSecret(id),
    onSuccess: (r) => {
      invalidate()
      setResult(r)
    },
    onError: (e) =>
      addNotification({ type: 'error', message: apiError(e, 'Could not rotate the secret.') }),
  })

  const poll = useMutation({
    mutationFn: (id: string) => pollSiemIntegrationNow(id),
    onSuccess: () => {
      invalidate()
      addNotification({ type: 'success', message: 'Poll scheduled. Results appear within a few seconds.' })
      // The collector ticks every ~10s; refresh once it has had a chance to run.
      window.setTimeout(invalidate, 12_000)
    },
    onError: (e) => addNotification({ type: 'error', message: apiError(e, 'Could not start a poll.') }),
  })

  const remove = useMutation({
    mutationFn: (id: string) => deleteSiemIntegration(id),
    onSuccess: () => {
      invalidate()
      setPendingDelete(null)
      addNotification({ type: 'success', message: 'Connection deleted.' })
    },
    onError: (e) =>
      addNotification({ type: 'error', message: apiError(e, 'Could not delete the connection.') }),
  })

  const rows = rowsQ.data?.integrations ?? []
  const configured = rows.filter((r) => r.registered)
  const observedOnly = rows.filter((r) => !r.registered)
  // killchain: forwarded / not-analysable counters, shown when the backend reports them.
  const hasForwarding = configured.some((r) => r.linesForwarded != null || r.notAnalysable != null)

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">Log sources</CardTitle>
            <p className="text-xs text-slate-500 font-normal mt-1 max-w-2xl">
              Add the security products you want to collect from. Each connection either receives
              alerts (webhook, syslog, forwarding agent) or collects them from the product’s API on
              a schedule. Alerts are mapped to OCSF automatically, so no schema setup is needed.
            </p>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setAdding(true)}
            disabled={vendorsQ.isLoading}
          >
            <Plus className="h-3.5 w-3.5 mr-1" aria-hidden="true" />
            Add connection
          </Button>
        </CardHeader>
        <CardContent>
          {rowsQ.isLoading && <p className="text-sm text-slate-500 py-6">Loading connections…</p>}
          {rowsQ.isError && (
            <p className="text-sm text-red-600 py-6">Could not load log source connections.</p>
          )}

          {rowsQ.data && configured.length === 0 && (
            <div className="py-8 text-center">
              <p className="text-sm text-slate-600">No log sources configured yet.</p>
              <p className="text-xs text-slate-500 mt-1">
                Add one to start collecting alerts from your SIEM or EDR.
              </p>
            </div>
          )}

          {configured.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Configured log source connections</caption>
                <thead>
                  <tr className="text-left text-xs text-slate-500 border-b border-slate-200">
                    <th scope="col" className="pb-2 pr-4">Name</th>
                    <th scope="col" className="pb-2 pr-4">Product</th>
                    <th scope="col" className="pb-2 pr-4">Method</th>
                    <th scope="col" className="pb-2 pr-4">Status</th>
                    <th scope="col" className="pb-2 pr-4">Last ingest</th>
                    <th scope="col" className="pb-2 pr-4">Today</th>
                    <th scope="col" className="pb-2 pr-4">Total</th>
                    {hasForwarding && (
                      <>
                        <th scope="col" className="pb-2 pr-4" title="Raw log lines forwarded to live mode">
                          Forwarded
                        </th>
                        <th scope="col" className="pb-2 pr-4" title="Records with no raw log line">
                          Not analysable
                        </th>
                      </>
                    )}
                    <th scope="col" className="pb-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {configured.map((r) => {
                    const id = r.connectorId as string
                    const busy =
                      (rotate.isPending && rotate.variables === id) ||
                      (toggle.isPending && toggle.variables?.id === id) ||
                      (poll.isPending && poll.variables === id)
                    return (
                      <tr key={id} className="border-b border-slate-100 align-middle">
                        <td className="py-3 pr-2 font-medium text-slate-800">
                          {r.name}
                          <Subtitle row={r} />
                        </td>
                        <td className="py-3 text-slate-700">{r.vendorLabel}</td>
                        <td className="py-3">
                          <span className="text-xs text-slate-700">
                            {r.transport ? TRANSPORT_SHORT[r.transport] : 'Webhook'}
                          </span>
                          <div className="text-[11px] text-slate-400">
                            {r.authMode ? AUTH_MODE_LABEL[r.authMode] : '—'}
                          </div>
                          {r.secretHint && (
                            <div className="font-mono text-[11px] text-slate-400">{r.secretHint}</div>
                          )}
                        </td>
                        <td className="py-3">
                          <StatusPill row={r} />
                        </td>
                        <td className="py-3 font-mono text-slate-600 text-xs">
                          {r.lastIngestAt ? formatRelativeTime(r.lastIngestAt) : '—'}
                        </td>
                        <td className="py-3 tabular-nums">{r.alertsToday}</td>
                        <td className="py-3 tabular-nums text-slate-600">{r.totalAlerts}</td>
                        {hasForwarding && (
                          <>
                            <td className="py-3 tabular-nums text-slate-600">{r.linesForwarded ?? 0}</td>
                            <td
                              className={
                                r.notAnalysable
                                  ? 'py-3 tabular-nums text-amber-700'
                                  : 'py-3 tabular-nums text-slate-600'
                              }
                            >
                              {r.notAnalysable ?? 0}
                            </td>
                          </>
                        )}
                        <td className="py-3">
                          <div className="flex gap-1.5 justify-end">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setDetails(r)}
                              title="Details"
                              aria-label={`Details for ${r.name}`}
                            >
                              <Info className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            {r.transport === 'api_pull' && (
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={busy || !r.enabled}
                                onClick={() => poll.mutate(id)}
                                title="Poll now"
                                aria-label={`Poll ${r.name} now`}
                              >
                                {poll.isPending && poll.variables === id ? (
                                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                                ) : (
                                  <Play className="h-3.5 w-3.5" aria-hidden="true" />
                                )}
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busy}
                              onClick={() => setEditing(r)}
                              title="Edit"
                              aria-label={`Edit ${r.name}`}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busy}
                              onClick={() => toggle.mutate({ id, enabled: !r.enabled })}
                              title={r.enabled ? 'Stop collecting alerts' : 'Resume collecting alerts'}
                            >
                              {r.enabled ? 'Disable' : 'Enable'}
                            </Button>
                            {canRotate(r) && (
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={busy}
                                onClick={() => rotate.mutate(id)}
                                title="Issue a new secret (the current one stops working immediately)"
                                aria-label={`Rotate secret for ${r.name}`}
                              >
                                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busy}
                              onClick={() => setPendingDelete(r)}
                              title="Delete this connection"
                              aria-label={`Delete ${r.name}`}
                              className="text-red-600 hover:text-red-700"
                            >
                              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {observedOnly.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Other sources seen in alert data</CardTitle>
            <p className="text-xs text-slate-500 font-normal mt-1 max-w-2xl">
              These are inferred from records already stored rather than from a configured
              connection, for example records received before the connection existed. Add a
              connection above if you want a managed credential for one of them.
            </p>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <caption className="sr-only">Sources observed in alert data only</caption>
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-200">
                  <th scope="col" className="pb-2 pr-4">Source</th>
                  <th scope="col" className="pb-2 pr-4">Status</th>
                  <th scope="col" className="pb-2 pr-4">Last ingest</th>
                  <th scope="col" className="pb-2 pr-4">Today</th>
                  <th scope="col" className="pb-2">Total</th>
                </tr>
              </thead>
              <tbody>
                {observedOnly.map((r) => (
                  <tr key={`obs-${r.name}`} className="border-b border-slate-100">
                    <td className="py-3 font-medium text-slate-800">{r.name}</td>
                    <td className="py-3">
                      <StatusPill row={r} />
                    </td>
                    <td className="py-3 font-mono text-slate-600 text-xs">
                      {r.lastIngestAt ? formatRelativeTime(r.lastIngestAt) : '—'}
                    </td>
                    <td className="py-3 tabular-nums">{r.alertsToday}</td>
                    <td className="py-3 tabular-nums text-slate-600">{r.totalAlerts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {adding && (
        <AddConnectionDialog
          vendors={vendors}
          endpoints={endpoints}
          onClose={() => setAdding(false)}
          onCreated={(r) => {
            setAdding(false)
            setResult(r)
          }}
        />
      )}

      {result && (
        <ResultDialog
          result={result}
          vendor={vendorFor(result.vendor)}
          endpoints={endpoints}
          onClose={() => setResult(null)}
        />
      )}

      {editing && (
        <EditConnectionDialog
          row={editing}
          vendor={vendorFor(editing.vendor)}
          onClose={() => setEditing(null)}
        />
      )}

      {details && (
        <ConnectionDetailsDialog
          // Re-read from the live list so counters/state refresh while open.
          row={configured.find((r) => r.connectorId === details.connectorId) ?? details}
          endpoints={endpoints}
          onClose={() => setDetails(null)}
        />
      )}

      {pendingDelete && (
        <Dialog open onOpenChange={(o) => !o && setPendingDelete(null)}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Delete “{pendingDelete.name}”?</DialogTitle>
              <DialogDescription>
                {pendingDelete.transport === 'api_pull'
                  ? `Polling ${pendingDelete.vendorLabel} stops and its stored API credentials are deleted.`
                  : `${pendingDelete.vendorLabel} will stop being able to send alerts through this connection immediately.`}{' '}
                Alerts already ingested are kept. This cannot be undone — adding the source again
                produces a new connection id and credential.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setPendingDelete(null)}>
                Cancel
              </Button>
              <Button
                onClick={() => remove.mutate(pendingDelete.connectorId as string)}
                disabled={remove.isPending}
                className="bg-red-600 hover:bg-red-700 text-white"
              >
                {remove.isPending && (
                  <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" aria-hidden="true" />
                )}
                Delete connection
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
