// Copied from AI-SOC web_app/frontend/src/components/settings/siem/EditConnectionDialog.tsx
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertCircle, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useAppStore } from '@/store/useAppStore'
import { updateSiemIntegration } from '@/lib/connectors-api'
import { SIEM_INTEGRATIONS_KEY } from '@/hooks/useConnectors'
import type { SiemIntegrationRow, SiemVendor, UpdateSiemIntegrationPayload } from '@/types/connectors'
import {
  TRANSPORT_LABEL,
  apiError,
  initialPullConfig,
  nonEmptyCredentials,
  parseSources,
  serialisePullConfig,
} from './labels'
import { PullConfigFields, PullCredentialFields } from './PullFields'
import { MonitoringFields } from './MonitoringFields'
import { type MonitoringValues, monitoringFromRow, silenceToApi } from './monitoring'

export function EditConnectionDialog({
  row,
  vendor,
  onClose,
}: {
  row: SiemIntegrationRow
  vendor: SiemVendor | undefined
  onClose: () => void
}) {
  const addNotification = useAppStore((s) => s.addNotification)
  const queryClient = useQueryClient()
  const pullSpec = row.transport === 'api_pull' ? vendor?.pull ?? null : null

  const [name, setName] = useState(row.name)
  const [cnPattern, setCnPattern] = useState(row.allowedCnPattern ?? '')
  const [pullValues, setPullValues] = useState<Record<string, unknown>>(() =>
    initialPullConfig(pullSpec, row.pull?.config)
  )
  const [interval, setIntervalSeconds] = useState(
    row.pull?.intervalSeconds || pullSpec?.defaultIntervalSeconds || 300
  )
  const [creds, setCreds] = useState<Record<string, string>>({})
  const [sourcesText, setSourcesText] = useState((row.syslog?.allowedSources ?? []).join('\n'))
  const [monitoring, setMonitoring] = useState<MonitoringValues>(() =>
    monitoringFromRow(row.timeZone, row.health?.silenceMinutes)
  )
  const [formError, setFormError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (payload: UpdateSiemIntegrationPayload) =>
      updateSiemIntegration(row.connectorId as string, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: SIEM_INTEGRATIONS_KEY })
      addNotification({ type: 'success', message: `${row.name} updated.` })
      onClose()
    },
    onError: (e) => setFormError(apiError(e, 'Could not update the connection.')),
  })

  function submit() {
    const payload: UpdateSiemIntegrationPayload = {}
    if (name.trim() !== row.name) payload.name = name.trim()
    if (row.authMode === 'mtls' && cnPattern.trim() !== (row.allowedCnPattern ?? '')) {
      payload.allowed_cn_pattern = cnPattern.trim()
    }
    if (pullSpec) {
      const { config, error } = serialisePullConfig(pullSpec, pullValues)
      if (error) {
        setFormError(error)
        return
      }
      payload.pull = { config, interval_seconds: interval }
      const c = nonEmptyCredentials(creds)
      if (Object.keys(c).length) payload.credentials = c
    }
    if (row.transport === 'syslog') {
      payload.allowed_sources = parseSources(sourcesText)
    }
    if (monitoring.timeZone.trim() !== (row.timeZone ?? '')) {
      payload.time_zone = monitoring.timeZone.trim()
    }
    const silence = silenceToApi(monitoring)
    if (silence.error) {
      setFormError(silence.error)
      return
    }
    const current = row.health?.silenceMinutes
    const currentApi = current === 0 ? 0 : current && current > 0 ? current : -1
    if (silence.value !== currentApi) payload.silence_minutes = silence.value
    setFormError(null)
    save.mutate(payload)
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[88vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit “{row.name}”</DialogTitle>
          <DialogDescription>
            {row.vendorLabel} · {row.transport ? TRANSPORT_LABEL[row.transport] : ''}
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (!save.isPending) submit()
          }}
          noValidate
        >
          <div>
            <label htmlFor="edit-name" className="text-sm font-medium text-slate-700 block mb-1">
              Name
            </label>
            <Input id="edit-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} />
          </div>

          {row.authMode === 'mtls' && (
            <div>
              <label htmlFor="edit-cn" className="text-sm font-medium text-slate-700 block mb-1">
                Allowed certificate CN pattern
              </label>
              <Input
                id="edit-cn"
                value={cnPattern}
                onChange={(e) => setCnPattern(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          )}

          {row.transport === 'syslog' && row.authMode === 'source_ip' && (
            <div>
              <label htmlFor="edit-sources" className="text-sm font-medium text-slate-700 block mb-1">
                Allowed sender addresses
              </label>
              <Textarea
                id="edit-sources"
                value={sourcesText}
                onChange={(e) => setSourcesText(e.target.value)}
                className="font-mono text-xs"
                aria-describedby="edit-sources-help"
              />
              <p id="edit-sources-help" className="text-xs text-slate-500 mt-1">
                IP addresses or CIDR ranges, one per line. Changes apply within 30 seconds.
              </p>
            </div>
          )}

          {pullSpec && (
            <>
              <PullConfigFields
                spec={pullSpec}
                values={pullValues}
                onChange={(k, v) => setPullValues((p) => ({ ...p, [k]: v }))}
                intervalSeconds={interval}
                onIntervalChange={setIntervalSeconds}
                idPrefix="edit-pull"
              />
              <p className="text-xs text-slate-500">
                Changing the endpoint, resource or filter restarts collection from the initial
                lookback window. Alerts already collected are not duplicated.
              </p>
              <PullCredentialFields
                spec={pullSpec}
                config={pullValues}
                values={creds}
                onChange={(k, v) => setCreds((p) => ({ ...p, [k]: v }))}
                idPrefix="edit-pull"
                editing
                credentialHint={row.pull?.credentialHint}
              />
            </>
          )}

          <MonitoringFields values={monitoring} onChange={setMonitoring} idPrefix="edit-mon" />

          {formError && (
            <p role="alert" className="text-sm text-red-600 flex gap-1.5 items-start">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden="true" />
              {formError}
            </p>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending || !name.trim()}>
              {save.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" aria-hidden="true" />}
              Save changes
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
