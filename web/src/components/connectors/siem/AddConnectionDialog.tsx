// Copied from AI-SOC web_app/frontend/src/components/settings/siem/AddConnectionDialog.tsx
import { useMemo, useState } from 'react'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { createSiemIntegration } from '@/lib/connectors-api'
import { SIEM_INTEGRATIONS_KEY } from '@/hooks/useConnectors'
import type {
  ConnectorAuthMode,
  CreateSiemIntegrationPayload,
  IngestEndpoints,
  SiemAuthMode,
  SiemIntegrationSecretResponse,
  SiemTransport,
  SiemVendor,
} from '@/types/connectors'
import {
  AUTH_MODE_HELP,
  AUTH_MODE_LABEL,
  SYSLOG_AUTH_HELP,
  TRANSPORT_HELP,
  TRANSPORT_LABEL,
  apiError,
  initialPullConfig,
  nonEmptyCredentials,
  parseSources,
  serialisePullConfig,
} from './labels'
import { StepList } from './common'
import { PullConfigFields, PullCredentialFields } from './PullFields'
import { MonitoringFields } from './MonitoringFields'
import { type MonitoringValues, monitoringFromRow, silenceToApi } from './monitoring'

const AGENT_AUTH_MODES: SiemAuthMode[] = ['hmac', 'bearer', 'mtls']

export function AddConnectionDialog({
  vendors,
  endpoints,
  onCreated,
  onClose,
}: {
  vendors: SiemVendor[]
  endpoints: IngestEndpoints | undefined
  onCreated: (r: SiemIntegrationSecretResponse) => void
  onClose: () => void
}) {
  const queryClient = useQueryClient()

  const [vendorId, setVendorId] = useState('')
  const [transport, setTransport] = useState<SiemTransport | ''>('')
  const [name, setName] = useState('')
  const [authMode, setAuthMode] = useState<ConnectorAuthMode | ''>('')
  const [cnPattern, setCnPattern] = useState('')
  const [pullValues, setPullValues] = useState<Record<string, unknown>>({})
  const [interval, setIntervalSeconds] = useState(300)
  const [creds, setCreds] = useState<Record<string, string>>({})
  const [sourcesText, setSourcesText] = useState('')
  const [monitoring, setMonitoring] = useState<MonitoringValues>(() => monitoringFromRow(null, null))
  const [formError, setFormError] = useState<string | null>(null)

  const vendor = useMemo(() => vendors.find((v) => v.id === vendorId), [vendors, vendorId])
  const effectiveTransport: SiemTransport | '' = transport || vendor?.transports[0] || ''

  const authOptions: ConnectorAuthMode[] = useMemo(() => {
    if (!vendor || !effectiveTransport) return []
    if (effectiveTransport === 'webhook') return vendor.authModes
    if (effectiveTransport === 'agent') return AGENT_AUTH_MODES
    if (effectiveTransport === 'syslog') return ['source_ip', 'mtls']
    return ['api']
  }, [vendor, effectiveTransport])

  const defaultMode: ConnectorAuthMode | '' =
    effectiveTransport === 'webhook'
      ? vendor?.defaultAuthMode ?? ''
      : effectiveTransport === 'agent'
        ? 'hmac'
        : effectiveTransport === 'syslog'
          ? 'source_ip'
          : effectiveTransport === 'api_pull'
            ? 'api'
            : ''
  const effectiveMode: ConnectorAuthMode | '' =
    authMode && authOptions.includes(authMode) ? authMode : defaultMode

  const pullSpec = effectiveTransport === 'api_pull' ? vendor?.pull ?? null : null
  const pullBlocked = effectiveTransport === 'api_pull' && endpoints?.credentialsKeyConfigured === false

  function selectVendor(id: string) {
    const v = vendors.find((x) => x.id === id)
    setVendorId(id)
    setTransport('')
    setAuthMode('')
    setCnPattern('')
    setCreds({})
    setSourcesText('')
    setFormError(null)
    setPullValues(initialPullConfig(v?.pull))
    setIntervalSeconds(v?.pull?.defaultIntervalSeconds ?? 300)
  }

  function selectTransport(t: SiemTransport) {
    setTransport(t)
    setAuthMode('')
    setFormError(null)
  }

  const create = useMutation({
    mutationFn: (payload: CreateSiemIntegrationPayload) => createSiemIntegration(payload),
    onSuccess: (r) => {
      void queryClient.invalidateQueries({ queryKey: SIEM_INTEGRATIONS_KEY })
      onCreated(r)
    },
    onError: (e) => setFormError(apiError(e, 'Could not create the connection.')),
  })

  function submit() {
    if (!vendor || !effectiveTransport) return
    const payload: CreateSiemIntegrationPayload = {
      vendor: vendor.id,
      name: name.trim(),
      transport: effectiveTransport,
      auth_mode: effectiveMode || undefined,
    }
    if (effectiveMode === 'mtls' && cnPattern.trim()) payload.allowed_cn_pattern = cnPattern.trim()
    if (effectiveTransport === 'api_pull' && pullSpec) {
      const { config, error } = serialisePullConfig(pullSpec, pullValues)
      if (error) {
        setFormError(error)
        return
      }
      payload.pull = { config, interval_seconds: interval }
      payload.credentials = nonEmptyCredentials(creds)
    }
    if (effectiveTransport === 'syslog') {
      payload.allowed_sources = parseSources(sourcesText)
    }
    if (monitoring.timeZone.trim()) payload.time_zone = monitoring.timeZone.trim()
    const silence = silenceToApi(monitoring)
    if (silence.error) {
      setFormError(silence.error)
      return
    }
    if (silence.value >= 0) payload.silence_minutes = silence.value
    setFormError(null)
    create.mutate(payload)
  }

  const canSubmit =
    Boolean(vendorId && name.trim() && effectiveTransport) && !create.isPending && !pullBlocked

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[88vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add log source</DialogTitle>
          <DialogDescription>
            Pick the product and how its alerts should reach the platform.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (canSubmit) submit()
          }}
          noValidate
        >
          <div>
            <label htmlFor="vendor" className="text-sm font-medium text-slate-700 block mb-1">
              Log source
            </label>
            <Select value={vendorId} onValueChange={selectVendor}>
              <SelectTrigger id="vendor">
                <SelectValue placeholder="Select a product…" />
              </SelectTrigger>
              <SelectContent>
                {vendors.map((v) => (
                  <SelectItem key={v.id} value={v.id}>
                    {v.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {vendor && (
            <div>
              <label htmlFor="transport" className="text-sm font-medium text-slate-700 block mb-1">
                Collection method
              </label>
              <Select
                value={effectiveTransport}
                onValueChange={(v) => selectTransport(v as SiemTransport)}
              >
                <SelectTrigger id="transport" aria-describedby="transport-help">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {vendor.transports.map((t) => (
                    <SelectItem key={t} value={t}>
                      {TRANSPORT_LABEL[t]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {effectiveTransport && (
                <p id="transport-help" className="text-xs text-slate-500 mt-1">
                  {TRANSPORT_HELP[effectiveTransport]}
                </p>
              )}
            </div>
          )}

          <div>
            <label htmlFor="conn-name" className="text-sm font-medium text-slate-700 block mb-1">
              Name
            </label>
            <Input
              id="conn-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Production cluster"
              maxLength={60}
              aria-describedby="conn-name-help"
            />
            <p id="conn-name-help" className="text-xs text-slate-500 mt-1">
              Just a label, so you can tell multiple connections apart.
            </p>
          </div>

          {vendor && (effectiveTransport === 'webhook' || effectiveTransport === 'agent') && (
            <div>
              <label htmlFor="auth-mode" className="text-sm font-medium text-slate-700 block mb-1">
                Authentication
              </label>
              {authOptions.length > 1 ? (
                <Select value={effectiveMode} onValueChange={(v) => setAuthMode(v as ConnectorAuthMode)}>
                  <SelectTrigger id="auth-mode" aria-describedby="auth-help">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {authOptions.map((m) => (
                      <SelectItem key={m} value={m}>
                        {AUTH_MODE_LABEL[m]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <p id="auth-mode" className="text-sm text-slate-700">
                  {effectiveMode ? AUTH_MODE_LABEL[effectiveMode] : '—'}
                </p>
              )}
              {effectiveMode && effectiveMode in AUTH_MODE_HELP && (
                <p id="auth-help" className="text-xs text-slate-500 mt-1">
                  {AUTH_MODE_HELP[effectiveMode as SiemAuthMode]}
                </p>
              )}
            </div>
          )}

          {vendor && effectiveTransport === 'syslog' && (
            <>
              <div>
                <label htmlFor="syslog-auth" className="text-sm font-medium text-slate-700 block mb-1">
                  Identify the sender by
                </label>
                <Select value={effectiveMode} onValueChange={(v) => setAuthMode(v as ConnectorAuthMode)}>
                  <SelectTrigger id="syslog-auth" aria-describedby="syslog-auth-help">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="source_ip">Sender IP address</SelectItem>
                    <SelectItem value="mtls">Client certificate (TLS listener)</SelectItem>
                  </SelectContent>
                </Select>
                <p id="syslog-auth-help" className="text-xs text-slate-500 mt-1">
                  {SYSLOG_AUTH_HELP[effectiveMode === 'mtls' ? 'mtls' : 'source_ip']}
                </p>
                {effectiveMode === 'mtls' && endpoints && !endpoints.syslog.tlsEnabled && (
                  <p className="text-xs text-amber-700 mt-1">
                    The TLS syslog listener is not enabled on this deployment yet
                    (SYSLOG_TLS_CERT / SYSLOG_TLS_KEY on the log collector).
                  </p>
                )}
              </div>
              {effectiveMode === 'source_ip' && (
                <div>
                  <label htmlFor="sources" className="text-sm font-medium text-slate-700 block mb-1">
                    Allowed sender addresses
                  </label>
                  <Textarea
                    id="sources"
                    value={sourcesText}
                    onChange={(e) => setSourcesText(e.target.value)}
                    placeholder={'203.0.113.10\n10.20.0.0/24'}
                    className="font-mono text-xs"
                    aria-describedby="sources-help"
                  />
                  <p id="sources-help" className="text-xs text-slate-500 mt-1">
                    IP addresses or CIDR ranges, one per line. Use the address the platform sees —
                    for a source behind NAT, that is the firewall’s public address.
                  </p>
                </div>
              )}
            </>
          )}

          {effectiveMode === 'mtls' && (
            <div>
              <label htmlFor="cn" className="text-sm font-medium text-slate-700 block mb-1">
                Allowed certificate CN pattern
              </label>
              <Input
                id="cn"
                value={cnPattern}
                onChange={(e) => setCnPattern(e.target.value)}
                placeholder={vendorId ? `${vendorId}.*` : 'e.g. wazuh.*'}
                className="font-mono text-xs"
                aria-describedby="cn-help"
              />
              <p id="cn-help" className="text-xs text-slate-500 mt-1">
                Regular expression the whole client certificate Common Name must match. Defaults to{' '}
                <span className="font-mono">{vendorId || 'vendor'}.*</span> if left blank.
              </p>
            </div>
          )}

          {pullSpec && (
            <>
              {pullBlocked && (
                <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800 flex gap-2">
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden="true" />
                  <span>
                    API credentials cannot be stored until an administrator sets
                    CONNECTOR_CREDENTIALS_KEY on the web-app backend and log collector.
                  </span>
                </div>
              )}
              <StepList title={`Before you start (${vendor?.label})`} steps={pullSpec.setupSteps} />
              {pullSpec.docsUrl && (
                <a
                  href={pullSpec.docsUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-xs text-blue-700 underline inline-block"
                >
                  {vendor?.label} API documentation
                </a>
              )}
              <PullConfigFields
                spec={pullSpec}
                values={pullValues}
                onChange={(k, v) => setPullValues((p) => ({ ...p, [k]: v }))}
                intervalSeconds={interval}
                onIntervalChange={setIntervalSeconds}
                idPrefix="add-pull"
              />
              <PullCredentialFields
                spec={pullSpec}
                config={pullValues}
                values={creds}
                onChange={(k, v) => setCreds((p) => ({ ...p, [k]: v }))}
                idPrefix="add-pull"
                editing={false}
              />
            </>
          )}

          {vendor && (
            <MonitoringFields values={monitoring} onChange={setMonitoring} idPrefix="add-mon" />
          )}

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
            <Button type="submit" disabled={!canSubmit}>
              {create.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" aria-hidden="true" />}
              Create connection
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
