// Copied from AI-SOC web_app/frontend/src/components/settings/siem/ResultDialog.tsx
import { AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { IngestEndpoints, SiemIntegrationSecretResponse, SiemVendor } from '@/types/connectors'
import { buildAgentConfig, formatInterval, syslogTargets } from './labels'
import { CodeBlock, ReadOnlyField, StepList } from './common'

function SecretBlock({ result }: { result: SiemIntegrationSecretResponse }) {
  if (!result.secret) return null
  const mode = result.authMode
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 space-y-3">
      <p className="text-xs text-amber-900 flex gap-2">
        <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden="true" />
        <span>
          Copy this secret now. It is stored only as a hash, so it cannot be shown again. If you
          lose it, rotate the secret to issue a new one.
        </span>
      </p>
      <ReadOnlyField label="Secret" value={result.secret} />
      {mode === 'bearer' && result.transport === 'webhook' && (
        <>
          <ReadOnlyField label="Request header" value={`Authorization: Bearer ${result.secret}`} />
          <p className="text-xs text-amber-900">
            If your SIEM will not let you set <span className="font-mono">Authorization</span>, send
            the same value as <span className="font-mono">X-SOAR-Token</span> instead.
          </p>
        </>
      )}
      {mode === 'hmac' && result.transport === 'webhook' && (
        <p className="text-xs text-amber-900">
          Send <span className="font-mono">X-SOAR-Signature: sha256=&lt;digest&gt;</span>, where the
          digest is <span className="font-mono">HMAC-SHA256</span> of the raw request body keyed
          with <span className="font-mono">SHA256(secret)</span>.
        </p>
      )}
    </div>
  )
}

function MtlsBlock({ result }: { result: SiemIntegrationSecretResponse }) {
  if (result.authMode !== 'mtls') return null
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 space-y-2">
      <p className="text-xs text-slate-700">
        This connection authenticates with a client certificate — there is no secret. Issue a
        certificate from the <strong>Certificates</strong> tab whose Common Name matches the
        pattern below.
      </p>
      {result.allowedCnPattern && (
        <ReadOnlyField label="Allowed CN pattern" value={result.allowedCnPattern} />
      )}
    </div>
  )
}

const CEF_EXAMPLE =
  '<134>Sep 30 12:00:00 fw01 CEF:0|Vendor|Product|1.0|100|Brute force detected|8|' +
  'src=203.0.113.5 dst=10.0.0.12 dpt=22 suser=root msg=25 failed logins in 60s'

/** Shown after creating a connection, or after rotating its secret. */
export function ResultDialog({
  result,
  vendor,
  endpoints,
  onClose,
}: {
  result: SiemIntegrationSecretResponse
  vendor: SiemVendor | undefined
  endpoints: IngestEndpoints | undefined
  onClose: () => void
}) {
  const t = result.transport ?? 'webhook'
  const description = {
    webhook: `Point your ${result.vendorLabel} webhook at the URL below.`,
    api_pull: `The log collector will start polling ${result.vendorLabel} within a few seconds.`,
    syslog: `Send ${result.vendorLabel} syslog to the address below.`,
    agent: `Install the forwarding agent next to ${result.vendorLabel} with the configuration below.`,
  }[t]

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{result.name} is ready</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {t === 'webhook' && (
            <>
              {result.webhookUrl && <ReadOnlyField label="Webhook URL" value={result.webhookUrl} />}
              <SecretBlock result={result} />
              <MtlsBlock result={result} />
              <StepList title={`Setting up ${vendor?.label ?? result.vendorLabel}`} steps={vendor?.setupSteps ?? []} />
              {vendor?.docsUrl && (
                <a
                  href={vendor.docsUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-xs text-blue-700 underline inline-block"
                >
                  {vendor.label} webhook documentation
                </a>
              )}
              {vendor?.payloadTemplate && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-800 mb-1">Suggested payload template</h4>
                  <p className="text-xs text-slate-500 mb-1.5">
                    A starting point only — any JSON shape is accepted, since fields are mapped to
                    OCSF automatically.
                  </p>
                  <CodeBlock value={vendor.payloadTemplate} label="payload template" />
                </div>
              )}
            </>
          )}

          {t === 'api_pull' && result.pull && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 space-y-1.5 text-xs text-slate-700">
              <p>
                Polling every <strong>{formatInterval(result.pull.intervalSeconds)}</strong>. The
                first poll looks back{' '}
                <strong>{String(result.pull.config.initial_lookback_minutes ?? 60)} minutes</strong>;
                later polls continue from the newest alert collected.
              </p>
              <p>
                Credentials are stored encrypted ({result.pull.credentialHint || 'hidden'}) and
                cannot be viewed again. Progress and errors appear in the connection list.
              </p>
            </div>
          )}

          {t === 'syslog' && (
            <>
              {syslogTargets(endpoints)
                .filter((x) => result.authMode !== 'mtls' || x.label === 'TLS')
                .map((x) => (
                  <ReadOnlyField key={x.label} label={`Syslog ${x.label}`} value={x.value} />
                ))}
              {result.authMode === 'mtls' && !endpoints?.syslog.tlsEnabled && (
                <p className="text-xs text-amber-700">
                  The TLS listener is not enabled yet. Ask an administrator to set SYSLOG_TLS_CERT
                  and SYSLOG_TLS_KEY on the log collector.
                </p>
              )}
              {result.syslog?.allowedSources.length ? (
                <p className="text-xs text-slate-600">
                  Accepting from:{' '}
                  <span className="font-mono">{result.syslog.allowedSources.join(', ')}</span>
                </p>
              ) : null}
              <MtlsBlock result={result} />
              <StepList title={`Setting up ${vendor?.label ?? result.vendorLabel}`} steps={vendor?.syslogSteps ?? []} />
              <div>
                <h4 className="text-xs font-semibold text-slate-800 mb-1">Test message (CEF)</h4>
                <CodeBlock value={CEF_EXAMPLE} label="example CEF message" />
              </div>
            </>
          )}

          {t === 'agent' && (
            <>
              <SecretBlock result={result} />
              <MtlsBlock result={result} />
              <div>
                <h4 className="text-xs font-semibold text-slate-800 mb-1">agent.json</h4>
                <p className="text-xs text-slate-500 mb-1.5">
                  {result.secret
                    ? 'Contains the secret above. Store it with restricted permissions (chmod 600), or remove the "secret" line and set SOAR_AGENT_SECRET instead.'
                    : 'Set the certificate paths, then edit the inputs for this host.'}
                </p>
                <CodeBlock value={buildAgentConfig(result, result.secret)} label="agent configuration" />
              </div>
              <StepList title="Installing the agent" steps={vendor?.agentSteps ?? []} />
            </>
          )}
        </div>

        <DialogFooter>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
