// Copied from AI-SOC web_app/frontend/src/components/settings/siem/common.tsx
import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useAppStore } from '@/store/useAppStore'
import { formatRelativeTime } from '@/lib/utils'
import type { SiemIntegrationRow } from '@/types/connectors'
import { HEALTH_KIND_SHORT } from './labels'

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const addNotification = useAppStore((s) => s.addNotification)

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard access is blocked on insecure origins and in some browsers.
      // Say so rather than silently doing nothing — the user needs this value.
      addNotification({
        type: 'error',
        message: 'Could not copy automatically. Select the text and copy manually.',
      })
    }
  }

  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      onClick={copy}
      aria-label={`Copy ${label}`}
      className="shrink-0"
    >
      {copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
      <span className="ml-1.5">{copied ? 'Copied' : 'Copy'}</span>
    </Button>
  )
}

export function ReadOnlyField({
  label,
  value,
  mono = true,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  const id = `f-${label.replace(/[^A-Za-z0-9]+/g, '-').toLowerCase()}`
  return (
    <div>
      <label htmlFor={id} className="text-xs font-medium text-slate-700 block mb-1">
        {label}
      </label>
      <div className="flex gap-2 items-center">
        <Input
          id={id}
          readOnly
          value={value}
          className={mono ? 'font-mono text-xs' : 'text-xs'}
          onFocus={(e) => e.currentTarget.select()}
        />
        <CopyButton value={value} label={label} />
      </div>
    </div>
  )
}

export function CodeBlock({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <pre
        className="text-[11px] bg-slate-900 text-slate-100 rounded-lg p-3 overflow-x-auto max-h-72"
        aria-label={label}
      >
        {value}
      </pre>
      <div className="mt-2">
        <CopyButton value={value} label={label} />
      </div>
    </div>
  )
}

export function StepList({ title, steps }: { title: string; steps: string[] }) {
  if (!steps.length) return null
  return (
    <div>
      <h4 className="text-xs font-semibold text-slate-800 mb-2">{title}</h4>
      <ol className="list-decimal list-outside ml-4 space-y-1.5 text-xs text-slate-600">
        {steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
    </div>
  )
}

export function StatusPill({ row }: { row: SiemIntegrationRow }) {
  if (!row.enabled) {
    return <span className="text-slate-400">○ Disabled</span>
  }
  // Open source-health incidents outrank recency: a source can be "active"
  // and still be losing alerts or sending future-dated ones.
  const incidents = row.health?.openIncidents ?? []
  if (incidents.length) {
    const critical = incidents.includes('events_lost') || incidents.includes('pull_failing')
    const label = incidents.map((k) => HEALTH_KIND_SHORT[k] ?? k).join(', ')
    return (
      <span className={critical ? 'text-red-600' : 'text-amber-600'} title="Open source-health issues">
        ▲ {label}
      </span>
    )
  }
  if (row.transport === 'api_pull' && row.pullState?.lastError) {
    const kind = row.pullState.lastError.kind
    return (
      <span className="text-red-600" title={row.pullState.lastError.message}>
        ● {kind === 'auth' ? 'Credentials rejected' : kind === 'config' ? 'Needs attention' : 'Retrying'}
      </span>
    )
  }
  if (row.transport === 'api_pull' && row.pullState?.running) {
    return <span className="text-blue-600">● Polling…</span>
  }
  if (row.observedStatus === 'active') return <span className="text-green-600">● Active</span>
  if (row.observedStatus === 'idle') return <span className="text-amber-600">● Recent</span>
  if (row.transport === 'api_pull' && row.pullState?.lastSuccessAt) {
    return <span className="text-green-600">● Polling OK</span>
  }
  return <span className="text-slate-400">○ No data yet</span>
}

/** One-line summary of the most recent poll, for the table. */
export function PullSummary({ row }: { row: SiemIntegrationRow }) {
  const st = row.pullState
  if (!st) return null
  if (st.lastError) {
    return (
      <div className="text-[11px] text-red-600 mt-0.5 max-w-xs truncate" title={st.lastError.message}>
        {st.lastError.message}
      </div>
    )
  }
  if (st.lastRunAt && st.lastRun) {
    return (
      <div className="text-[11px] text-slate-400 mt-0.5">
        Last poll {formatRelativeTime(st.lastRunAt)}: {st.lastRun.queued} new
        {st.lastRun.duplicates ? `, ${st.lastRun.duplicates} seen` : ''}
      </div>
    )
  }
  return <div className="text-[11px] text-slate-400 mt-0.5">Waiting for first poll</div>
}
