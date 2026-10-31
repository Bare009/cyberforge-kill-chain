// Copied from AI-SOC web_app/frontend/src/components/settings/siem/PullFields.tsx
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { PullConfigField, SiemPullSpec } from '@/types/connectors'
import { INTERVAL_OPTIONS, isCredentialVisible, isFieldVisible } from './labels'

function fieldId(prefix: string, key: string) {
  return `${prefix}-${key.replace(/[^A-Za-z0-9]+/g, '-')}`
}

function ConfigField({
  field,
  value,
  onChange,
  idPrefix,
}: {
  field: PullConfigField
  value: unknown
  onChange: (v: unknown) => void
  idPrefix: string
}) {
  const id = fieldId(idPrefix, field.key)
  const helpId = field.help ? `${id}-help` : undefined
  const label = (
    <label htmlFor={id} className="text-sm font-medium text-slate-700 block mb-1">
      {field.label}
      {field.required && !field.allow_empty && <span className="text-red-600" aria-hidden="true"> *</span>}
    </label>
  )
  const help = field.help ? (
    <p id={helpId} className="text-xs text-slate-500 mt-1">
      {field.help}
    </p>
  ) : null

  if (field.type === 'boolean') {
    return (
      <div>
        <div className="flex items-center gap-2">
          <Checkbox
            id={id}
            checked={Boolean(value)}
            onCheckedChange={(c) => onChange(c === true)}
            aria-describedby={helpId}
          />
          <label htmlFor={id} className="text-sm text-slate-700">
            {field.label}
          </label>
        </div>
        {help}
      </div>
    )
  }

  if (field.type === 'select') {
    return (
      <div>
        {label}
        <Select value={value == null ? '' : String(value)} onValueChange={(v) => onChange(v)}>
          <SelectTrigger id={id} aria-describedby={helpId}>
            <SelectValue placeholder="Select…" />
          </SelectTrigger>
          <SelectContent>
            {(field.options ?? []).map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {help}
      </div>
    )
  }

  if (field.type === 'json') {
    return (
      <div>
        {label}
        <Textarea
          id={id}
          value={value == null ? '' : String(value)}
          onChange={(e) => onChange(e.target.value)}
          className="font-mono text-xs min-h-[70px]"
          aria-describedby={helpId}
          spellCheck={false}
        />
        {help}
      </div>
    )
  }

  return (
    <div>
      {label}
      <Input
        id={id}
        type={field.type === 'number' ? 'number' : field.type === 'url' ? 'url' : 'text'}
        value={value == null ? '' : String(value)}
        onChange={(e) =>
          onChange(field.type === 'number' && e.target.value !== '' ? Number(e.target.value) : e.target.value)
        }
        placeholder={field.placeholder}
        className={field.type === 'url' ? 'font-mono text-xs' : undefined}
        aria-describedby={helpId}
        required={field.required && !field.allow_empty}
      />
      {help}
    </div>
  )
}

export function PullConfigFields({
  spec,
  values,
  onChange,
  intervalSeconds,
  onIntervalChange,
  idPrefix,
}: {
  spec: SiemPullSpec
  values: Record<string, unknown>
  onChange: (key: string, value: unknown) => void
  intervalSeconds: number
  onIntervalChange: (v: number) => void
  idPrefix: string
}) {
  const intervalId = `${idPrefix}-interval`
  const options = INTERVAL_OPTIONS.some((o) => o.value === intervalSeconds)
    ? INTERVAL_OPTIONS
    : [...INTERVAL_OPTIONS, { value: intervalSeconds, label: `Every ${intervalSeconds} s` }]
  return (
    <fieldset className="space-y-3">
      <legend className="text-sm font-semibold text-slate-800 mb-1">Connection</legend>
      {spec.configFields
        .filter((f) => isFieldVisible(f, values))
        .map((f) => (
          <ConfigField
            key={f.key}
            field={f}
            value={values[f.key]}
            onChange={(v) => onChange(f.key, v)}
            idPrefix={idPrefix}
          />
        ))}
      <div>
        <label htmlFor={intervalId} className="text-sm font-medium text-slate-700 block mb-1">
          Poll frequency
        </label>
        <Select value={String(intervalSeconds)} onValueChange={(v) => onIntervalChange(Number(v))}>
          <SelectTrigger id={intervalId}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o.value} value={String(o.value)}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </fieldset>
  )
}

export function PullCredentialFields({
  spec,
  config,
  values,
  onChange,
  idPrefix,
  editing,
  credentialHint,
}: {
  spec: SiemPullSpec
  config: Record<string, unknown>
  values: Record<string, string>
  onChange: (key: string, value: string) => void
  idPrefix: string
  editing: boolean
  credentialHint?: string | null
}) {
  const fields = spec.credentialFields.filter((f) => isCredentialVisible(f.key, spec.client, config))
  if (!fields.length) return null
  return (
    <fieldset className="space-y-3">
      <legend className="text-sm font-semibold text-slate-800 mb-1">Credentials</legend>
      <p className="text-xs text-slate-500">
        Stored encrypted and never shown again.
        {editing && ' Leave a field blank to keep its current value.'}
        {editing && credentialHint ? ` Current: ${credentialHint}.` : ''}
      </p>
      {fields.map((f) => {
        const id = fieldId(`${idPrefix}-cred`, f.key)
        const helpId = f.help ? `${id}-help` : undefined
        const required = !editing && (spec.client === 'generic_rest' || f.required)
        return (
          <div key={f.key}>
            <label htmlFor={id} className="text-sm font-medium text-slate-700 block mb-1">
              {f.label}
              {required && <span className="text-red-600" aria-hidden="true"> *</span>}
            </label>
            <Input
              id={id}
              type={f.secret ? 'password' : 'text'}
              autoComplete="off"
              value={values[f.key] ?? ''}
              onChange={(e) => onChange(f.key, e.target.value)}
              placeholder={editing ? '•••••• (unchanged)' : undefined}
              aria-describedby={helpId}
              className="font-mono text-xs"
            />
            {f.help && (
              <p id={helpId} className="text-xs text-slate-500 mt-1">
                {f.help}
              </p>
            )}
          </div>
        )
      })}
    </fieldset>
  )
}
