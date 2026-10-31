// Copied from AI-SOC web_app/frontend/src/components/settings/siem/MonitoringFields.tsx
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { TIME_ZONE_SUGGESTIONS } from './labels'
import type { MonitoringValues, SilenceMode } from './monitoring'

/** Time zone + silence-alert settings, shared by the add and edit dialogs. */
export function MonitoringFields({
  values,
  onChange,
  idPrefix,
}: {
  values: MonitoringValues
  onChange: (v: MonitoringValues) => void
  idPrefix: string
}) {
  const tzId = `${idPrefix}-tz`
  const modeId = `${idPrefix}-silence-mode`
  const minId = `${idPrefix}-silence-min`
  return (
    <fieldset className="space-y-3">
      <legend className="text-sm font-semibold text-slate-800 mb-1">Time &amp; monitoring</legend>
      <div>
        <label htmlFor={tzId} className="text-sm font-medium text-slate-700 block mb-1">
          Source time zone
        </label>
        <Input
          id={tzId}
          list={`${tzId}-options`}
          value={values.timeZone}
          onChange={(e) => onChange({ ...values, timeZone: e.target.value })}
          placeholder="UTC"
          className="font-mono text-xs"
          aria-describedby={`${tzId}-help`}
          autoComplete="off"
        />
        <datalist id={`${tzId}-options`}>
          {TIME_ZONE_SUGGESTIONS.map((z) => (
            <option key={z} value={z} />
          ))}
        </datalist>
        <p id={`${tzId}-help`} className="text-xs text-slate-500 mt-1">
          Used for timestamps the source writes without a zone (classic syslog, many log files).
          An IANA name such as <span className="font-mono">Asia/Kolkata</span> or an offset such as{' '}
          <span className="font-mono">+05:30</span>. Leave empty for UTC.
        </p>
      </div>
      <div>
        <label htmlFor={modeId} className="text-sm font-medium text-slate-700 block mb-1">
          Alert when the source goes silent
        </label>
        <Select
          value={values.silenceMode}
          onValueChange={(v) => onChange({ ...values, silenceMode: v as SilenceMode })}
        >
          <SelectTrigger id={modeId} aria-describedby={`${modeId}-help`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="auto">Automatically, from its normal alert rate</SelectItem>
            <SelectItem value="custom">After a fixed time without alerts</SelectItem>
            <SelectItem value="off">Never</SelectItem>
          </SelectContent>
        </Select>
        <p id={`${modeId}-help`} className="text-xs text-slate-500 mt-1">
          {values.silenceMode === 'auto'
            ? 'Learned from the last 7 days. Sources that alert rarely are not monitored automatically — a quiet EDR is not necessarily a broken one.'
            : values.silenceMode === 'off'
              ? 'No silence incidents for this connection. Other checks (clock skew, lost alerts) still run.'
              : 'An incident opens, and Admins/Engineers are emailed, when no alert arrives for this long.'}
        </p>
      </div>
      {values.silenceMode === 'custom' && (
        <div>
          <label htmlFor={minId} className="text-sm font-medium text-slate-700 block mb-1">
            Minutes without alerts
          </label>
          <Input
            id={minId}
            type="number"
            min={5}
            max={10080}
            value={values.silenceMinutes}
            onChange={(e) => onChange({ ...values, silenceMinutes: e.target.value })}
            className="w-40"
          />
        </div>
      )}
    </fieldset>
  )
}
