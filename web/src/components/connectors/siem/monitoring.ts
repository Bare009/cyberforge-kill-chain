// Copied from AI-SOC web_app/frontend/src/components/settings/siem/monitoring.ts
export type SilenceMode = 'auto' | 'custom' | 'off'

export interface MonitoringValues {
  timeZone: string
  silenceMode: SilenceMode
  silenceMinutes: string
}

export function monitoringFromRow(
  timeZone: string | null | undefined,
  silenceMinutes: number | null | undefined
): MonitoringValues {
  return {
    timeZone: timeZone ?? '',
    silenceMode: silenceMinutes === 0 ? 'off' : silenceMinutes && silenceMinutes > 0 ? 'custom' : 'auto',
    silenceMinutes: silenceMinutes && silenceMinutes > 0 ? String(silenceMinutes) : '60',
  }
}

/** API value: -1 learned, 0 off, n minutes. Returns an error string when invalid. */
export function silenceToApi(v: MonitoringValues): { value: number; error: string | null } {
  if (v.silenceMode === 'off') return { value: 0, error: null }
  if (v.silenceMode === 'auto') return { value: -1, error: null }
  const n = Number(v.silenceMinutes)
  if (!Number.isInteger(n) || n < 5 || n > 10080) {
    return { value: -1, error: 'Silence threshold must be a whole number of minutes between 5 and 10080.' }
  }
  return { value: n, error: null }
}
