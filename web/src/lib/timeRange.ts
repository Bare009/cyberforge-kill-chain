/**
 * The dashboard's time range and time zone (AISIM-0008).
 *
 * Mirrors web_app/backend/app/services/time_window.py: a range is a preset
 * relative to now, or an absolute start and end (ISO instants), and it is read in
 * a time zone (an IANA name). The server resolves it and returns the exact window
 * it counted, which drill-down links pass on, so a list opened from a card counts
 * the same alerts.
 */

export type RangePreset =
  | 'last_15m' | 'last_1h' | 'last_4h' | 'last_12h' | 'last_24h'
  | 'today' | 'yesterday' | 'last_7d' | 'last_14d' | 'last_30d' | 'last_90d'

/** A preset, or an absolute range as ISO 8601 instants. */
export interface TimeRange {
  preset?: RangePreset | null
  start?: string | null
  end?: string | null
}

/** Relative ranges end now; calendar ranges start at local midnight in the chosen zone. */
export const RANGE_PRESETS: { value: RangePreset; label: string; kind: 'relative' | 'calendar' }[] = [
  { value: 'last_15m', label: 'Last 15 minutes', kind: 'relative' },
  { value: 'last_1h', label: 'Last 1 hour', kind: 'relative' },
  { value: 'last_4h', label: 'Last 4 hours', kind: 'relative' },
  { value: 'last_12h', label: 'Last 12 hours', kind: 'relative' },
  { value: 'last_24h', label: 'Last 24 hours', kind: 'relative' },
  { value: 'today', label: 'Today', kind: 'calendar' },
  { value: 'yesterday', label: 'Yesterday', kind: 'calendar' },
  { value: 'last_7d', label: 'Last 7 days', kind: 'calendar' },
  { value: 'last_14d', label: 'Last 14 days', kind: 'calendar' },
  { value: 'last_30d', label: 'Last 30 days', kind: 'calendar' },
  { value: 'last_90d', label: 'Last 90 days', kind: 'calendar' },
]
export const DEFAULT_PRESET: RangePreset = 'last_14d'
export const MAX_RANGE_DAYS = 90

/** Preference value meaning "whatever zone this computer is set to". */
export const BROWSER_ZONE = 'browser'

/** Seconds; 0 = off. Must match REFRESH_CHOICES in web_app/backend/app/routes/preferences.py. */
export const REFRESH_OPTIONS: { value: number; label: string }[] = [
  { value: 0, label: 'Off' },
  { value: 15, label: 'Every 15 s' },
  { value: 30, label: 'Every 30 s' },
  { value: 60, label: 'Every 1 min' },
  { value: 300, label: 'Every 5 min' },
  { value: 900, label: 'Every 15 min' },
]

export const COMMON_ZONES = [
  'UTC', 'Asia/Kolkata', 'Asia/Dubai', 'Asia/Singapore', 'Asia/Tokyo', 'Europe/London',
  'Europe/Berlin', 'America/New_York', 'America/Chicago', 'America/Los_Angeles', 'Australia/Sydney',
]

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function pad(n: number): string {
  return String(n).padStart(2, '0')
}

export function presetLabel(preset: string | null | undefined): string {
  return RANGE_PRESETS.find((p) => p.value === preset)?.label ?? 'Custom range'
}

export function isPreset(value: unknown): value is RangePreset {
  return RANGE_PRESETS.some((p) => p.value === value)
}

// ── zones ────────────────────────────────────────────────────────────────────

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

export function isValidTimeZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone })
    return true
  } catch {
    return false
  }
}

/** The IANA zone a preference stands for ('browser' = this computer's zone). */
export function resolveTimeZone(pref: string | null | undefined): string {
  if (!pref || pref === BROWSER_ZONE) return browserTimeZone()
  return isValidTimeZone(pref) ? pref : browserTimeZone()
}

/** Every zone this browser knows, UTC first. */
export function listTimeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
  let zones: string[] = []
  try {
    zones = intl.supportedValuesOf?.('timeZone') ?? []
  } catch {
    zones = []
  }
  return Array.from(new Set(['UTC', ...(zones.length ? zones : COMMON_ZONES)]))
}

const partFormatters = new Map<string, Intl.DateTimeFormat>()

function partFormatter(zone: string): Intl.DateTimeFormat {
  let f = partFormatters.get(zone)
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
    partFormatters.set(zone, f)
  }
  return f
}

interface WallClock { year: number; month: number; day: number; hour: number; minute: number; second: number }

/** What a clock in `zone` shows at instant `ms`. */
export function wallClock(ms: number, zone: string): WallClock {
  const p: Record<string, string> = {}
  for (const part of partFormatter(zone).formatToParts(new Date(ms))) p[part.type] = part.value
  return {
    year: Number(p.year), month: Number(p.month), day: Number(p.day),
    hour: Number(p.hour) % 24, minute: Number(p.minute), second: Number(p.second),
  }
}

/** Minutes `zone` is ahead of UTC at instant `ms` (IST: 330). */
export function zoneOffsetMinutes(zone: string, ms: number): number {
  const c = wallClock(ms, zone)
  const asUtc = Date.UTC(c.year, c.month - 1, c.day, c.hour, c.minute, c.second)
  return Math.round((asUtc - Math.floor(ms / 1000) * 1000) / 60000)
}

/** 'UTC+05:30'. */
export function utcOffsetLabel(zone: string, ms: number = Date.now()): string {
  const m = zoneOffsetMinutes(zone, ms)
  const a = Math.abs(m)
  return `UTC${m < 0 ? '-' : '+'}${pad(Math.floor(a / 60))}:${pad(a % 60)}`
}

/** '2026-10-16T09:30' on the zone's clock, for an <input type="datetime-local">. */
export function toWallTime(iso: string | null | undefined, zone: string): string {
  if (!iso) return ''
  const ms = Date.parse(iso)
  if (Number.isNaN(ms)) return ''
  const c = wallClock(ms, zone)
  return `${c.year}-${pad(c.month)}-${pad(c.day)}T${pad(c.hour)}:${pad(c.minute)}`
}

/** The instant (ISO, UTC) that a wall-clock time typed for `zone` denotes. */
export function fromWallTime(wall: string, zone: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(wall.trim())
  if (!m) return null
  const guess = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0))
  if (Number.isNaN(guess)) return null
  // Near a DST change the offset at the guess and at the answer can differ, so
  // keep the candidate whose own offset agrees with the one used to find it.
  const off1 = zoneOffsetMinutes(zone, guess)
  const t1 = guess - off1 * 60000
  const off2 = zoneOffsetMinutes(zone, t1)
  if (off2 === off1) return new Date(t1).toISOString()
  const t2 = guess - off2 * 60000
  if (zoneOffsetMinutes(zone, t2) === off2) return new Date(t2).toISOString()
  // Neither: the time falls in the hour a spring-forward skips. Move it forward,
  // as the browser and Python's zoneinfo do (02:30 becomes 03:30).
  return new Date(Math.max(t1, t2)).toISOString()
}

/** '16 Oct 2026, 09:30' (or with seconds) on the zone's clock. */
export function formatInZone(
  iso: string | null | undefined,
  zone: string,
  opts: { year?: boolean; seconds?: boolean } = {}
): string {
  if (!iso) return '—'
  const ms = Date.parse(iso)
  if (Number.isNaN(ms)) return '—'
  const c = wallClock(ms, zone)
  const year = opts.year === false ? '' : ` ${c.year}`
  const secs = opts.seconds ? `:${pad(c.second)}` : ''
  return `${c.day} ${MONTHS[c.month - 1]}${year}, ${pad(c.hour)}:${pad(c.minute)}${secs}`
}

/** '16 Oct 09:30 → 17 Oct 09:30', with the year only when it is not this year. */
export function describeWindow(startIso: string, endIso: string, zone: string): string {
  const thisYear = wallClock(Date.now(), zone).year
  const showYear = [startIso, endIso].some((iso) => wallClock(Date.parse(iso), zone).year !== thisYear)
  return `${formatInZone(startIso, zone, { year: showYear })} → ${formatInZone(endIso, zone, { year: showYear })}`
}

// ── ranges ───────────────────────────────────────────────────────────────────

export function isCustomRange(range: TimeRange | null | undefined): boolean {
  return !!(range?.start && range?.end)
}

/** Query parameters for GET /dashboard/summary. */
export function rangeParams(range: TimeRange, zone: string): Record<string, string> {
  if (range.start && range.end) return { start: range.start, end: range.end, tz: zone }
  return { preset: isPreset(range.preset) ? range.preset : DEFAULT_PRESET, tz: zone }
}

/** Why a custom range cannot be used, or null if it can. */
export function customRangeError(startIso: string | null, endIso: string | null): string | null {
  if (!startIso || !endIso) return 'Pick both a start and an end.'
  const s = Date.parse(startIso)
  const e = Date.parse(endIso)
  if (!(e > s)) return 'The end must be after the start.'
  if (e - s > MAX_RANGE_DAYS * 86_400_000) return `The range can be at most ${MAX_RANGE_DAYS} days.`
  return null
}
