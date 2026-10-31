import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN'

export function getSeverityClasses(severity: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: 'bg-red-50 text-red-700 border border-red-200',
    HIGH: 'bg-orange-50 text-orange-700 border border-orange-200',
    MEDIUM: 'bg-amber-50 text-amber-700 border border-amber-200',
    LOW: 'bg-blue-50 text-blue-700 border border-blue-200',
    INFO: 'bg-slate-100 text-slate-600 border border-slate-200',
    UNKNOWN: 'bg-zinc-100 text-zinc-600 border border-zinc-300',
  }
  return map[severity] ?? map.UNKNOWN
}

export type AlertStatus = 'new' | 'in_review' | 'resolved' | 'false_positive' | 'escalated'

export function getStatusClasses(status: AlertStatus): string {
  const map: Record<AlertStatus, string> = {
    new: 'text-purple-700 bg-purple-50 border-purple-200',
    in_review: 'text-amber-700 bg-amber-50 border-amber-200',
    resolved: 'text-green-700 bg-green-50 border-green-200',
    false_positive: 'text-slate-600 bg-slate-100 border-slate-200',
    escalated: 'text-red-700 bg-red-50 border-red-200',
  }
  return map[status] ?? 'text-slate-600 bg-slate-100'
}

export function getStatusLabel(status: AlertStatus): string {
  const map: Record<AlertStatus, string> = {
    new: 'New',
    in_review: 'In Review',
    resolved: 'Resolved',
    false_positive: 'False Positive',
    escalated: 'Escalated',
  }
  return map[status] ?? status
}

/** Format minutes for MTTD / MTTR display */
export function formatMinutes(m: number | null | undefined): string {
  if (m == null || Number.isNaN(m)) return '—'
  return `${m}m`
}

const TZ_SUFFIX = /(?:Z|[+-]\d{2}:?\d{2})$/i

/**
 * The API's timestamps are UTC. If one arrives with no offset
 * ("2026-10-15T08:00:00"), the browser would read it as local time, which for an
 * IST analyst makes a new alert look 5h30 old. Mark such a string as UTC.
 */
export function asUtc(iso: string): string {
  return /T\d{2}:\d{2}/.test(iso) && !TZ_SUFFIX.test(iso) ? `${iso}Z` : iso
}

// Fixed locale and a 24-hour clock, so the format does not depend on the browser's
// language. The time zone is the viewer's: the one they picked on the dashboard
// (saved to their profile), else the browser's own. MainLayout sets it before
// anything renders, so every page shows times on the same clock.
let displayZone: string | undefined

function exactFormat(zone: string | undefined, withZone: boolean): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
    ...(withZone ? { timeZoneName: 'short' as const } : {}),
    ...(zone ? { timeZone: zone } : {}),
  })
}

let EXACT = exactFormat(undefined, false)
let EXACT_WITH_ZONE = exactFormat(undefined, true)

/** Show every timestamp in this IANA zone (undefined = the browser's). */
export function setDisplayTimeZone(zone: string | undefined): void {
  const next = zone || undefined
  if (next === displayZone) return
  try {
    EXACT = exactFormat(next, false)
    EXACT_WITH_ZONE = exactFormat(next, true)
    displayZone = next
  } catch {
    // An unknown zone: keep the previous formatters rather than break every page.
  }
}

/** The IANA zone timestamps are shown in. */
export function getDisplayTimeZone(): string {
  return displayZone ?? (Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
}

function toDate(iso: string | null | undefined): Date | null {
  if (!iso) return null
  const d = new Date(asUtc(iso))
  return Number.isNaN(d.getTime()) ? null : d
}

function partsOf(fmt: Intl.DateTimeFormat, d: Date): Record<string, string> {
  return Object.fromEntries(fmt.formatToParts(d).map((p) => [p.type, p.value]))
}

/** An event's time on the viewer's clock, split for a narrow table cell: "16 Oct" over "09:33:12". The year is added when it is not this year. */
export function exactTimeParts(iso: string | null | undefined): { date: string; time: string } | null {
  const d = toDate(iso)
  if (!d) return null
  const p = partsOf(EXACT, d)
  const sameYear = p.year === partsOf(EXACT, new Date()).year      // on the same clock
  return { date: sameYear ? `${p.day} ${p.month}` : `${p.day} ${p.month} ${p.year}`, time: `${p.hour}:${p.minute}:${p.second}` }
}

/** "16 Oct, 09:33:12" on the viewer's clock (year added when it is not this year). */
export function formatExactTime(iso: string | null | undefined): string {
  const t = exactTimeParts(iso)
  return t ? `${t.date}, ${t.time}` : '—'
}

/** "16 Oct 2026, 09:33:12 GMT+5:30": always the year and the viewer's time zone. For detail pages. */
export function formatFullTime(iso: string | null | undefined): string {
  const d = toDate(iso)
  if (!d) return '—'
  const p = partsOf(EXACT_WITH_ZONE, d)
  return `${p.day} ${p.month} ${p.year}, ${p.hour}:${p.minute}:${p.second} ${p.timeZoneName ?? ''}`.trim()
}

/** "2026-10-16 04:03:12 UTC": the same instant for anyone, whatever their zone. */
export function formatUtcTime(iso: string | null | undefined): string {
  const d = toDate(iso)
  return d ? `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC` : '—'
}

/** Hover text for an exact time: full local time, UTC, and how long ago. */
export function timeTooltip(iso: string | null | undefined): string | undefined {
  const d = toDate(iso)
  if (!d) return undefined
  return `${formatFullTime(iso)} · ${formatUtcTime(iso)} · ${formatRelativeTime(iso as string)}`
}

export function formatRelativeTime(dateStr: string): string {
  const date = new Date(asUtc(dateStr))
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)
  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} min ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString(undefined, displayZone ? { timeZone: displayZone } : undefined)
}
