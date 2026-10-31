import type { SeverityCounts, SeverityLabel } from '@/types/mitre'

/** Severity palette, matching Analytics and the threat-report PDFs. */
export const SEVERITY_COLOURS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  info: '#94a3b8',
  unknown: '#cbd5e1',
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const

/** Text colour for a severity badge label. */
export const SEVERITY_TEXT: Record<SeverityLabel, string> = {
  CRITICAL: 'text-red-700',
  HIGH: 'text-orange-700',
  MEDIUM: 'text-amber-700',
  LOW: 'text-blue-700',
  INFO: 'text-slate-500',
  UNKNOWN: 'text-slate-400',
}

/**
 * Cell shading.
 *
 * Volume is log-scaled: alert counts across ATT&CK are very skewed (one noisy
 * technique can outnumber the rest together), and a linear scale would leave
 * every other observed technique looking identical to an unobserved one.
 * The hue comes from the worst severity in the cell, so a single critical is
 * never lost behind a pile of informational alerts.
 */
export function cellStyle(alerts: number, maxSeverity: SeverityLabel | null, max: number): {
  background: string
  color: string
} {
  if (alerts <= 0) return { background: '#f8fafc', color: '#cbd5e1' }
  const intensity = Math.log1p(alerts) / Math.log1p(Math.max(max, 2))
  // 0.18-0.92 keeps the lightest cell clearly darker than an empty one and the
  // darkest short of pure black.
  const alpha = 0.18 + 0.74 * Math.min(1, Math.max(0, intensity))
  const base = SEVERITY_COLOURS[(maxSeverity ?? 'UNKNOWN').toLowerCase()] ?? SEVERITY_COLOURS.unknown
  return {
    background: withAlpha(base, alpha),
    // White text once the fill is dark enough to swallow slate.
    color: alpha > 0.6 ? '#ffffff' : '#0f172a',
  }
}

function withAlpha(hex: string, alpha: number): string {
  const n = parseInt(hex.slice(1), 16)
  const r = (n >> 16) & 255
  const g = (n >> 8) & 255
  const b = n & 255
  return `rgba(${r}, ${g}, ${b}, ${alpha.toFixed(3)})`
}

export function severitySummary(s: SeverityCounts): string {
  const parts = SEVERITY_ORDER.filter((k) => s[k] > 0).map((k) => `${s[k]} ${k}`)
  return parts.length ? parts.join(', ') : 'no alerts'
}

export function pct(part: number, whole: number): number {
  return whole > 0 ? Math.round((100 * part) / whole) : 0
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}
