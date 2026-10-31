import { cn } from '@/lib/utils'
import type { Severity } from '@/lib/utils'

/** OCSF `severity_id` (0–5) for tables and compact rows. */
export function SeverityIdDisplay({
  severityId,
  className,
}: {
  severityId: number | null | undefined
  className?: string
}) {
  return (
    <span
      className={cn('font-mono text-xs tabular-nums text-slate-800', className)}
      title="OCSF severity_id (0=Unknown … 5=Critical)"
    >
      {severityId ?? '—'}
    </span>
  )
}

interface SeverityBadgeProps {
  severity: Severity
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-2 py-0.5 text-xs font-mono font-medium',
        severity === 'CRITICAL' && 'bg-red-50 text-red-700 border-red-200',
        severity === 'HIGH' && 'bg-orange-50 text-orange-700 border-orange-200',
        severity === 'MEDIUM' && 'bg-amber-50 text-amber-700 border-amber-200',
        severity === 'LOW' && 'bg-blue-50 text-blue-700 border-blue-200',
        severity === 'INFO' && 'bg-slate-100 text-slate-600 border-slate-200',
        severity === 'UNKNOWN' && 'bg-zinc-100 text-zinc-600 border-zinc-300',
        className
      )}
    >
      {severity}
    </span>
  )
}
