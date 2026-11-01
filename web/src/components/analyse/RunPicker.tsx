import { Loader2 } from 'lucide-react'
import { useRuns, useSelectRun } from '@/hooks/useJobs'
import { apiErrorMessage } from '@/lib/api'
import { formatBytes } from '@/lib/format'
import { useAppStore } from '@/store/useAppStore'

/** Which analysed run every page shows (POST /runs/select). */
export function RunPicker() {
  const runs = useRuns()
  const select = useSelectRun()
  const notify = useAppStore((s) => s.addNotification)
  const rows = runs.data?.runs ?? []
  // nothing loaded (--run none): no run list either, so the Dashboard is clean before the first upload
  if (rows.length < 2 || !rows.some((r) => r.active)) return null
  const active = rows.find((r) => r.active)?.name ?? runs.data?.active ?? ''
  return (
    <label className="flex items-center gap-2 text-xs text-slate-600">
      {select.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-600" />}
      Showing run
      <select
        aria-label="Run shown"
        className="h-8 rounded-md border border-slate-200 bg-white px-2 text-xs text-slate-800"
        value={active}
        disabled={select.isPending}
        onChange={(e) =>
          select.mutate(e.target.value, {
            onSuccess: (d) => notify({ type: 'success', message: `Now showing run ${d.active}`, duration: 4000 }),
            onError: (err) => notify({ type: 'error', message: apiErrorMessage(err, 'Could not switch runs') }),
          })
        }
      >
        {rows.map((r) => (
          <option key={r.name} value={r.name}>
            {r.name}
            {r.incidents != null ? ` · ${r.incidents} incidents` : ''}
            {r.input_bytes ? ` · ${formatBytes(r.input_bytes)}` : ''}
            {r.sample ? ' · sample' : ''}
          </option>
        ))}
      </select>
    </label>
  )
}
