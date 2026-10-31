import { AlertCircle, ChevronLeft, ChevronRight, FileWarning } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useIncidentEvents } from '@/hooks/useIncidents'
import { apiErrorMessage } from '@/lib/api'
import { cn } from '@/lib/utils'
import { tacticColor } from '@/lib/killchain'
import type { Step } from '@/types/incident'

const PAGE = 50

interface Props {
  incidentNumber: number
  chain: Step[]
  step: number | null
  page: number
  onChange: (step: number | null, page: number) => void
}

/** The raw log lines behind each step, with their line numbers and byte offsets. */
export function EvidenceTab({ incidentNumber, chain, step, page, onChange }: Props) {
  const { data, isLoading, isError, error, isFetching } = useIncidentEvents(String(incidentNumber), step, page * PAGE, PAGE)
  const counts = new Map((data?.steps ?? []).map((s) => [s.step, s.lines]))
  const allLines = data?.steps.reduce((n, s) => n + s.lines, 0)
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE)) : 1
  const stepOf = new Map(chain.map((s) => [s.n, s]))

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Evidence for step">
        <Button size="sm" variant={step == null ? 'default' : 'outline'} onClick={() => onChange(null, 0)} aria-pressed={step == null}>
          All steps{allLines != null && ` (${allLines.toLocaleString()})`}
        </Button>
        {chain.map((s) => (
          <Button
            key={s.n}
            size="sm"
            variant={step === s.n ? 'default' : 'outline'}
            onClick={() => onChange(s.n, 0)}
            aria-pressed={step === s.n}
            title={s.action}
          >
            Step {s.n}
            {counts.has(s.n) && ` (${counts.get(s.n)!.toLocaleString()})`}
          </Button>
        ))}
      </div>

      {step != null && stepOf.get(step) && (
        <p className="text-sm text-slate-700">
          <span className="font-mono font-bold">Step {step}.</span> {stepOf.get(step)!.action}{' '}
          <span className="text-slate-500">({stepOf.get(step)!.line_total.toLocaleString()} lines in the run)</span>
        </p>
      )}

      {data && !data.raw_available && data.total > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <FileWarning className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            The raw log is not on the API server, so only line numbers and byte offsets are shown. Put the log in
            the raw folder (KILLCHAIN_RAW_DIR, default data/raw) to see each line.
          </span>
        </div>
      )}

      {isError ? (
        <div role="alert" className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-3 text-sm text-red-700">
          <AlertCircle className="h-4 w-4 shrink-0" /> Could not load the evidence: {apiErrorMessage(error)}
        </div>
      ) : isLoading || !data ? (
        <div className="space-y-1.5">
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      ) : data.total === 0 ? (
        <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">No evidence lines for this selection.</p>
      ) : (
        <div className={cn('overflow-x-auto rounded-lg border border-slate-200 bg-white', isFetching && 'opacity-70')}>
          <table className="w-full text-xs">
            <thead className="bg-slate-50 text-left text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-2 py-1.5 font-medium">Step</th>
                <th className="px-2 py-1.5 font-medium">Line</th>
                <th className="px-2 py-1.5 font-medium">Time (IST)</th>
                <th className="px-2 py-1.5 font-medium">Technique</th>
                <th className="px-2 py-1.5 font-medium">Log line</th>
              </tr>
            </thead>
            <tbody>
              {data.lines.map((ln) => (
                <tr key={`${ln.source}:${ln.line}`} className="border-t border-slate-100 align-top">
                  <td className="px-2 py-1.5">
                    {ln.step != null && (
                      <span
                        className="inline-flex h-5 w-5 items-center justify-center rounded-full font-mono text-[10px] font-bold text-white"
                        style={{ background: tacticColor(stepOf.get(ln.step)?.tactic) }}
                      >
                        {ln.step}
                      </span>
                    )}
                  </td>
                  {/* Plain digits, so a line number or offset can be copied and searched for as is. */}
                  <td className="whitespace-nowrap px-2 py-1.5 font-mono text-slate-700" title={`${ln.source}, byte ${ln.byte_offset}`}>
                    {ln.line}
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 font-mono text-slate-600">{ln.ts_ist ?? '—'}</td>
                  <td className="whitespace-nowrap px-2 py-1.5 font-mono text-red-600">{ln.technique ?? '—'}</td>
                  <td className="px-2 py-1.5 font-mono text-[11px] leading-snug text-slate-800 break-all">
                    {ln.raw ?? <span className="text-slate-400">{ln.source} @ byte {ln.byte_offset}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > PAGE && (
        <div className="flex items-center justify-between text-xs text-slate-500">
          <span>
            Lines {(data.offset + 1).toLocaleString()} to {(data.offset + data.lines.length).toLocaleString()} of{' '}
            {data.total.toLocaleString()}
          </span>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => onChange(step, page - 1)} aria-label="Previous page">
              <ChevronLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="px-1">
              Page {page + 1} of {pages}
            </span>
            <Button size="sm" variant="outline" disabled={page + 1 >= pages} onClick={() => onChange(step, page + 1)} aria-label="Next page">
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
      {data && <p className="text-[11px] text-slate-400">Source: {data.origin}. Line numbers are 1-based, byte offsets 0-based, as in the organisers' manifest.</p>}
    </div>
  )
}
