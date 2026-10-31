import { Fragment, useMemo } from 'react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { MitreMatrix, TacticColumn, TechniqueCell } from '@/types/mitre'
import { cellStyle, fmtDateTime, severitySummary } from './heat'

interface Props {
  matrix: MitreMatrix
  /** Hide techniques with no alerts, so only what fired is shown. */
  onlyObserved: boolean
  selectedId: string | null
  onSelect: (techniqueId: string) => void
}

function CellButton({
  cell,
  max,
  selected,
  onSelect,
}: {
  cell: TechniqueCell
  max: number
  selected: boolean
  onSelect: (id: string) => void
}) {
  const style = cellStyle(cell.alerts, cell.maxSeverity, max)
  const label = cell.seen
    ? `${cell.id} ${cell.name}: ${cell.alerts} alert(s)`
    : `${cell.id} ${cell.name}: not observed`
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={() => onSelect(cell.id)}
          aria-label={label}
          aria-pressed={selected}
          className={cn(
            'w-full rounded border px-1.5 py-1 text-left text-[11px] leading-tight transition-shadow',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500',
            selected ? 'border-blue-600 ring-2 ring-blue-500' : 'border-slate-200 hover:border-slate-400',
            !cell.seen && 'text-slate-400'
          )}
          style={style}
        >
          <span className="flex items-start justify-between gap-1">
            <span className="line-clamp-2">{cell.name}</span>
            {cell.alerts > 0 && (
              <span className="shrink-0 font-mono font-semibold">{cell.alerts.toLocaleString()}</span>
            )}
          </span>
          {cell.subtechniquesSeen > 0 && (
            <span className="mt-0.5 block font-mono text-[9px] opacity-80">
              +{cell.subtechniquesSeen} sub
            </span>
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent side="right" className="max-w-xs">
        <div className="space-y-0.5">
          <div className="font-mono text-xs font-semibold">{cell.id}</div>
          <div className="text-xs">{cell.name}</div>
          {cell.seen ? (
            <>
              <div className="text-xs">
                {cell.alerts.toLocaleString()} alert(s) · {severitySummary(cell.severity)}
              </div>
              <div className="text-xs">
                {cell.openAlerts} open · {cell.correlatedAlerts} in incidents
              </div>
              <div className="text-xs">Last seen {fmtDateTime(cell.lastSeen)}</div>
              {cell.subtechniquesTotal > 0 && (
                <div className="text-xs">
                  {cell.subtechniquesSeen} of {cell.subtechniquesTotal} sub-techniques observed
                </div>
              )}
            </>
          ) : (
            <div className="text-xs">Not observed in this period.</div>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  )
}

function Column({
  tactic,
  cells,
  max,
  selectedId,
  onSelect,
}: {
  tactic: TacticColumn
  cells: TechniqueCell[]
  max: number
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <div className="w-[168px] shrink-0">
      <div className="sticky top-0 z-10 mb-1.5 rounded-t border-b-2 border-slate-300 bg-white px-1.5 pb-1.5 pt-1">
        <a
          href={tactic.url}
          target="_blank"
          rel="noreferrer noopener"
          className="block text-xs font-semibold text-slate-800 hover:text-blue-700 hover:underline"
          title={`${tactic.name} (${tactic.id}) on attack.mitre.org`}
        >
          {tactic.name}
        </a>
        <div className="font-mono text-[10px] text-slate-500">
          {tactic.techniquesSeen}/{tactic.techniquesTotal} seen
        </div>
      </div>
      <div className="space-y-1 px-1">
        {cells.length === 0 ? (
          <p className="px-0.5 py-2 text-[11px] text-slate-400">Nothing observed.</p>
        ) : (
          cells.map((c) => (
            <CellButton
              key={c.id}
              cell={c}
              max={max}
              selected={selectedId === c.id}
              onSelect={onSelect}
            />
          ))
        )}
      </div>
    </div>
  )
}

export function AttackMatrix({ matrix, onlyObserved, selectedId, onSelect }: Props) {
  const max = useMemo(
    () => Math.max(1, ...matrix.tactics.flatMap((t) => t.techniques.map((c) => c.alerts))),
    [matrix]
  )
  const columns = useMemo(
    () =>
      matrix.tactics.map((t) => ({
        tactic: t,
        cells: onlyObserved ? t.techniques.filter((c) => c.seen) : t.techniques,
      })),
    [matrix, onlyObserved]
  )

  return (
    <div className="overflow-x-auto pb-2">
      <div
        className="flex min-w-max items-start gap-0.5"
        role="group"
        aria-label="ATT&CK tactic by technique matrix"
      >
        {columns.map(({ tactic, cells }) => (
          <Fragment key={tactic.id}>
            <Column
              tactic={tactic}
              cells={cells}
              max={max}
              selectedId={selectedId}
              onSelect={onSelect}
            />
          </Fragment>
        ))}
      </div>
    </div>
  )
}
