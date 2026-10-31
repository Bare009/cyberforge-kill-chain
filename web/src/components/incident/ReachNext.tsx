import { ArrowRight, Compass } from 'lucide-react'
import { TacticChip } from '@/components/incident/badges'
import { cn } from '@/lib/utils'
import { inKillChainOrder } from '@/lib/killchain'
import type { GraphNode, Incident, Reachable } from '@/types/incident'

/** What each kind of access-graph edge means (docs/build-plan.md P8). */
const EDGE_LABEL: Record<string, string> = {
  controls: 'admin account controls the firewall',
  admin_port: 'allowed session on an admin port',
  allowed_flow: 'allowed internal session',
  zone_neighbour: 'same subnet (inferred)',
  logs_on: 'account logs on',
  admin_on: 'account is admin on',
  member_of: 'account is a member of',
}

function KindBadge({ kind }: { kind: Reachable['kind'] }) {
  return (
    <span
      className={cn(
        'rounded border px-1.5 py-0.5 text-[10px] font-medium',
        kind === 'observed' ? 'border-sky-200 bg-sky-50 text-sky-700' : 'border-dashed border-slate-300 bg-white text-slate-500'
      )}
      title={kind === 'observed' ? 'A connection was seen in the logs' : 'Not seen; inferred from the network layout'}
    >
      {kind}
    </span>
  )
}

interface Props {
  next: Incident['next']
  nodes: GraphNode[]
  onEntity: (value: string) => void
}

/** Reach next (FR-6): where the attacker can go from what they already control. */
export function ReachNext({ next, nodes, onEntity }: Props) {
  const label = (id: string) => nodes.find((n) => n.id === id)?.label ?? id
  const ordered = [...next.reachable].sort(
    (a, b) => a.hop - b.hop || (a.kind === b.kind ? 0 : a.kind === 'observed' ? -1 : 1)
  )

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-lg border border-slate-200 bg-white p-4">
        <Compass className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
        <p className="text-sm leading-relaxed text-slate-800">{next.sentence}</p>
      </div>

      {ordered.length === 0 ? (
        <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">
          No reachable host was found from this incident's footholds.
        </p>
      ) : (
        <ol className="space-y-2">
          {ordered.map((r, i) => (
            <li key={`${r.host}-${i}`} className="rounded-lg border border-slate-200 bg-white p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-slate-400">#{i + 1}</span>
                <button type="button" onClick={() => onEntity(r.host)} className="font-mono text-sm font-semibold text-blue-700 hover:underline">
                  {label(r.host)}
                </button>
                <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600">zone {r.zone}</span>
                <span className="text-[11px] text-slate-500">{r.hop === 1 ? '1 hop' : `${r.hop} hops`}</span>
                <KindBadge kind={r.kind} />
              </div>
              {r.via.length > 0 && (
                <ul className="mt-2 space-y-1 text-xs text-slate-600">
                  {r.via.map((v, j) => (
                    <li key={j} className="flex flex-wrap items-center gap-1.5">
                      <button type="button" onClick={() => onEntity(v.from)} className="font-mono text-slate-800 hover:underline">
                        {label(v.from)}
                      </button>
                      <ArrowRight className="h-3 w-3 text-slate-400" />
                      <span className="font-mono">{label(r.host)}</span>
                      <span className="text-slate-500">: {EDGE_LABEL[v.edge] ?? v.edge}</span>
                      {v.count > 0 && <span className="text-slate-500">({v.count.toLocaleString()} sessions)</span>}
                      {v.lines.length > 0 && (
                        <span className="text-slate-400">lines {v.lines.slice(0, 5).map((l) => l.line).join(', ')}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ol>
      )}

      {next.likely_tactics.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[11px] uppercase tracking-wider text-slate-500">
            Likely next tactics <span className="normal-case tracking-normal text-slate-400">(heuristic: the stages after the furthest one reached)</span>
          </p>
          <div className="flex flex-wrap gap-1">
            {inKillChainOrder(next.likely_tactics).map((t) => (
              <TacticChip key={t} tactic={t} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
