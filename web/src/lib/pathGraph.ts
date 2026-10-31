/**
 * Layout for the attack path graph (FR-5): a fixed left-to-right layout so the
 * story reads in order. Pure functions, so they are unit tested; the canvas
 * drawing lives in components/path/AttackPathGraph.tsx.
 *
 * Columns: the source of step 1 is column 0, each step's target sits one
 * column to the right of its source (unless it was already placed), and
 * reach-next nodes sit one column right of the node they are reached from.
 */
import { tacticColor } from '@/lib/killchain'
import type { GraphEdge, GraphNode, NodeKind, Step } from '@/types/incident'

export const COLUMN_GAP = 230
export const ROW_GAP = 95

/** Node colours, from AI-SOC's ENTITY_COLORS (IP cyan, user violet, asset green, domain amber), attacker in rose. */
export const NODE_KIND_COLOR: Record<NodeKind, string> = {
  external_ip: '#f43f5e',
  internal_host: '#22d3ee',
  server: '#34d399',
  firewall: '#f97316',
  account: '#a78bfa',
  domain: '#fbbf24',
}

export const NODE_KIND_LABEL: Record<NodeKind, string> = {
  external_ip: 'External IP',
  internal_host: 'Internal host',
  server: 'Server',
  firewall: 'Firewall management',
  account: 'Account',
  domain: 'Domain',
}

export const REACH_COLOR = { observed: '#0284c7', inferred: '#94a3b8' } as const

export interface PathNode extends GraphNode {
  column: number
  row: number
  /** Fixed position: react-force-graph keeps nodes with fx/fy where they are. */
  fx: number
  fy: number
  color: string
  radius: number
  /** Step numbers that touch this node. */
  steps: number[]
}

export interface PathLink {
  source: string
  target: string
  step: number | null
  technique: string | null
  tactic: string | null
  label: string
  kind: GraphEdge['kind']
  curvature: number
  color: string
  dashed: boolean
  /** The step's action sentence, for the tooltip. */
  action?: string
}

export interface PathLayout {
  nodes: PathNode[]
  links: PathLink[]
  columns: number
  steps: number[]
}

export function nodeRadius(importance: number): number {
  return 7 + Math.max(0, Math.min(1, importance)) * 7
}

export function layoutPathGraph(graph: { nodes: GraphNode[]; edges: GraphEdge[] }, chain: Step[] = []): PathLayout {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]))
  const column = new Map<string, number>()
  const order: string[] = []
  const place = (id: string, col: number) => {
    if (!byId.has(id) || column.has(id)) return
    column.set(id, col)
    order.push(id)
  }

  const stepEdges = graph.edges.filter((e) => e.kind === 'step').sort((a, b) => (a.step ?? 0) - (b.step ?? 0))
  for (const e of stepEdges) {
    place(e.source, 0)
    place(e.target, (column.get(e.source) ?? 0) + 1)
  }
  // reach edges may chain (hop 2 from hop 1), so repeat until nothing new is placed
  const reachEdges = graph.edges.filter((e) => e.kind !== 'step')
  for (let pass = 0; pass < 3; pass++) {
    for (const e of reachEdges) {
      if (column.has(e.source)) place(e.target, (column.get(e.source) ?? 0) + 1)
    }
  }
  const maxCol = Math.max(-1, ...column.values())
  for (const n of graph.nodes) place(n.id, maxCol + 1)       // anything left over goes in a last column

  const perColumn = new Map<number, string[]>()
  for (const id of order) {
    const c = column.get(id)!
    perColumn.set(c, [...(perColumn.get(c) ?? []), id])
  }

  const stepsOf = new Map<string, number[]>()
  for (const e of stepEdges) {
    if (e.step == null) continue
    for (const id of [e.source, e.target]) stepsOf.set(id, [...new Set([...(stepsOf.get(id) ?? []), e.step])])
  }

  const nodes: PathNode[] = order.map((id) => {
    const n = byId.get(id)!
    const c = column.get(id)!
    const ids = perColumn.get(c)!
    const row = ids.indexOf(id)
    return {
      ...n,
      column: c,
      row,
      fx: c * COLUMN_GAP,
      fy: (row - (ids.length - 1) / 2) * ROW_GAP,
      color: n.reach ? REACH_COLOR[n.reach] : NODE_KIND_COLOR[n.kind] ?? '#64748b',
      radius: nodeRadius(n.importance),
      steps: stepsOf.get(id) ?? [],
    }
  })

  // Parallel edges between the same two nodes fan out so each label stays readable.
  const actionOf = new Map(chain.map((s) => [s.n, s.action]))
  const groups = new Map<string, GraphEdge[]>()
  const edges = graph.edges.filter((e) => byId.has(e.source) && byId.has(e.target))
  for (const e of edges) {
    const key = [e.source, e.target].sort().join('|')
    groups.set(key, [...(groups.get(key) ?? []), e])
  }
  const links: PathLink[] = edges.map((e) => {
    const key = [e.source, e.target].sort().join('|')
    const group = groups.get(key)!
    const i = group.indexOf(e)
    let curvature = group.length === 1 ? 0 : (i - (group.length - 1) / 2) * 0.35
    if (e.source > e.target) curvature = -curvature              // same side whichever way the edge points
    const reach = e.kind !== 'step'
    return {
      source: e.source,
      target: e.target,
      step: e.step,
      technique: e.technique,
      tactic: e.tactic,
      label: e.label,
      kind: e.kind,
      curvature,
      color: reach ? REACH_COLOR[e.kind === 'reach_observed' ? 'observed' : 'inferred'] : tacticColor(e.tactic),
      dashed: reach,
      action: e.step != null ? actionOf.get(e.step) : undefined,
    }
  })

  return {
    nodes,
    links,
    columns: Math.max(0, ...nodes.map((n) => n.column)) + 1,
    steps: [...new Set(stepEdges.map((e) => e.step).filter((s): s is number => s != null))].sort((a, b) => a - b),
  }
}

/**
 * Where to draw a link's label: the middle of the curve. Matches force-graph's
 * quadratic curve, whose control point is `curvature × length` off the
 * midpoint, perpendicular to the link; the curve's middle is half way there.
 */
export function labelPoint(sx: number, sy: number, tx: number, ty: number, curvature: number): { x: number; y: number } {
  const mx = (sx + tx) / 2
  const my = (sy + ty) / 2
  if (!curvature) return { x: mx, y: my }
  const len = Math.hypot(tx - sx, ty - sy)
  const angle = Math.atan2(ty - sy, tx - sx)
  const d = (len * curvature) / 2
  return { x: mx + d * Math.cos(angle - Math.PI / 2), y: my + d * Math.sin(angle - Math.PI / 2) }
}

/** Is a link drawn at full strength while the play-through shows `upTo` steps? null shows everything. */
export function linkVisible(link: Pick<PathLink, 'step'>, upTo: number | null): boolean {
  if (upTo == null) return true
  return link.step != null && link.step <= upTo
}
