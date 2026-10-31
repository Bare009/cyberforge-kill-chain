/**
 * Layout for the attack path graph (FR-5): a fixed left-to-right layout so the
 * story reads in order. Pure functions, so they are unit tested; the canvas
 * drawing lives in components/path/AttackPathGraph.tsx.
 *
 * Columns: the source of step 1 is column 0, each step's target sits one
 * column to the right of its source (unless it was already placed), and
 * reach-next nodes sit one column right of the node they are reached from.
 *
 * To keep busy incidents readable:
 * - parallel step edges between the same two nodes are drawn as a tight bundle
 *   with one label card listing the steps (`card` on the first link of the bundle);
 * - edges of supporting anomalies are left out unless `showSupporting`;
 * - each node's reach-next targets are cut to the first `reachLimit` (they come
 *   ranked) plus one "+N more" node; `reachLimit: null` shows all, 0 none.
 */
import { tacticColor } from '@/lib/killchain'
import type { GraphEdge, GraphNode, NodeKind, Step } from '@/types/incident'

export const COLUMN_GAP = 340
export const ROW_GAP = 80
export const BUNDLE_SPREAD = 0.06
export const DEFAULT_REACH_LIMIT = 3
export const MORE_PREFIX = '__more__:'
/** Step-card font size in graph units; the layout leaves room for cards of this size. */
export const CARD_FONT = 10.5
const CARD_MARGIN = 16

/** Height of a step card with `lines` lines, in graph units (matches drawLinkLabel). */
export function cardHeight(lines: number): number {
  if (lines <= 0) return 0
  const lineH = CARD_FONT * 1.55
  return CARD_FONT * 1.2 + lineH * lines - (lineH - CARD_FONT)
}

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
  /** A "+N more" node standing for reach-next targets that are not drawn. */
  more?: { count: number; from: string }
}

/** One line of a bundle's label card. */
export interface CardLine {
  step: number | null
  text: string
  color: string
  supporting: boolean
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
  supporting: boolean
  /** The step's action sentence, for the tooltip. */
  action?: string
  /** Set on the first link of each step bundle: the label card drawn for the whole bundle. */
  card?: CardLine[]
  /** Where the card sits along the edge, 0 = source, 1 = target (default 0.5). */
  cardAt?: number
}

export interface PathLayout {
  nodes: PathNode[]
  links: PathLink[]
  columns: number
  /** Most nodes stacked in one column (sets the canvas height). */
  maxRows: number
  steps: number[]
  /** Reach-next targets left out of the drawing (shown as "+N more"). */
  hiddenReach: number
  /** Supporting-anomaly edges left out of the drawing. */
  hiddenSupporting: number
}

export interface LayoutOptions {
  showSupporting?: boolean
  /** Reach-next targets drawn per node; null = all, 0 = none. */
  reachLimit?: number | null
}

export function nodeRadius(importance: number): number {
  return 7 + Math.max(0, Math.min(1, importance)) * 7
}

/** "2. web sqli x60" -> "web sqli x60" (the card shows the step number in its own badge). */
function stripNumber(label: string): string {
  return label.replace(/^\s*\d+\.\s*/, '')
}

/** The reach part of the graph after the per-node limit: edges kept, nodes kept, "+N more" nodes. */
function limitReach(graph: { nodes: GraphNode[]; edges: GraphEdge[] }, limit: number | null) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]))
  const reachEdges = graph.edges.filter((e) => e.kind !== 'step')
  if (limit == null) return { edges: reachEdges, more: [] as PathNode[], hidden: 0, drop: new Set<string>() }
  if (limit <= 0) {
    const drop = new Set(reachEdges.map((e) => e.target).filter((t) => byId.get(t)?.reach))
    return { edges: [] as GraphEdge[], more: [] as PathNode[], hidden: drop.size, drop }
  }
  // Each source adds at most `limit` new targets (they come ranked), and each
  // target keeps one incoming edge, from the first source that drew it; the
  // other routes are on the Reach next tab and in "All".
  const bySource = new Map<string, GraphEdge[]>()
  for (const e of reachEdges) bySource.set(e.source, [...(bySource.get(e.source) ?? []), e])
  let kept: GraphEdge[] = []
  const drawn = new Set<string>()
  for (const es of bySource.values()) {
    let added = 0
    for (const e of es) {
      if (drawn.has(e.target)) continue
      if (added < limit) {
        kept.push(e)
        drawn.add(e.target)
        added += 1
      }
    }
  }
  // A hop-2 target reached only from a dropped hop-1 node goes too; repeat until nothing changes.
  let drop = new Set<string>()
  for (;;) {
    const keptTargets = new Set(kept.filter((e) => !drop.has(e.source)).map((e) => e.target))
    const next = new Set(reachEdges.map((e) => e.target).filter((t) => !keptTargets.has(t) && byId.get(t)?.reach))
    if (next.size === drop.size) break
    drop = next
  }
  kept = kept.filter((e) => !drop.has(e.source))
  // "+N more" per drawn source: the hidden targets it reaches, each counted once over all sources
  const more: { from: string; count: number; kind: 'observed' | 'inferred' }[] = []
  const counted = new Set<string>()
  for (const [from, es] of bySource) {
    if (drop.has(from)) continue
    const rest = es.filter((e) => drop.has(e.target) && !counted.has(e.target))
    const targets = new Set(rest.map((e) => e.target))
    targets.forEach((t) => counted.add(t))
    if (targets.size) {
      const inferred = [...targets].every((t) => byId.get(t)?.reach === 'inferred')
      more.push({ from, count: targets.size, kind: inferred ? 'inferred' : 'observed' })
    }
  }
  const moreNodes: PathNode[] = more.map((m) => ({
    id: `${MORE_PREFIX}${m.from}`, label: `+${m.count} more`, kind: 'server', zone: 'unknown', importance: 0,
    reach: m.kind, column: 0, row: 0, fx: 0, fy: 0, color: REACH_COLOR[m.kind], radius: 9, steps: [],
    more: { count: m.count, from: m.from },
  }))
  return { edges: kept, more: moreNodes, hidden: drop.size, drop }
}

export function layoutPathGraph(graph: { nodes: GraphNode[]; edges: GraphEdge[] }, chain: Step[] = [],
                                options: LayoutOptions = {}): PathLayout {
  const showSupporting = options.showSupporting ?? false
  const reachLimit = options.reachLimit === undefined ? DEFAULT_REACH_LIMIT : options.reachLimit

  const reach = limitReach(graph, reachLimit)
  const allSteps = graph.edges.filter((e) => e.kind === 'step')
  const hiddenSupporting = showSupporting ? 0 : allSteps.filter((e) => e.supporting).length
  const stepEdges = allSteps.filter((e) => showSupporting || !e.supporting)
    .sort((a, b) => (a.step ?? 0) - (b.step ?? 0) || Number(!!a.supporting) - Number(!!b.supporting))
  const moreEdges: GraphEdge[] = reach.more.map((m) => ({
    source: m.more!.from, target: m.id, step: null, technique: null, tactic: null,
    label: `${m.more!.count} more reachable (${m.reach})`, kind: m.reach === 'observed' ? 'reach_observed' : 'reach_inferred',
  }))
  const allReachEdges = [...reach.edges, ...moreEdges]

  // A node only a hidden supporting anomaly touches is hidden with it, and so
  // is what it reaches next: otherwise it would float unconnected with its fan.
  const stepNodes = new Set(stepEdges.flatMap((e) => [e.source, e.target]))
  const onlyHidden = new Set(allSteps.filter((e) => e.supporting && !showSupporting)
    .flatMap((e) => [e.source, e.target]).filter((id) => !stepNodes.has(id)))
  const isReachNode = new Set([...graph.nodes.filter((n) => n.reach).map((n) => n.id), ...reach.more.map((m) => m.id)])
  const live = new Set(graph.nodes.filter((n) => !n.reach && !onlyHidden.has(n.id)).map((n) => n.id))
  for (let grew = true; grew;) {
    grew = false
    for (const e of allReachEdges) {
      if (live.has(e.source) && !live.has(e.target) && isReachNode.has(e.target) && !reach.drop.has(e.target)) {
        live.add(e.target)
        grew = true
      }
    }
  }
  const reachEdges = allReachEdges.filter((e) => live.has(e.source) && live.has(e.target))
  const baseNodes = graph.nodes.filter((n) => live.has(n.id))
  const byId = new Map<string, GraphNode | PathNode>(baseNodes.map((n) => [n.id, n]))
  for (const m of reach.more) if (live.has(m.id)) byId.set(m.id, m)

  const column = new Map<string, number>()
  const order: string[] = []
  const place = (id: string, col: number) => {
    if (!byId.has(id) || column.has(id)) return
    column.set(id, col)
    order.push(id)
  }
  const parent = new Map<string, string>()
  for (const e of stepEdges) {
    place(e.source, 0)
    if (byId.has(e.target) && !column.has(e.target)) parent.set(e.target, e.source)
    place(e.target, (column.get(e.source) ?? 0) + 1)
  }
  // reach edges may chain (hop 2 from hop 1), so repeat until nothing new is placed
  const placeReach = () => {
    for (let grew = true; grew;) {
      grew = false
      for (const e of reachEdges) {
        if (column.has(e.source) && !column.has(e.target) && byId.has(e.target)) {
          parent.set(e.target, e.source)
          place(e.target, column.get(e.source)! + 1)
          grew = true
        }
      }
    }
  }
  placeReach()
  // nodes in no step (isolated, or reach sources only), then what they reach, go further right
  const maxCol = Math.max(-1, ...column.values())
  for (const n of baseNodes) if (!n.reach) place(n.id, maxCol + 1)
  placeReach()
  for (const id of byId.keys()) place(id, maxCol + 1)

  // Within a column, children follow the order of their parents (fewer crossings),
  // and a parent's "+N more" comes right after its drawn children.
  const perColumn = new Map<number, string[]>()
  for (const id of order) {
    const c = column.get(id)!
    perColumn.set(c, [...(perColumn.get(c) ?? []), id])
  }
  const rowOf = new Map<string, number>()
  for (const c of [...perColumn.keys()].sort((a, b) => a - b)) {
    const ids = perColumn.get(c)!
    const key = (id: string) => {
      const p = parent.get(id)
      return [p != null && rowOf.has(p) ? column.get(p)! : -1, p != null ? rowOf.get(p) ?? -1 : -1,
              id.startsWith(MORE_PREFIX) ? 1 : 0, order.indexOf(id)]
    }
    ids.sort((a, b) => {
      const ka = key(a)
      const kb = key(b)
      for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i]
      return 0
    })
    ids.forEach((id, i) => rowOf.set(id, i))
  }

  const stepsOf = new Map<string, number[]>()
  for (const e of stepEdges) {
    if (e.step == null) continue
    for (const id of [e.source, e.target]) stepsOf.set(id, [...new Set([...(stepsOf.get(id) ?? []), e.step])])
  }

  // A step card sits half way along its edge, so two fanned-out edges' cards are
  // half as far apart as their end nodes. Give a node whose incoming card is
  // tall enough room that neighbouring cards do not overlap.
  const cardLines = new Map<string, number>()
  const stepPairs = new Map<string, { right: string; lines: number }>()
  for (const e of stepEdges) {
    if (!column.has(e.source) || !column.has(e.target)) continue
    const key = [e.source, e.target].sort().join('|')
    const right = (column.get(e.source)! > column.get(e.target)!) ? e.source : e.target
    const p = stepPairs.get(key) ?? { right, lines: 0 }
    p.lines += 1
    stepPairs.set(key, p)
  }
  for (const { right, lines } of stepPairs.values()) cardLines.set(right, Math.max(cardLines.get(right) ?? 0, lines))
  const fyOf = new Map<string, number>()
  for (const ids of perColumn.values()) {
    const ys = [0]
    for (let i = 1; i < ids.length; i++) {
      const need = cardHeight(cardLines.get(ids[i - 1]) ?? 0) + cardHeight(cardLines.get(ids[i]) ?? 0) + CARD_MARGIN
      ys.push(ys[i - 1] + Math.max(ROW_GAP, need))
    }
    const mid = ys[ys.length - 1] / 2
    ids.forEach((id, i) => fyOf.set(id, ys[i] - mid))
  }

  const nodes: PathNode[] = order.map((id) => {
    const n = byId.get(id)!
    const c = column.get(id)!
    const ids = perColumn.get(c)!
    const row = ids.indexOf(id)
    const base = 'more' in n && n.more ? n : null
    return {
      ...n,
      column: c,
      row,
      fx: c * COLUMN_GAP,
      fy: fyOf.get(id)!,
      color: base ? base.color : n.reach ? REACH_COLOR[n.reach] : NODE_KIND_COLOR[n.kind] ?? '#64748b',
      radius: base ? base.radius : nodeRadius(n.importance),
      steps: stepsOf.get(id) ?? [],
    }
  })

  // Parallel step edges between the same two nodes form a tight bundle with one label card.
  const actionOf = new Map(chain.map((s) => [s.n, s.action]))
  // only edges between drawn nodes: force-graph throws on a link to a missing node
  const edges = [...stepEdges, ...reachEdges].filter((e) => column.has(e.source) && column.has(e.target))
  const groups = new Map<string, GraphEdge[]>()
  for (const e of edges) {
    const key = [e.source, e.target].sort().join('|')
    groups.set(key, [...(groups.get(key) ?? []), e])
  }
  const links: PathLink[] = edges.map((e) => {
    const key = [e.source, e.target].sort().join('|')
    const group = groups.get(key)!
    const i = group.indexOf(e)
    const spread = group.length > 2 ? BUNDLE_SPREAD : 0.2
    let curvature = group.length === 1 ? 0 : (i - (group.length - 1) / 2) * spread
    if (e.source > e.target) curvature = -curvature              // same side whichever way the edge points
    const isReach = e.kind !== 'step'
    const color = isReach ? REACH_COLOR[e.kind === 'reach_observed' ? 'observed' : 'inferred'] : tacticColor(e.tactic)
    const link: PathLink = {
      source: e.source,
      target: e.target,
      step: e.step,
      technique: e.technique,
      tactic: e.tactic,
      label: e.label,
      kind: e.kind,
      curvature,
      color,
      dashed: isReach,
      supporting: !!e.supporting,
      action: e.step != null ? actionOf.get(e.step) : undefined,
    }
    if (!isReach && i === group.findIndex((g) => g.kind === 'step')) {
      link.card = group.filter((g) => g.kind === 'step').map((g) => ({
        step: g.step,
        text: stripNumber(g.label).replace(/\s*\(anomaly\)$/, ''),
        color: tacticColor(g.tactic),
        supporting: !!g.supporting,
      }))
    }
    return link
  })
  placeCards(links, nodes)

  return {
    nodes,
    links,
    columns: Math.max(0, ...nodes.map((n) => n.column)) + 1,
    maxRows: Math.max(1, ...[...perColumn.values()].map((ids) => ids.length)),
    steps: [...new Set(stepEdges.map((e) => e.step).filter((s): s is number => s != null))].sort((a, b) => a - b),
    hiddenReach: reach.hidden,
    hiddenSupporting,
  }
}

interface Box { x0: number; y0: number; x1: number; y1: number }

function overlap(a: Box, b: Box): number {
  const w = Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0)
  const h = Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0)
  return w > 0 && h > 0 ? w * h : 0
}

/** Rough size of a step card in graph units (the canvas measures the real text). */
export function cardSize(card: CardLine[]): { w: number; h: number } {
  const chars = Math.max(...card.map((l) => l.text.length + (l.supporting ? 9 : 0)))
  return { w: CARD_FONT * (3.3 + chars * 0.56), h: cardHeight(card.length) }
}

const CARD_POSITIONS = [0.5, 0.4, 0.6, 0.32, 0.68, 0.25, 0.75]

/**
 * Crossing edges share a midpoint, so their cards would sit on top of each
 * other. Each card takes the first spot along its edge (`cardAt`, a fraction
 * from source to target, middle first) that (nearly) clears the cards placed
 * before it and the nodes with their labels, or the spot with the least overlap.
 */
function placeCards(links: PathLink[], nodes: PathNode[]): void {
  const pos = new Map(nodes.map((n) => [n.id, n]))
  // node plus label: under the node, or to its right for reach nodes
  const taken: Box[] = nodes.map((n) => {
    const half = Math.max(n.radius, (Math.max(n.label.length, 13) * 11 * 0.55) / 2)
    return n.reach
      ? { x0: n.fx - n.radius, x1: n.fx + n.radius + 2 * half, y0: n.fy - n.radius, y1: n.fy + n.radius }
      : { x0: n.fx - half, x1: n.fx + half, y0: n.fy - n.radius, y1: n.fy + n.radius + 30 }
  })
  for (const l of links) {
    if (!l.card) continue
    const s = pos.get(l.source)
    const t = pos.get(l.target)
    if (!s || !t) continue
    const { w, h } = cardSize(l.card)
    let best = { at: 0.5, cost: Infinity, box: null as Box | null }
    for (const at of CARD_POSITIONS) {
      const x = s.fx + (t.fx - s.fx) * at
      const y = s.fy + (t.fy - s.fy) * at
      const box = { x0: x - w / 2 - 4, x1: x + w / 2 + 4, y0: y - h / 2 - 4, y1: y + h / 2 + 4 }
      const cost = taken.reduce((a, b) => a + overlap(box, b), 0)
      if (cost < best.cost) best = { at, cost, box }
      if (cost <= 0.05 * w * h) break                      // a sliver of overlap: keep the earlier, more central spot
    }
    l.cardAt = best.at
    if (best.box) taken.push(best.box)
  }
}

/** Is a link drawn at full strength while the play-through shows `upTo` steps? null shows everything. */
export function linkVisible(link: Pick<PathLink, 'step'>, upTo: number | null): boolean {
  if (upTo == null) return true
  return link.step != null && link.step <= upTo
}

/** Canvas height for a layout: room for the tallest column, within limits. */
export function graphHeight(layout: Pick<PathLayout, 'nodes'>, min = 340, max = 640): number {
  if (layout.nodes.length === 0) return min
  const ys = layout.nodes.map((n) => n.fy)
  return Math.max(min, Math.min(max, Math.max(...ys) - Math.min(...ys) + 200))
}
