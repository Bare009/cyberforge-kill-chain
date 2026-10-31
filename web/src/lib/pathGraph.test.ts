import { describe, expect, it } from 'vitest'
import { COLUMN_GAP, cardHeight, layoutPathGraph, linkVisible } from './pathGraph'
import { sampleIncident } from '@/test/fixtures'
import type { GraphEdge, GraphNode } from '@/types/incident'

const node = (id: string, kind: GraphNode['kind'] = 'internal_host', extra: Partial<GraphNode> = {}): GraphNode => ({
  id, label: id, kind, zone: 'desktop', importance: 0.25, ...extra,
})
const step = (source: string, target: string, n: number, tactic = 'lateral-movement'): GraphEdge => ({
  source, target, step: n, technique: 'T1021.002', tactic, label: `${n}. x`, kind: 'step',
})

describe('layoutPathGraph', () => {
  it('lays the sample out left to right: attacker, portal, then the reach-next server', () => {
    const g = layoutPathGraph(sampleIncident.graph, sampleIncident.chain)
    const col = Object.fromEntries(g.nodes.map((n) => [n.id, n.column]))
    expect(col).toEqual({ '32.127.48.11': 0, '10.10.20.20': 1, '10.10.20.31': 2 })
    expect(g.columns).toBe(3)
    expect(g.steps).toEqual([1, 2, 3, 4])
    const portal = g.nodes.find((n) => n.id === '10.10.20.20')!
    expect(portal.fx).toBe(COLUMN_GAP)
    expect(portal.steps).toEqual([1, 2, 3, 4])
  })

  it('fans out the four parallel steps so their labels do not overlap', () => {
    const g = layoutPathGraph(sampleIncident.graph, sampleIncident.chain)
    const steps = g.links.filter((l) => l.kind === 'step')
    const curves = steps.map((l) => l.curvature)
    expect(new Set(curves).size).toBe(4)
    expect(curves.reduce((a, b) => a + b, 0)).toBeCloseTo(0)
    expect(steps[0].action).toBe(sampleIncident.chain[0].action)
  })

  it('draws reach-next as dashed and colours steps by tactic', () => {
    const g = layoutPathGraph(sampleIncident.graph, sampleIncident.chain)
    const reach = g.links.find((l) => l.kind === 'reach_inferred')!
    expect(reach.dashed).toBe(true)
    const recon = g.links.find((l) => l.step === 1)!
    expect(recon.dashed).toBe(false)
    expect(recon.color).toBe('#0284c7')                         // reconnaissance colour
    expect(g.nodes.find((n) => n.id === '10.10.20.31')!.color).toBe('#94a3b8') // inferred reach
  })

  it('follows a lateral chain across columns and stacks siblings in one column', () => {
    const g = layoutPathGraph({
      nodes: [node('a'), node('b'), node('c'), node('d')],
      edges: [step('a', 'b', 1), step('b', 'c', 2), step('b', 'd', 3)],
    })
    const at = Object.fromEntries(g.nodes.map((n) => [n.id, [n.column, n.fy]]))
    expect(at.a[0]).toBe(0)
    expect(at.b[0]).toBe(1)
    expect(at.c[0]).toBe(2)
    expect(at.d[0]).toBe(2)
    expect(at.c[1]).toBe(-at.d[1])                               // centred around the middle row
  })

  it('keeps a back edge from moving a node already placed, and places isolated nodes last', () => {
    const g = layoutPathGraph({
      nodes: [node('a'), node('b'), node('lonely', 'domain')],
      edges: [step('a', 'b', 1), step('b', 'a', 2)],
    })
    const col = Object.fromEntries(g.nodes.map((n) => [n.id, n.column]))
    expect(col).toEqual({ a: 0, b: 1, lonely: 2 })
  })

  it('gives a bundle of parallel steps one label card, in step order', () => {
    const g = layoutPathGraph(sampleIncident.graph, sampleIncident.chain)
    const cards = g.links.filter((l) => l.card)
    expect(cards).toHaveLength(1)
    expect(cards[0].card!.map((c) => [c.step, c.text])).toEqual([
      [1, 'recon port sweep x240'], [2, 'web sqli x60'], [3, 'web shell x40'], [4, 'exfil volume x600']])
    expect(Math.max(...g.links.filter((l) => l.kind === 'step').map((l) => Math.abs(l.curvature)))).toBeLessThan(0.15)
  })

  it('keeps the top reach targets per node and folds the rest into one "+N more" node', () => {
    const reach = ['r1', 'r2', 'r3', 'r4', 'r5'].map((id) => node(id, 'server', { reach: 'inferred' }))
    const edges: GraphEdge[] = [step('a', 'b', 1),
      ...reach.map((r) => ({ source: 'b', target: r.id, step: null, technique: null, tactic: null, label: 'x', kind: 'reach_inferred' as const }))]
    const g = layoutPathGraph({ nodes: [node('a'), node('b'), ...reach], edges })
    expect(g.nodes.map((n) => n.id)).toEqual(['a', 'b', 'r1', 'r2', 'r3', '__more__:b'])
    expect(g.nodes.at(-1)!.more).toEqual({ count: 2, from: 'b' })
    expect(g.hiddenReach).toBe(2)
    expect(layoutPathGraph({ nodes: [node('a'), node('b'), ...reach], edges }, [], { reachLimit: null }).nodes).toHaveLength(7)
    const off = layoutPathGraph({ nodes: [node('a'), node('b'), ...reach], edges }, [], { reachLimit: 0 })
    expect(off.nodes.map((n) => n.id)).toEqual(['a', 'b'])
    expect(off.hiddenReach).toBe(5)
  })

  it('hides supporting anomalies, and nodes only they touch, unless asked', () => {
    const sup: GraphEdge = { ...step('x', 'b', 1), supporting: true }
    const g = layoutPathGraph({ nodes: [node('a'), node('b'), node('x')], edges: [step('a', 'b', 1), sup] })
    expect(g.nodes.map((n) => n.id)).toEqual(['a', 'b'])
    expect(g.hiddenSupporting).toBe(1)
    const all = layoutPathGraph({ nodes: [node('a'), node('b'), node('x')], edges: [step('a', 'b', 1), sup] }, [], { showSupporting: true })
    expect(all.nodes.map((n) => n.id).sort()).toEqual(['a', 'b', 'x'])
    expect(all.links.find((l) => l.supporting)!.supporting).toBe(true)
  })

  it('drops edges whose ends are not nodes', () => {
    const g = layoutPathGraph({ nodes: [node('a')], edges: [step('a', 'ghost', 1)] })
    expect(g.links).toEqual([])
  })
})

describe('reach through a subnet neighbour', () => {
  const reachEdge = (source: string, target: string): GraphEdge =>
    ({ source, target, step: null, technique: null, tactic: null, label: 'x', kind: 'reach_observed' })
  const servers = ['s1', 's2', 's3', 's4', 's5'].map((id) => node(id, 'server', { reach: 'inferred' }))
  const graph = {
    nodes: [node('a'), node('b', 'external_ip'), node('n1', 'internal_host', { reach: 'inferred' }),
      node('n2', 'internal_host', { reach: 'inferred' }), ...servers],
    edges: [step('a', 'b', 1), reachEdge('a', 'n1'), reachEdge('a', 'n2'),
      ...servers.flatMap((s) => [reachEdge('n1', s.id), reachEdge('n2', s.id)])],
  }

  it('chains foothold -> neighbour -> server, one incoming edge per target', () => {
    const g = layoutPathGraph(graph)
    const col = Object.fromEntries(g.nodes.map((n) => [n.id, n.column]))
    expect([col.n1, col.n2, col.s1, col.s4]).toEqual([1, 1, 2, 2])
    const into = (id: string) => g.links.filter((l) => l.target === id).length
    expect(servers.map((s) => into(s.id))).toEqual([1, 1, 1, 1, 1])
    expect(g.links.filter((l) => l.target === 's1')[0].source).toBe('n1')
    expect(g.links.filter((l) => l.target === 's4')[0].source).toBe('n2')
    expect(g.nodes.some((n) => n.more)).toBe(false)               // n1 drew 3, n2 the other 2
  })

  it('counts each hidden target once and never links to a node it did not draw', () => {
    const many = { ...graph, nodes: [...graph.nodes, ...['s6', 's7', 's8'].map((id) => node(id, 'server', { reach: 'inferred' }))],
      edges: [...graph.edges, ...['s6', 's7', 's8'].flatMap((s) => [reachEdge('n1', s), reachEdge('n2', s)])] }
    const g = layoutPathGraph(many)
    const ids = new Set(g.nodes.map((n) => n.id))
    expect(g.links.every((l) => ids.has(l.source) && ids.has(l.target))).toBe(true)
    expect(g.nodes.filter((n) => n.more).map((n) => n.more)).toEqual([{ count: 2, from: 'n1' }])
    expect(g.hiddenReach).toBe(2)
  })

  it('puts a "+N more" node right after its source\'s drawn targets', () => {
    const many = { ...graph, nodes: [...graph.nodes, ...['s6', 's7', 's8'].map((id) => node(id, 'server', { reach: 'inferred' }))],
      edges: [...graph.edges, ...['s6', 's7', 's8'].flatMap((s) => [reachEdge('n1', s), reachEdge('n2', s)])] }
    const g = layoutPathGraph(many)
    const byRow = g.nodes.filter((n) => n.column === 2).sort((x, y) => x.row - y.row).map((n) => n.id)
    expect(byRow).toEqual(['s1', 's2', 's3', '__more__:n1', 's4', 's5', 's6'])
  })
})

describe('step cards', () => {
  it('spaces targets so fanned-out cards do not overlap', () => {
    const g = layoutPathGraph({
      nodes: [node('a'), node('b', 'external_ip'), node('c', 'domain')],
      edges: [step('a', 'b', 1), step('a', 'b', 2), step('a', 'b', 3), step('a', 'c', 1)],
    })
    const fy = Object.fromEntries(g.nodes.map((n) => [n.id, n.fy]))
    // the cards sit half way, so the targets are twice the cards' combined height apart
    expect(Math.abs(fy.b - fy.c) / 2).toBeGreaterThanOrEqual((cardHeight(3) + cardHeight(1)) / 2)
  })

  it('moves a card along its edge when crossing edges would stack two cards', () => {
    const g = layoutPathGraph({
      nodes: [node('a'), node('b'), node('c'), node('d')],
      edges: [step('a', 'c', 1), step('a', 'd', 2), step('b', 'c', 3), step('b', 'd', 4)],
    })
    const at = g.links.filter((l) => l.card).map((l) => l.cardAt)
    expect(at.length).toBe(4)
    expect(new Set(at).size).toBeGreaterThan(1)
  })
})

describe('linkVisible', () => {
  it('shows every link when not playing, and only steps up to the current one while playing', () => {
    expect(linkVisible({ step: 3 }, null)).toBe(true)
    expect(linkVisible({ step: 2 }, 2)).toBe(true)
    expect(linkVisible({ step: 3 }, 2)).toBe(false)
    expect(linkVisible({ step: null }, 4)).toBe(false)
  })
})
