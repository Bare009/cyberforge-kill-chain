import { describe, expect, it } from 'vitest'
import { COLUMN_GAP, labelPoint, layoutPathGraph, linkVisible } from './pathGraph'
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

  it('drops edges whose ends are not nodes', () => {
    const g = layoutPathGraph({ nodes: [node('a')], edges: [step('a', 'ghost', 1)] })
    expect(g.links).toEqual([])
  })
})

describe('labelPoint', () => {
  it('is the midpoint of a straight link', () => {
    expect(labelPoint(0, 0, 100, 0, 0)).toEqual({ x: 50, y: 0 })
  })
  it('moves off the line by half the curve offset', () => {
    const p = labelPoint(0, 0, 100, 0, 0.4)
    expect(p.x).toBeCloseTo(50)
    expect(p.y).toBeCloseTo(-20)
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
