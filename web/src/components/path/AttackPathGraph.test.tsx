import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { sampleIncident } from '@/test/fixtures'
import { AttackPathGraph } from './AttackPathGraph'

vi.mock('react-force-graph-2d', () => import('@/test/forceGraphStub'))

function draw(props: Partial<Parameters<typeof AttackPathGraph>[0]> = {}) {
  const onNodeClick = vi.fn()
  const onStepClick = vi.fn()
  render(
    <AttackPathGraph
      graph={sampleIncident.graph}
      chain={sampleIncident.chain}
      fileName="incident-1-attack-path"
      onNodeClick={onNodeClick}
      onStepClick={onStepClick}
      {...props}
    />
  )
  return { onNodeClick, onStepClick }
}

describe('AttackPathGraph', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('draws every node and edge, with a step button per numbered step', () => {
    draw()
    for (const id of ['32.127.48.11', '10.10.20.20', '10.10.20.31']) {
      expect(screen.getByRole('button', { name: `node ${id}` })).toBeInTheDocument()
    }
    expect(screen.getByRole('button', { name: 'edge 2. web sqli x60' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'edge same server subnet (inferred)' })).toBeInTheDocument()
    const group = screen.getByRole('group', { name: 'Show up to step' })
    expect(Array.from(group.querySelectorAll('button')).map((b) => b.textContent)).toEqual(['1', '2', '3', '4'])
    expect(screen.getByText(/All 4 steps shown/)).toBeInTheDocument()
  })

  it('shows the legend for the kinds present, including inferred reach', () => {
    draw()
    expect(screen.getByText('External IP')).toBeInTheDocument()
    expect(screen.getByText('Server')).toBeInTheDocument()
    expect(screen.getByText('Reach next, inferred')).toBeInTheDocument()
    expect(screen.queryByText('Reach next, observed')).not.toBeInTheDocument()
  })

  it('opens a node and a step from clicks', () => {
    const { onNodeClick, onStepClick } = draw()
    fireEvent.click(screen.getByRole('button', { name: 'node 32.127.48.11' }))
    expect(onNodeClick).toHaveBeenCalledWith('32.127.48.11')
    fireEvent.click(screen.getByRole('button', { name: 'edge 3. web shell x40' }))
    expect(onStepClick).toHaveBeenCalledWith(3)
    // reach edges have no step, so nothing to open
    fireEvent.click(screen.getByRole('button', { name: 'edge same server subnet (inferred)' }))
    expect(onStepClick).toHaveBeenCalledTimes(1)
  })

  it('jumps to a step and fades the later edges', () => {
    draw()
    fireEvent.click(screen.getByRole('button', { name: '2' }))
    expect(screen.getByText(sampleIncident.chain[1].action)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'edge 2. web sqli x60' })).toHaveAttribute('data-color', '#0d9488')
    expect(screen.getByRole('button', { name: 'edge 3. web shell x40' })).toHaveAttribute('data-color', '#e2e8f0')
    fireEvent.click(screen.getByRole('button', { name: /All steps/ }))
    expect(screen.getByText(/All 4 steps shown/)).toBeInTheDocument()
  })

  it('plays the steps in order, one at a time, then stops on the last', () => {
    vi.useFakeTimers()
    draw()
    fireEvent.click(screen.getByRole('button', { name: 'Play steps in order' }))
    expect(screen.getByText(sampleIncident.chain[0].action)).toBeInTheDocument()
    for (const i of [1, 2, 3]) {
      act(() => {
        vi.advanceTimersByTime(1400)
      })
      expect(screen.getByText(sampleIncident.chain[i].action)).toBeInTheDocument()
    }
    act(() => {
      vi.advanceTimersByTime(1400 * 3)
    })
    expect(screen.getByText(sampleIncident.chain[3].action)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Play steps in order' })).toBeInTheDocument()   // stopped
  })

  it('cuts a long reach list to the top 3 with a "+N more" node, and shows all or none on request', () => {
    const reach = ['10.10.20.31', '10.10.20.74', '10.10.20.218', '10.10.20.182', '10.10.20.96']
    const graph = {
      nodes: [...sampleIncident.graph.nodes.filter((n) => !n.reach),
        ...reach.map((id) => ({ id, label: id, kind: 'server' as const, zone: 'server' as const, importance: 0.75, reach: 'inferred' as const }))],
      edges: [...sampleIncident.graph.edges.filter((e) => e.kind === 'step'),
        ...reach.map((t) => ({ source: '10.10.20.20', target: t, step: null, technique: null, tactic: null,
          label: 'same server subnet (inferred)', kind: 'reach_inferred' as const }))],
    }
    draw({ graph })
    expect(screen.getByRole('button', { name: 'node 10.10.20.218' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'node 10.10.20.182' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'node __more__:10.10.20.20' }))          // the "+2 more" node
    expect(screen.getByRole('button', { name: 'node 10.10.20.182' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'All 5' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getByRole('button', { name: 'Off' }))
    expect(screen.queryByRole('button', { name: 'node 10.10.20.31' })).not.toBeInTheDocument()
  })

  it('hides the edges of supporting anomalies until asked', () => {
    const graph = {
      nodes: sampleIncident.graph.nodes,
      edges: [...sampleIncident.graph.edges, { source: '32.127.48.11', target: '10.10.20.20', step: 2, technique: 'T1190',
        tactic: 'initial-access', label: '2. denied then allowed x241 (anomaly)', kind: 'step' as const, supporting: true }],
    }
    draw({ graph })
    expect(screen.queryByRole('button', { name: /denied then allowed/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Anomaly evidence (1)' }))
    expect(screen.getByRole('button', { name: 'edge 2. denied then allowed x241 (anomaly)' })).toBeInTheDocument()
  })

  it('says so when there is nothing to draw', () => {
    draw({ graph: { nodes: [], edges: [] }, chain: [] })
    expect(screen.getByText('This incident has no graph.')).toBeInTheDocument()
  })
})
