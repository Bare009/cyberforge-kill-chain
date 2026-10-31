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
    expect(screen.getByRole('button', { name: 'edge 3. web shell x40' })).toHaveAttribute('data-color', '#cbd5e1')
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

  it('says so when there is nothing to draw', () => {
    draw({ graph: { nodes: [], edges: [] }, chain: [] })
    expect(screen.getByText('This incident has no graph.')).toBeInTheDocument()
  })
})
