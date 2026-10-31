/** Day-3 tabs of the incident page: attack path, reach next, evidence, and the entity drawer. */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'
import { renderPage } from '@/test/render'
import { sampleIncident } from '@/test/fixtures'
import eventsAll from '@/test/fixtures/events-all.json'
import eventsStep2 from '@/test/fixtures/events-step2.json'
import entityAttacker from '@/test/fixtures/entity-attacker.json'
import entityReach from '@/test/fixtures/entity-reach.json'
import { IncidentPage } from './IncidentPage'

vi.mock('react-force-graph-2d', () => import('@/test/forceGraphStub'))

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...args: unknown[]) => get(...args) } }
})

/** Answers like killchain/api over the sample run (the fixtures are real API output). */
function fakeApi(url: string, config?: { params?: Record<string, unknown> }) {
  if (url === '/incidents/1') return Promise.resolve({ data: sampleIncident })
  if (url === '/incidents/1/events') {
    const p = config?.params ?? {}
    if (p.step === 2) return Promise.resolve({ data: eventsStep2 })
    if (p.step == null) return Promise.resolve({ data: eventsAll })
    return Promise.resolve({ data: { ...eventsAll, step: p.step, total: 0, lines: [] } })
  }
  if (url === '/entities/32.127.48.11') return Promise.resolve({ data: entityAttacker })
  if (url === '/entities/10.10.20.31') return Promise.resolve({ data: entityReach })
  return Promise.reject(new Error(`unexpected ${url}`))
}

function Where() {
  const loc = useLocation()
  return <output data-testid="where">{loc.pathname + loc.search}</output>
}

function open(url: string) {
  return renderPage(
    <>
      <IncidentPage />
      <Where />
    </>,
    { url, path: '/incidents/:id' }
  )
}

describe('Incident page, attack path tab', () => {
  beforeEach(() => {
    get.mockReset()
    get.mockImplementation(fakeApi)
  })

  it('draws the graph from the incident', async () => {
    open('/incidents/1?tab=path')
    const graph = await screen.findByTestId('force-graph')
    expect(within(graph).getByRole('button', { name: 'node 32.127.48.11' })).toBeInTheDocument()
    expect(within(graph).getAllByRole('button', { name: /^edge \d\./ })).toHaveLength(4)
  })

  it('opens the entity drawer from a node, with its incidents, alerts and threat intel', async () => {
    open('/incidents/1?tab=path')
    await userEvent.click(await screen.findByRole('button', { name: 'node 32.127.48.11' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('Incidents (1)')).toBeInTheDocument()
    expect(within(drawer).getByText('External IP · zone internet · importance 0.25')).toBeInTheDocument()
    expect(within(drawer).getByText('source')).toBeInTheDocument()
    expect(within(drawer).getByText('step 1, 2, 3, 4')).toBeInTheDocument()
    expect(within(drawer).getByText('Alerts (4)')).toBeInTheDocument()
    expect(within(drawer).getByText('TI: No reports')).toBeInTheDocument()
    expect(within(drawer).getByRole('link', { name: 'Filter the list' })).toHaveAttribute('href', '/incidents?entity=32.127.48.11')
    expect(get).toHaveBeenCalledWith('/entities/32.127.48.11')
  })

  it('opens the evidence of a step from its edge', async () => {
    open('/incidents/1?tab=path')
    await userEvent.click(await screen.findByRole('button', { name: 'edge 2. web sqli x60' }))
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/incidents/1?tab=evidence&step=2'))
    expect(await screen.findByRole('button', { name: 'Step 2 (20)', pressed: true })).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('/incidents/1/events', { params: { offset: 0, limit: 50, step: 2 } })
  })
})

describe('Incident page, reach next tab', () => {
  beforeEach(() => {
    get.mockReset()
    get.mockImplementation(fakeApi)
  })

  it('shows the sentence, the ranked hosts with how they are reached, and likely tactics', async () => {
    open('/incidents/1?tab=reach')
    expect(await screen.findByText(sampleIncident.next.sentence)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '10.10.20.31' })).toBeInTheDocument()
    expect(screen.getByText('inferred')).toBeInTheDocument()
    expect(screen.getByText(': same subnet (inferred)')).toBeInTheDocument()
    expect(screen.getByText('Credential Access')).toBeInTheDocument()
    expect(screen.getByText('Lateral Movement')).toBeInTheDocument()
  })

  it('opens a reachable host in the drawer', async () => {
    open('/incidents/1?tab=reach')
    await userEvent.click(await screen.findByRole('button', { name: '10.10.20.31' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('reachable next')).toBeInTheDocument()
    expect(within(drawer).getByText('No alert names this value directly.')).toBeInTheDocument()
  })
})

describe('Incident page, evidence tab', () => {
  beforeEach(() => {
    get.mockReset()
    get.mockImplementation(fakeApi)
  })

  it('lists the raw log lines with line numbers, IST times and step numbers', async () => {
    open('/incidents/1?tab=evidence')
    expect(await screen.findByRole('button', { name: 'All steps (80)', pressed: true })).toBeInTheDocument()
    const table = screen.getByRole('table')
    const rows = within(table).getAllByRole('row')
    expect(rows).toHaveLength(51)                      // header + 50 lines (first page)
    const first = rows[1]
    expect(within(first).getByText('3210274')).toBeInTheDocument()
    expect(within(first).getByText('2026-10-29 01:51:23')).toBeInTheDocument()
    expect(within(first).getByText(/srcip=32\.127\.48\.11 /)).toBeInTheDocument()
    expect(screen.getByText('Lines 1 to 50 of 80')).toBeInTheDocument()
    expect(screen.queryByText(/raw log is not on the API server/)).not.toBeInTheDocument()
  })

  it('pages through the lines and keeps the page in the URL', async () => {
    open('/incidents/1?tab=evidence')
    await screen.findByText('Lines 1 to 50 of 80')
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/incidents/1?tab=evidence&page=2'))
    expect(get).toHaveBeenCalledWith('/incidents/1/events', { params: { offset: 50, limit: 50 } })
  })

  it('filters to one step', async () => {
    open('/incidents/1?tab=evidence')
    await userEvent.click(await screen.findByRole('button', { name: 'Step 2 (20)' }))
    expect(await screen.findByText(sampleIncident.chain[1].action)).toBeInTheDocument()
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(21))
  })

  it('warns when the raw log is not on the server and shows the byte offset instead', async () => {
    get.mockImplementation((url: string, config?: { params?: Record<string, unknown> }) =>
      url === '/incidents/1/events'
        ? Promise.resolve({
            data: { ...eventsAll, raw_available: false, lines: eventsAll.lines.map((l) => ({ ...l, raw: null })) },
          })
        : fakeApi(url, config)
    )
    open('/incidents/1?tab=evidence')
    expect(await screen.findByText(/raw log is not on the API server/)).toBeInTheDocument()
    expect(screen.getByText('firex-10G.log @ byte 1694144963')).toBeInTheDocument()
  })
})

describe('Incident page header', () => {
  beforeEach(() => {
    get.mockReset()
    get.mockImplementation(fakeApi)
  })

  it('lists the entities and opens one in the drawer', async () => {
    open('/incidents/1')
    await screen.findByRole('heading', { name: sampleIncident.title })
    expect(screen.getByRole('button', { name: 'portal.corp.local' })).toBeInTheDocument()
    // 10.10.20.20 is an IP and a host; shown once
    expect(screen.getAllByRole('button', { name: '10.10.20.20' })).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: '32.127.48.11' }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })
})
