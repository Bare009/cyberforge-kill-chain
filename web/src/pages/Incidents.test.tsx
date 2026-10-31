import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderPage } from '@/test/render'
import { sampleIndexRows } from '@/test/fixtures'
import { Incidents } from './Incidents'

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...args: unknown[]) => get(...args) } }
})

function listResponse(rows = sampleIndexRows) {
  return { data: { run: 'sample-run', total: rows.length, limit: 500, offset: 0, incidents: rows } }
}

describe('Incidents page', () => {
  beforeEach(() => {
    get.mockReset()
  })

  it('shows each incident with risk, tactics in kill chain order, merged counts and IST times', async () => {
    get.mockResolvedValue(listResponse())
    renderPage(<Incidents />, { url: '/incidents' })

    const row = await screen.findByRole('link', { name: /Incident 1:/ })
    expect(row).toHaveAttribute('href', '/incidents/1')
    expect(within(row).getByText('#1')).toBeInTheDocument()
    expect(within(row).getByText('critical')).toBeInTheDocument()
    expect(within(row).getByText('77')).toBeInTheDocument()          // 76.5 rounded
    expect(within(row).getByText('4 alerts · 940 events')).toBeInTheDocument()
    expect(within(row).getByText('29 Oct 2026, 01:51:23 IST')).toBeInTheDocument()
    expect(within(row).getByText('AI: Looks real')).toBeInTheDocument()

    const chips = ['Reconnaissance', 'Initial Access', 'Persistence', 'Exfiltration']
    const order = chips.map((c) => within(row).getByText(c))
    for (let i = 1; i < order.length; i++) {
      // each chip comes after the previous one in the document
      expect(order[i - 1].compareDocumentPosition(order[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
  })

  it('sums merged alerts and events in the stat cards', async () => {
    get.mockResolvedValue(listResponse())
    renderPage(<Incidents />, { url: '/incidents' })
    expect(await screen.findByText('940')).toBeInTheDocument()
    expect(screen.getByText('Log events merged')).toBeInTheDocument()
  })

  it('sends filters from the URL to the API', async () => {
    get.mockResolvedValue(listResponse())
    renderPage(<Incidents />, { url: '/incidents?technique=T1190&severity=4' })
    await screen.findByRole('link', { name: /Incident 1:/ })
    expect(get).toHaveBeenCalledWith('/incidents', { params: { technique: 'T1190', severity: 4, limit: 500 } })
    expect(screen.getByLabelText('Technique')).toHaveValue('T1190')
  })

  it('searches as you type', async () => {
    get.mockResolvedValue(listResponse())
    renderPage(<Incidents />, { url: '/incidents' })
    await screen.findByRole('link', { name: /Incident 1:/ })
    await userEvent.type(screen.getByLabelText('Search incidents'), 'portal')
    await waitFor(() =>
      expect(get).toHaveBeenLastCalledWith('/incidents', { params: { q: 'portal', limit: 500 } })
    )
  })

  it('says when no incident matches the filters', async () => {
    get.mockResolvedValue(listResponse([]))
    renderPage(<Incidents />, { url: '/incidents?tactic=impact' })
    expect(await screen.findByText('No incident matches these filters.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Clear filters/ })).toBeInTheDocument()
  })

  it('shows the API error and a retry button', async () => {
    get.mockRejectedValue(new Error('boom'))
    renderPage(<Incidents />, { url: '/incidents' })
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load incidents: boom')
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})
