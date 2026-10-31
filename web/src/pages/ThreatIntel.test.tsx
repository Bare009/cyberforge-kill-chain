import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AxiosError, AxiosHeaders } from 'axios'
import { renderPage } from '@/test/render'
import status from '@/test/fixtures/ti-status.json'
import indicators from '@/test/fixtures/ti-indicators.json'
import attacker from '@/test/fixtures/ti-indicator-attacker.json'
import flagged from '@/test/fixtures/ti-lookup-flagged.json'
import privateLookup from '@/test/fixtures/ti-lookup-private.json'
import { ThreatIntel } from './ThreatIntel'

const get = vi.fn()
const post = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a) } }
})

function fakeGet(url: string) {
  if (url === '/ti/status') return Promise.resolve({ data: status })
  if (url === '/ti/indicators') return Promise.resolve({ data: indicators })
  if (url === '/ti/indicators/32.127.48.11') return Promise.resolve({ data: attacker })
  return Promise.reject(new Error(`unexpected ${url}`))
}

describe('Threat Intel page', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
    get.mockImplementation(fakeGet)
  })

  it('shows provider status and where the results come from', async () => {
    renderPage(<ThreatIntel />, { url: '/threat-intel' })
    expect(await screen.findByText('AlienVault OTX')).toBeInTheDocument()
    expect(screen.getByText('Local context')).toBeInTheDocument()
    expect(screen.getByText(/4 indicators from the last engine run/)).toBeInTheDocument()
    expect(screen.getByText(/never sent outside/)).toBeInTheDocument()
  })

  it('lists every indicator with verdict, kind, OTX pulses and incident links', async () => {
    renderPage(<ThreatIntel />, { url: '/threat-intel' })
    const table = await screen.findByRole('table')
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(4)
    const first = rows[0]
    expect(within(first).getByRole('button', { name: '32.127.48.11' })).toBeInTheDocument()
    expect(within(first).getByText('TI: No reports')).toBeInTheDocument()
    expect(within(first).getByText('0')).toBeInTheDocument()                        // OTX pulses
    expect(within(first).getByRole('link', { name: '#1' })).toHaveAttribute('href', '/incidents/1?tab=intel')
    const portal = rows.find((r) => within(r).queryByRole('button', { name: 'portal.corp.local' }))!
    expect(within(portal).getByText('kept local')).toBeInTheDocument()
    expect(within(portal).getByText('TI: Not checked')).toBeInTheDocument()
  })

  it('sends filters from the URL', async () => {
    renderPage(<ThreatIntel />, { url: '/threat-intel?verdict=unknown&kind=ip&sendable=true' })
    await screen.findByRole('table')
    expect(get).toHaveBeenCalledWith('/ti/indicators', { params: { verdict: 'unknown', kind: 'ip', sendable: true } })
  })

  it('opens an indicator with each provider answer and a link to OTX', async () => {
    renderPage(<ThreatIntel />, { url: '/threat-intel' })
    await userEvent.click(await screen.findByRole('button', { name: '32.127.48.11' }))
    const drawer = await screen.findByRole('dialog')
    const card = await within(drawer).findByLabelText('Threat intel for 32.127.48.11')
    expect(within(card).getByText(/0 pulses · United States of America · AS7018/)).toBeInTheDocument()
    expect(within(card).getByText(/4 alerts in this run/)).toBeInTheDocument()
    expect(within(card).getByRole('link', { name: /OTX page/ })).toHaveAttribute(
      'href', 'https://otx.alienvault.com/indicator/ip/32.127.48.11')
    expect(within(drawer).getByRole('link', { name: /#1 Web attack chain/ })).toHaveAttribute('href', '/incidents/1?tab=intel')
  })

  it('looks up a value on demand and shows a flagged result', async () => {
    post.mockResolvedValue({ data: flagged })
    renderPage(<ThreatIntel />, { url: '/threat-intel' })
    await userEvent.type(await screen.findByLabelText('Look up an indicator'), '94.154.187.64')
    await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
    expect(post).toHaveBeenCalledWith('/ti/lookup', { value: '94.154.187.64' })
    const card = await screen.findByLabelText('Threat intel for 94.154.187.64')
    expect(within(card).getByText('TI: Known malicious')).toBeInTheDocument()
    expect(within(card).getByText('OTX: 7 pulses (Cobalt Strike)')).toBeInTheDocument()
    expect(within(card).getByText('flagged')).toBeInTheDocument()
    expect(within(card).getByRole('link', { name: 'Cobalt Strike C2 servers Oct 2026' })).toBeInTheDocument()
    expect(screen.getByText('Not seen in this run.')).toBeInTheDocument()
  })

  it('shows that a private value was kept local', async () => {
    post.mockResolvedValue({ data: privateLookup })
    renderPage(<ThreatIntel />, { url: '/threat-intel' })
    await userEvent.type(await screen.findByLabelText('Look up an indicator'), '10.10.20.20')
    await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
    const card = await screen.findByLabelText('Threat intel for 10.10.20.20')
    expect(within(card).getByText(/kept local: private, reserved or own address/)).toBeInTheDocument()
  })

  it('explains the rate limit', async () => {
    post.mockRejectedValue(
      new AxiosError('limit', 'ERR_BAD_REQUEST', undefined, undefined, {
        status: 429, statusText: 'Too Many Requests', headers: {}, config: { headers: new AxiosHeaders() },
        data: { detail: 'Lookup limit of 20 a minute reached; try again in 12 s.' },
      })
    )
    renderPage(<ThreatIntel />, { url: '/threat-intel' })
    await userEvent.type(await screen.findByLabelText('Look up an indicator'), '1.1.1.1')
    await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Lookup limit of 20 a minute reached'))
  })
})
