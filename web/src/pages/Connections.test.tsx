import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { renderPage } from '@/test/render'
import type { SiemIntegrationsResponse, SiemVendorsResponse } from '@/types/connectors'
import { Connections } from './Connections'

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, API_BASE_URL: 'http://api.test', api: { get: (...a: unknown[]) => get(...a) } }
})

const vendors: SiemVendorsResponse = {
  vendors: [
    {
      id: 'fortianalyzer',
      label: 'FortiAnalyzer',
      kind: 'siem',
      deployment: 'self-hosted',
      transports: ['webhook', 'api_pull'],
      authModes: ['bearer', 'hmac'],
      defaultAuthMode: 'bearer',
      docsUrl: null,
      setupSteps: [],
      syslogSteps: [],
      agentSteps: [],
      payloadTemplate: null,
      pull: null,
    },
  ],
  endpoints: {
    baseUrl: 'http://api.test',
    syslog: { host: 'localhost', udpPort: 514, tcpPort: 514, tlsPort: 6514, tlsEnabled: false },
    credentialsKeyConfigured: true,
  },
}

const integrations: SiemIntegrationsResponse = {
  integrations: [
    {
      connectorId: 'c1',
      vendor: 'fortianalyzer',
      vendorLabel: 'FortiAnalyzer',
      name: 'Branch firewall',
      transport: 'webhook',
      authMode: 'bearer',
      enabled: true,
      webhookUrl: 'http://api.test/ingest/webhook/c1',
      secretHint: 'soar_Ab12…',
      registered: true,
      observedStatus: 'active',
      alertsToday: 3,
      totalAlerts: 42,
      lastIngestAt: null,
      linesForwarded: 40,
      notAnalysable: 2,
    },
  ],
}

get.mockImplementation((url: string) => {
  const data = {
    '/settings/siem-vendors': vendors,
    '/settings/siem-integrations': integrations,
  }[url]
  return data ? Promise.resolve({ data }) : Promise.reject(new Error(url))
})

describe('Connections page', () => {
  it('renders the connection table and the Add connection button', async () => {
    renderPage(<Connections />)
    expect(screen.getByRole('heading', { name: 'SIEM connections' })).toBeInTheDocument()

    const table = await screen.findByRole('table', { name: 'Configured log source connections' })
    const row = within(table).getByText('Branch firewall').closest('tr') as HTMLElement
    expect(within(row).getByText('FortiAnalyzer')).toBeInTheDocument()
    expect(within(row).getByText('http://api.test/ingest/webhook/c1')).toBeInTheDocument()
    expect(within(table).getByText('Forwarded')).toBeInTheDocument()
    expect(within(row).getByText('40')).toBeInTheDocument()

    await waitFor(() => expect(screen.getByRole('button', { name: /Add connection/ })).toBeEnabled())
  })
})
