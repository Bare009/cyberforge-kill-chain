import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderPage } from '@/test/render'
import dashboard from '@/test/fixtures/dashboard.json'
import alertsPage from '@/test/fixtures/alerts-page.json'
import alertsNone from '@/test/fixtures/alerts-none.json'
import unexplained from '@/test/fixtures/unexplained.json'
import rules from '@/test/fixtures/rules.json'
import r12 from '@/test/fixtures/rule-r12.json'
import { Dashboard } from './Dashboard'
import { Alerts } from './Alerts'
import { Rules } from './Rules'

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...a: unknown[]) => get(...a) } }
})

function fakeGet(url: string, opts?: { params?: Record<string, unknown> }) {
  if (url === '/dashboard/summary') return Promise.resolve({ data: dashboard })
  if (url === '/alerts') return Promise.resolve({ data: opts?.params?.incident === 'none' ? alertsNone : alertsPage })
  if (url === '/unexplained') return Promise.resolve({ data: unexplained })
  if (url === '/rules') return Promise.resolve({ data: rules })
  if (url === '/rules/R12-large-lopsided-transfer') return Promise.resolve({ data: r12 })
  return Promise.reject(new Error(`unexpected ${url}`))
}

beforeEach(() => {
  get.mockReset()
  get.mockImplementation(fakeGet)
})

describe('Dashboard', () => {
  it('shows the KPI tiles from the run', async () => {
    renderPage(<Dashboard />, { url: '/' })
    const events = await screen.findByLabelText('Events parsed')
    expect(await within(events).findByText((9125383).toLocaleString())).toBeInTheDocument()
    expect(within(events).getByText(`${(15848040).toLocaleString()} log lines`)).toBeInTheDocument()
    expect(within(screen.getByLabelText('Alerts')).getByText('57')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Incidents')).getByText('25')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Log time span')).getByText('7 days')).toBeInTheDocument()
  })

  it('falls back to severity while the run has no risk scores, and says so', async () => {
    renderPage(<Dashboard />, { url: '/' })
    expect(await screen.findByText('Incidents by severity')).toBeInTheDocument()
    expect(screen.getByText(/Risk scores are not in this run yet/)).toBeInTheDocument()
    expect(within(screen.getByLabelText('Critical severity')).getByText('7')).toBeInTheDocument()
  })

  it('draws kill chain coverage in tactic order with links to the incident list', async () => {
    renderPage(<Dashboard />, { url: '/' })
    const cov = await screen.findByRole('list', { name: 'Kill chain coverage' })
    const bars = within(cov).getAllByRole('link')
    expect(bars).toHaveLength(14)
    expect(bars[2]).toHaveAccessibleName('Initial Access: 9 incidents')
    expect(bars[2]).toHaveAttribute('href', '/incidents?tactic=initial-access')
    expect(screen.getByText(/10 of 14 ATT&CK tactics reached/)).toBeInTheDocument()
  })

  it('lists top attackers, worst incidents and data quality', async () => {
    renderPage(<Dashboard />, { url: '/' })
    expect(await screen.findByRole('link', { name: '32.127.48.11' })).toHaveAttribute('href', '/incidents?entity=32.127.48.11')
    expect(screen.getByRole('link', { name: /#1\s*Discovery to Exfiltration by 32.127.48.11/ })).toHaveAttribute('href', '/incidents/1')
    expect(screen.getByText((5277136).toLocaleString())).toBeInTheDocument()                   // frozen-clock events
    expect(screen.getByText(/1\.6 GB in 1 range/)).toBeInTheDocument()
    expect(screen.getByLabelText('Alerts per hour chart')).toBeInTheDocument()
  })
})

describe('Alerts', () => {
  it('lists alerts with tab counts and incident links', async () => {
    renderPage(<Alerts />, { url: '/alerts' })
    expect(await screen.findByRole('tab', { name: /All\s*57/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: /Not in an incident\s*1/ })).toBeInTheDocument()
    const table = screen.getByRole('table')
    expect(within(table).getAllByRole('row')).toHaveLength(alertsPage.alerts.length + 1)
    expect(within(table).getAllByRole('link', { name: '#1' })[0]).toHaveAttribute('href', '/incidents/1')
    expect(within(table).getByRole('link', { name: 'R12-large-lopsided-transfer' })).toHaveAttribute(
      'href', '/rules?rule=R12-large-lopsided-transfer')
    expect(screen.getByText('57 alerts')).toBeInTheDocument()
  })

  it('sends URL filters (technique from the MITRE page) to the API', async () => {
    renderPage(<Alerts />, { url: '/alerts?technique=T1190&layer=rule&page=1' })
    await screen.findByRole('table')
    expect(get).toHaveBeenCalledWith('/alerts', { params: { technique: 'T1190', layer: 'rule', limit: 50, offset: 50 } })
  })

  it('asks for alerts in no incident on that tab', async () => {
    renderPage(<Alerts />, { url: '/alerts?tab=none' })
    await screen.findByRole('table')
    expect(get).toHaveBeenCalledWith('/alerts', { params: { incident: 'none', limit: 50, offset: 0 } })
    expect(screen.getByText('none')).toBeInTheDocument()
  })

  it('shows unexplained activity with the reason', async () => {
    renderPage(<Alerts />, { url: '/alerts' })
    await userEvent.click(await screen.findByRole('tab', { name: /Unexplained/ }))
    expect(await screen.findByText('single anomaly detector')).toBeInTheDocument()
    expect(screen.getByText(/nothing here changes an incident/)).toBeInTheDocument()
  })
})

describe('Rules', () => {
  it('lists rules with alerts and incident links', async () => {
    renderPage(<Rules />, { url: '/rules' })
    expect(await screen.findByText(/35 rules, \d+ fired/)).toBeInTheDocument()
    const row = screen.getByRole('button', { name: 'R12-large-lopsided-transfer' }).closest('tr')!
    expect(within(row).getByText('3')).toBeInTheDocument()
    expect(within(row).getByRole('link', { name: '#5' })).toHaveAttribute('href', '/incidents/5')
    expect(screen.getByRole('region', { name: 'Write a rule' })).toBeInTheDocument()
  })

  it('opens a rule with its YAML and recent alerts', async () => {
    renderPage(<Rules />, { url: '/rules' })
    await userEvent.click(await screen.findByRole('button', { name: 'R12-large-lopsided-transfer' }))
    const panel = await screen.findByLabelText('Rule R12-large-lopsided-transfer')
    await waitFor(() => expect(within(panel).getByLabelText('Rule YAML')).toHaveTextContent('id: R12-large-lopsided-transfer'))
    expect(within(panel).getAllByText(/planted 41 MB out/).length).toBeGreaterThan(0)
    expect(within(panel).getByText('needs eval')).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: 'All 3 alerts' })).toHaveAttribute('href', '/alerts?rule=R12-large-lopsided-transfer')
  })
})
