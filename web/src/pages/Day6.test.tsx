import { act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderPage } from '@/test/render'
import metrics from '@/test/fixtures/metrics.json'
import system from '@/test/fixtures/system.json'
import liveStatus from '@/test/fixtures/live-status.json'
import { LiveListener } from '@/components/live/LiveListener'
import { useLiveStore } from '@/store/useLiveStore'
import { Evaluation } from './Evaluation'
import { Live } from './Live'
import { System } from './System'

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, API_BASE_URL: 'http://api.test', api: { get: (...a: unknown[]) => get(...a) } }
})

const health = { status: 'ok', run: 'firex-10G', sample: false, counts: { incidents: 25, alerts: 57 }, llm: system.llm }

function fakeGet(url: string) {
  const data = { '/metrics': metrics, '/system': system, '/live/status': liveStatus, '/health': health }[url]
  return data ? Promise.resolve({ data }) : Promise.reject(new Error(url))
}

/** A stand-in EventSource that tests drive by hand. */
class FakeES {
  static last: FakeES | null = null
  static CLOSED = 2
  url: string
  readyState = 1
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  listeners: Record<string, ((m: MessageEvent) => void)[]> = {}
  closed = false
  constructor(url: string) {
    this.url = url
    FakeES.last = this
  }
  addEventListener(type: string, fn: (m: MessageEvent) => void) {
    ;(this.listeners[type] ??= []).push(fn)
  }
  emit(type: string, data: unknown) {
    for (const fn of this.listeners[type] ?? []) fn({ data: JSON.stringify(data) } as MessageEvent)
  }
  close() {
    this.closed = true
  }
}

beforeEach(() => {
  get.mockReset()
  get.mockImplementation(fakeGet)
  useLiveStore.setState({ follow: true, feed: [], changed: {}, connection: 'off' })
  vi.stubGlobal('EventSource', FakeES)
  FakeES.last = null
})
afterEach(() => vi.unstubAllGlobals())

describe('Evaluation page', () => {
  it('shows the seven metrics with grade and targets, and says the truth is silver', async () => {
    renderPage(<Evaluation />, { url: '/evaluation' })
    const recall = await screen.findByLabelText('Detection recall')
    expect(within(recall).getByText('100%')).toBeInTheDocument()
    expect(within(recall).getByText('Great')).toBeInTheDocument()
    expect(within(recall).getByText('Good ≥ 70% · Great ≥ 90%')).toBeInTheDocument()
    expect(within(screen.getByLabelText('False alarms')).getByText('Good ≤ 30% · Great ≤ 10%')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Investigation speed')).getByText('Good ≤ 2,000 ms · Great ≤ 500 ms')).toBeInTheDocument()
    expect(document.querySelectorAll('[data-metric]')).toHaveLength(7)
    expect(screen.getByText(/Scored against our silver truth/)).toBeInTheDocument()
  })

  it('lists planted incidents with recall, path order and our incident, and the per-rule table', async () => {
    renderPage(<Evaluation />, { url: '/evaluation' })
    const table = await screen.findByRole('table', { name: 'Per incident' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(25)
    expect(within(rows[0]).getByText('brute-force-burst')).toBeInTheDocument()
    expect(within(rows[0]).getByRole('link', { name: '#22' })).toHaveAttribute('href', '/incidents/22')
    const rules = screen.getByRole('table', { name: 'Per rule' })
    expect(within(rules).getByRole('link', { name: 'R12-large-lopsided-transfer' })).toHaveAttribute(
      'href', '/rules?rule=R12-large-lopsided-transfer')
  })

  it('shows the scorer notes for a manifest', async () => {
    get.mockImplementation((url: string) => url === '/metrics'
      ? Promise.resolve({ data: { ...metrics, truth: 'firex-30G.log.manifest.json',
          truth_notes: ['331 planted lines in 6 incident(s) are in the windows log, which was not given'] } })
      : fakeGet(url))
    renderPage(<Evaluation />, { url: '/evaluation' })
    const notes = await screen.findByRole('list', { name: 'Truth notes' })
    expect(notes).toHaveTextContent('windows log, which was not given')
    expect(screen.queryByText(/Scored against our silver truth/)).not.toBeInTheDocument()
  })

  it('explains how to score a run that has no metrics', async () => {
    get.mockImplementation((url: string) => url === '/metrics'
      ? Promise.resolve({ data: { available: false, run: 'x', hint: 'Run `python -m killchain eval score --run x`' } })
      : fakeGet(url))
    renderPage(<Evaluation />, { url: '/evaluation' })
    expect(await screen.findByText('This run has not been scored yet.')).toBeInTheDocument()
    expect(screen.getByText(/eval score --run x/)).toBeInTheDocument()
  })
})

describe('System page', () => {
  it('shows stages, run, data quality, threat intel and LLM status', async () => {
    renderPage(<System />, { url: '/system' })
    const stages = await screen.findByRole('table', { name: 'Stage timings' })
    const parse = within(stages).getByText('parse').closest('tr')!
    expect(within(parse).getByText(/MB$/)).toBeInTheDocument()
    expect(within(stages).getByText('Total')).toBeInTheDocument()
    const run = screen.getByLabelText('Run')
    expect(within(run).getByText('firex-10G')).toBeInTheDocument()
    expect(within(run).getByText(/not in \/app\/data\/raw/)).toBeInTheDocument()       // raw log not mounted
    expect(within(screen.getByLabelText('Data quality')).getByText((5277136).toLocaleString())).toBeInTheDocument()
    expect(within(screen.getByLabelText('Threat intel')).getByText('AlienVault OTX')).toBeInTheDocument()
    expect(within(screen.getByLabelText('LLM agents')).getByText('none (no key in .env)')).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Run file list' })).getByText('index.json')).toBeInTheDocument()
  })
})

describe('Live page and listener', () => {
  it('shows the process state, how to start it, and the follow switch', async () => {
    renderPage(<Live />, { url: '/live' })
    expect(await within(await screen.findByLabelText('Live process')).findByText('Not started')).toBeInTheDocument()
    expect(screen.getByText(/python -m killchain live/)).toBeInTheDocument()
    const sw = screen.getByRole('switch', { name: 'Follow live updates' })
    expect(sw).toHaveAttribute('aria-checked', 'true')
    await userEvent.click(sw)
    expect(sw).toHaveAttribute('aria-checked', 'false')
    expect(useLiveStore.getState().follow).toBe(false)
  })

  it('opens the stream, shows changes, refreshes the data and marks changed incidents', async () => {
    renderPage(<><LiveListener /><Live /></>, { url: '/live' })
    await waitFor(() => expect(FakeES.last).not.toBeNull())
    expect(FakeES.last!.url).toBe('http://api.test/live/stream')
    get.mockClear()
    act(() => {
      FakeES.last!.emit('hello', { id: 0, type: 'hello', at: '2026-11-01T10:00:00Z', version: 0 })
      FakeES.last!.emit('bundle', {
        id: 1, type: 'bundle', at: '2026-11-01T10:00:05Z', new_incidents: [26], changed_incidents: [1], removed_incidents: [],
        new_alerts: [{ alert_id: 'a1', rule_id: 'R01-admin-bruteforce', title: 'Brute force on the firewall admin login',
          severity: 4, ts_start: '2026-11-01T09:59:00Z', incident_number: 26, src_ip: '1.2.3.4', dst_ip: '10.10.99.1' }],
        counts: { incidents: 26, alerts: 58, new_alerts: 1, new_incidents: 1, changed_incidents: 1 },
      })
    })
    const feed = await screen.findByRole('list', { name: 'Live changes' })
    expect(within(feed).getByRole('link', { name: 'new #26' })).toHaveAttribute('href', '/incidents/26')
    expect(within(feed).getByRole('link', { name: 'changed #1' })).toBeInTheDocument()
    expect(within(feed).getByText('Brute force on the firewall admin login')).toBeInTheDocument()
    expect(useLiveStore.getState().changed).toEqual({ 1: '2026-11-01T10:00:05Z', 26: '2026-11-01T10:00:05Z' })
    await waitFor(() => expect(get).toHaveBeenCalledWith('/live/status'))             // queries were refreshed
  })

  it('closes the stream when following is switched off', async () => {
    renderPage(<LiveListener />)
    await waitFor(() => expect(FakeES.last).not.toBeNull())
    const es = FakeES.last!
    act(() => useLiveStore.getState().setFollow(false))
    expect(es.closed).toBe(true)
  })
})
