import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AxiosError, type AxiosResponse } from 'axios'
import { renderPage } from '@/test/render'
import { runNameFor, safeFileName, uploadFile } from '@/lib/upload'
import type { Job, RunList, UploadListing } from '@/types/jobs'
import { AnalyseLog } from './AnalyseLog'
import { RunPicker } from './RunPicker'
import { Dashboard } from '@/pages/Dashboard'

const get = vi.fn()
const post = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a) } }
})

const STAGES = ['parse', 'prepare', 'detect', 'correlate', 'chain', 'reach', 'score', 'report', 'enrich', 'narrate', 'bundle']

const listing: UploadListing = {
  enabled: true, raw_dir: 'F:/logs', partial: [], free_bytes: 150 * 2 ** 30, max_chunk: 256 * 2 ** 20,
  defaults: { workers: 8, cpus: 16 },
  files: [{ name: 'firex-10G.log', size: 6.5 * 2 ** 30, modified: '2026-10-30T10:00:00Z', runs: ['firex-10G'] }],
}
const runs: RunList = {
  active: 'firex-30G',
  runs: [
    { name: 'firex-30G', active: true, sample: false, incidents: 25, critical_incidents: 3, alerts: 127, events: 1, processing_secs: 600, bundled_at: null, input: 'firex-30G.log', input_bytes: 19.6 * 2 ** 30 },
    { name: 'firex-10G', active: false, sample: false, incidents: 25, critical_incidents: 3, alerts: 57, events: 1, processing_secs: 158, bundled_at: null, input: 'firex-10G.log', input_bytes: 6.5 * 2 ** 30 },
  ],
}

function job(over: Partial<Job> = {}): Job {
  return {
    id: 'j1', state: 'running', file: 'new.log', file_bytes: 12 * 2 ** 30, run: 'new',
    options: { offline: false, no_llm: true, workers: 8, switch: true },
    started_at: new Date(Date.now() - 65_000).toISOString(), finished_at: null, elapsed_secs: 65, upload_secs: 40,
    current: 'parse',
    stages: STAGES.map((name) => ({ name, status: name === 'parse' ? 'running' : 'pending', wall_secs: name === 'parse' ? 60 : null })),
    parse: { phase: 'parsing', pct: 25, gib: 3, secs: 60 }, tail: ['[parse] [new.log]  25.0%    3.00 GiB     60.0 s'],
    result: null, switched: false, error: null, ...over,
  }
}

let currentJob: Job | null = null

function fakeGet(url: string) {
  if (url === '/jobs/current') return Promise.resolve({ data: { enabled: true, job: currentJob } })
  if (url === '/uploads') return Promise.resolve({ data: listing })
  if (url === '/runs') return Promise.resolve({ data: runs })
  if (url === '/health') return Promise.resolve({ data: { status: 'ok', run: 'firex-30G', sample: false, counts: { incidents: 25, alerts: 127 }, llm: { enabled: false, configured: [] } } })
  if (url.startsWith('/uploads/')) return Promise.resolve({ data: { name: 'x', received: 0, size: null, complete: false } })
  return Promise.reject(new Error(`unexpected GET ${url}`))
}

beforeEach(() => {
  get.mockReset()
  post.mockReset()
  get.mockImplementation(fakeGet)
  currentJob = null
  localStorage.clear()
})

describe('upload helpers', () => {
  it('cleans file names and picks a run name no run has', () => {
    expect(safeFileName('My log (1).txt')).toBe('My_log__1_.txt')
    expect(safeFileName('..secret.log')).toBe('secret.log')
    expect(runNameFor('firex-13G.log', ['firex-30G'])).toBe('firex-13G')
    expect(runNameFor('firex-30G.log', ['firex-30G', 'firex-30G-2'])).toBe('firex-30G-3')
  })

  it('sends the file in chunks from where the server is, and follows a 409', async () => {
    const file = new File(['a'.repeat(250)], 'x.log')
    get.mockResolvedValueOnce({ data: { name: 'x.log', received: 50, size: null, complete: false } })
    const offsets: number[] = []
    let first = true
    post.mockImplementation((_url: string, body: Blob, cfg: { params: { offset: number } }) => {
      offsets.push(cfg.params.offset)
      if (first) {                                  // the server already moved on to 150
        first = false
        const res = { status: 409, data: { received: 150 } } as AxiosResponse
        return Promise.reject(new AxiosError('conflict', '409', undefined, undefined, res))
      }
      const received = cfg.params.offset + body.size
      return Promise.resolve({ data: { name: 'x.log', received, size: received === 250 ? 250 : null, complete: received === 250 } })
    })
    const progress: number[] = []
    const res = await uploadFile(file, 'x.log', { chunkBytes: 60, onProgress: (p) => progress.push(p.sent) })
    expect(res.already).toBe(false)
    expect(offsets).toEqual([50, 150, 210])
    expect(progress.at(-1)).toBe(250)
  })

  it('does not send a file the server already has', async () => {
    get.mockResolvedValueOnce({ data: { name: 'x.log', received: 3, size: 3, complete: true } })
    expect(await uploadFile(new File(['abc'], 'x.log'), 'x.log')).toEqual({ already: true, secs: 0 })
    expect(post).not.toHaveBeenCalled()
    get.mockResolvedValueOnce({ data: { name: 'x.log', received: 9, size: 9, complete: true } })
    await expect(uploadFile(new File(['abc'], 'x.log'), 'x.log')).rejects.toThrow(/different file/)
  })
})

describe('AnalyseLog', () => {
  it('uploads a chosen file, then starts the job with the options', async () => {
    post.mockImplementation((url: string, _body: unknown, cfg?: { params?: { offset: number; total: number } }) => {
      if (url === '/uploads/firex-13G.log') {
        return Promise.resolve({ data: { name: 'firex-13G.log', received: cfg!.params!.total, size: cfg!.params!.total, complete: true } })
      }
      if (url === '/jobs') {
        currentJob = job({ file: 'firex-13G.log', run: 'firex-13G' })
        return Promise.resolve({ data: currentJob })
      }
      return Promise.reject(new Error(`unexpected POST ${url}`))
    })
    renderPage(<AnalyseLog />)
    const input = await screen.findByTestId('log-file')
    fireEvent.change(input, { target: { files: [new File(['date=2026-10-27 x\n'], 'firex-13G.log')] } })
    expect(screen.getByLabelText('Save as')).toHaveValue('firex-13G.log')
    expect(screen.getByLabelText('Run name')).toHaveValue('firex-13G')
    await waitFor(() => expect(screen.getByLabelText('Parser processes')).toHaveValue(8))
    expect(screen.getByRole('checkbox', { name: /AI-written reports/ })).toBeDisabled()     // no LLM key
    await userEvent.click(screen.getByRole('button', { name: /Upload and analyse/ }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/jobs', expect.objectContaining({
      file: 'firex-13G.log', run: 'firex-13G', offline: false, no_llm: true, workers: 8,
    })))
    expect(await screen.findByText(/Analysing firex-13G.log/)).toBeInTheDocument()
  })

  it('analyses a log already on the server without uploading', async () => {
    post.mockImplementation((url: string) => {
      if (url === '/jobs') return Promise.resolve({ data: job() })
      return Promise.reject(new Error(`unexpected POST ${url}`))
    })
    renderPage(<AnalyseLog />)
    await userEvent.selectOptions(await screen.findByLabelText('Log on the server'), 'firex-10G.log')
    expect(screen.getByLabelText('Run name')).toHaveValue('firex-10G-2')
    await userEvent.click(screen.getByRole('button', { name: /^Analyse$/ }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/jobs', expect.objectContaining({ file: 'firex-10G.log', run: 'firex-10G-2', upload_secs: null })))
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('shows a running job stage by stage, with parse progress, and can cancel it', async () => {
    currentJob = job()
    post.mockResolvedValue({ data: job({ state: 'cancelled' }) })
    renderPage(<AnalyseLog />)
    expect(await screen.findByText(/Stage 1 of 11: Parse the log/)).toBeInTheDocument()
    expect(screen.getByText(/upload took 40 s/)).toBeInTheDocument()
    expect(screen.getByText(/8 parser processes/)).toBeInTheDocument()
    expect(screen.getByText(/Parsed 3.00 of 12.00 GiB \(25%\)/)).toBeInTheDocument()
    expect(screen.getByText(/about 3 min 0 s left/)).toBeInTheDocument()
    const stages = within(screen.getByRole('list', { name: 'Pipeline stages' })).getAllByRole('listitem')
    expect(stages).toHaveLength(11)
    expect(within(stages[0]).getByLabelText('running')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Cancel/ }))
    expect(post).toHaveBeenCalledWith('/jobs/current/cancel')
  })

  it('shows the result of a finished job: counts and times', async () => {
    currentJob = job({
      state: 'ok', current: null, finished_at: new Date().toISOString(), elapsed_secs: 400, switched: true,
      stages: STAGES.map((name) => ({ name, status: name === 'narrate' ? 'skipped' : 'ok', wall_secs: name === 'narrate' ? null : 10 })),
      result: { status: 'ok', exit_code: 0, wall_secs: 390, peak_rss_mb: 2400, incidents: 21, critical_incidents: 4, alerts: 99,
        unexplained: 40, events: 30_000_000, lines: 31_000_000, warnings: [], error: null },
    })
    renderPage(<AnalyseLog />)
    expect(await screen.findByText(/Done: new.log/)).toBeInTheDocument()
    expect(within(screen.getByLabelText('Incidents')).getByText('21')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Incidents')).getByText('4 critical')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Upload')).getByText('40 s')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Processing')).getByText('6 min 30 s')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Total')).getByText('7 min 10 s')).toBeInTheDocument()
    expect(screen.getByText(/every page now show this run/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Analyse another log/ }))
    expect(screen.getByRole('button', { name: 'Choose a log file' })).toBeInTheDocument()
  })
})

describe('Dashboard with no run loaded', () => {
  it('shows only the upload card, and no run list', async () => {
    const empty = { ...runs, active: 'none', runs: runs.runs.map((r) => ({ ...r, active: false })) }
    get.mockImplementation((url: string) => {
      if (url === '/dashboard/summary') return Promise.resolve({ data: { run: 'none', sample: false, empty: true } })
      if (url === '/runs') return Promise.resolve({ data: empty })
      return fakeGet(url)
    })
    renderPage(<Dashboard />)
    expect(await screen.findByText('No log analysed yet.')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Choose a log file' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Events parsed')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Run shown')).not.toBeInTheDocument()
  })
})

describe('RunPicker', () => {
  it('lists the runs and switches to the one picked', async () => {
    post.mockResolvedValue({ data: { active: 'firex-10G' } })
    renderPage(<RunPicker />)
    const select = await screen.findByLabelText('Run shown')
    expect(select).toHaveValue('firex-30G')
    await userEvent.selectOptions(select, 'firex-10G')
    expect(post).toHaveBeenCalledWith('/runs/select', { run: 'firex-10G' })
  })
})
