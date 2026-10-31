import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AxiosError, AxiosHeaders } from 'axios'
import { renderPage } from '@/test/render'
import alertsPage from '@/test/fixtures/alerts-page.json'
import { AskTab } from './AskTab'
import { RuleWriter } from './RuleWriter'
import { BudgetMeter } from './BudgetMeter'

const get = vi.fn()
const post = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a) } }
})

const health = {
  status: 'ok', run: 'firex-10G', sample: false, counts: { incidents: 25, alerts: 57 },
  llm: {
    enabled: true, configured: ['primary:llama-3.3-70b-versatile', 'primary:llama-3.1-8b-instant'],
    reports: 0, ai_reports: 0, template_reports: 25,
    budget: [
      { endpoint: 'primary:llama-3.3-70b-versatile', provider: 'primary', model: 'llama-3.3-70b-versatile', size: 'large',
        day: '2026-11-01', requests: 30, tokens: 45000, requests_per_day: 1000, tokens_per_day: 100000, tokens_left: 55000, paused: false },
      { endpoint: 'primary:llama-3.1-8b-instant', provider: 'primary', model: 'llama-3.1-8b-instant', size: 'small',
        day: '2026-11-01', requests: 2, tokens: 3000, requests_per_day: 14400, tokens_per_day: 500000, tokens_left: 497000, paused: false },
    ],
  },
}

function rejectWith(status: number, detail: string) {
  return new AxiosError('x', 'ERR_BAD_REQUEST', undefined, undefined, {
    status, statusText: 'x', headers: {}, config: { headers: new AxiosHeaders() }, data: { detail },
  })
}

beforeEach(() => {
  get.mockReset()
  post.mockReset()
  get.mockImplementation((url: string) => (url === '/health' ? Promise.resolve({ data: health }) : Promise.reject(new Error(url))))
})

describe('Budget meter', () => {
  it('shows tokens used today against the daily limit per model', async () => {
    renderPage(<BudgetMeter />)
    const meter = await screen.findByLabelText('LLM budget today')
    expect(within(meter).getByText('primary:llama-3.3-70b-versatile')).toBeInTheDocument()
    expect(within(meter).getByText(`${(45000).toLocaleString()} / ${(100000).toLocaleString()} tokens`)).toBeInTheDocument()
  })

  it('says how to add a key when no LLM is configured', async () => {
    get.mockResolvedValue({ data: { ...health, llm: { ...health.llm, configured: [], budget: [] } } })
    renderPage(<BudgetMeter />)
    expect(await screen.findByText(/add a Groq key/)).toBeInTheDocument()
  })
})

describe('Ask tab', () => {
  it('asks, shows the answer with the cited lines, and opens a step from a line', async () => {
    post.mockResolvedValue({ data: {
      incident_number: 1, question: 'Which steps got through?', answer: 'Steps 2 to 4 got through.',
      cited_lines: [{ line: 3210500, step: 2, ts_ist: '2026-10-29 02:07:10', raw: 'date=2026-10-29 time=02:07:10 action="accept"', source: 'firex-10G.log' }],
      model: 'primary:llama-3.1-8b-instant', cached: false, attempts: 1, lines_given: 60, tokens: 2100, rejected: false,
    } })
    const onOpenStep = vi.fn()
    renderPage(<AskTab incident={1} onOpenStep={onOpenStep} />)
    await userEvent.type(screen.getByLabelText('Ask about this incident'), 'Which steps got through?')
    await userEvent.click(screen.getByRole('button', { name: 'Ask' }))
    expect(post).toHaveBeenCalledWith('/incidents/1/ask', { question: 'Which steps got through?' }, { timeout: 90_000 })
    expect(await screen.findByText('Steps 2 to 4 got through.')).toBeInTheDocument()
    expect(screen.getByText(/answered from 60 evidence lines/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'line 3210500' }))
    expect(onOpenStep).toHaveBeenCalledWith(2)
    expect(screen.getByLabelText('Ask about this incident')).toHaveValue('')
  })

  it('shows a rejected answer as a warning, not as text', async () => {
    post.mockResolvedValue({ data: {
      incident_number: 1, question: 'q?', answer: null, cited_lines: [], model: null, cached: false, attempts: 2,
      lines_given: 60, tokens: 0, rejected: true, problems: ['cites line 1234567, which is not one of the evidence lines given'],
      note: 'The answer was not shown: it cited lines or addresses that are not in this incident\'s evidence.',
    } })
    renderPage(<AskTab incident={1} onOpenStep={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'How did the attacker get in?' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('The answer was not shown')
    expect(alert).toHaveTextContent('cites line 1234567')
  })

  it('explains the per-minute limit and a missing key', async () => {
    post.mockRejectedValueOnce(rejectWith(429, 'Limit of 6 questions and drafts a minute reached (free-tier LLM budget); try again in 40 s.'))
    renderPage(<AskTab incident={1} onOpenStep={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'How did the attacker get in?' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('try again in 40 s'))
  })
})

describe('Rule writer', () => {
  const yaml = 'id: U01-dns-burst\ntitle: DNS burst\nkind: count\n'
  const tested = {
    valid: true, ran: true, errors: [], alerts: 2, evidence_lines: 240, secs: 0.4,
    rule: { id: 'U01-dns-burst', title: 'DNS burst', kind: 'count', layer: 'rule', technique: 'T1071.004', tactic: 'command-and-control', severity: 3 },
    hits: alertsPage.alerts.slice(0, 2),
  }

  it('drafts a rule with AI, shows the YAML and the test on the run, then saves on a button press', async () => {
    post.mockImplementation((url: string) => {
      if (url === '/rules/draft') return Promise.resolve({ data: {
        description: 'd', yaml, explanation: 'Many DNS queries from one host.', test: tested, model: 'primary:big',
        cached: false, attempts: 1, problems: [], tokens: 1800 } })
      if (url === '/rules/save') return Promise.resolve({ data: {
        saved: true, path: 'rules/firewall/U01-dns-burst.yaml', rule: tested.rule, next: 'Run detect to include it.' } })
      return Promise.reject(new Error(url))
    })
    renderPage(<RuleWriter />)
    await userEvent.type(screen.getByLabelText('Rule writer: describe the rule'), 'more than 50 DNS queries from one host in 5 minutes')
    await userEvent.click(screen.getByRole('button', { name: 'Draft with AI' }))
    await waitFor(() => expect(screen.getByLabelText('Rule YAML')).toHaveValue(yaml))
    const result = screen.getByLabelText('Test result')
    expect(result).toHaveTextContent('2 alerts from 240 log lines in 0.4 s on this run')
    expect(within(result).getAllByRole('row')).toHaveLength(3)
    expect(post).not.toHaveBeenCalledWith('/rules/save', expect.anything())            // drafting never saves
    await userEvent.click(screen.getByRole('button', { name: 'Save rule' }))
    expect(post).toHaveBeenCalledWith('/rules/save', { yaml })
    expect(await screen.findByRole('status')).toHaveTextContent('rules/firewall/U01-dns-burst.yaml')
  })

  it('needs a passing test before Save, and an edit asks for a new test', async () => {
    post.mockImplementation((url: string) => url === '/rules/test'
      ? Promise.resolve({ data: tested }) : Promise.reject(new Error(url)))
    renderPage(<RuleWriter />)
    const editor = screen.getByLabelText('Rule YAML')
    await userEvent.type(editor, 'id: U01')
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Test on this run' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save rule' })).toBeEnabled())
    await userEvent.type(editor, 'x')
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeDisabled()
  })

  it('shows test errors from the API', async () => {
    post.mockResolvedValue({ data: { valid: false, ran: false, errors: ['x.yaml (U01): SQL does not compile: no column'], rule: null } })
    renderPage(<RuleWriter />)
    await userEvent.type(screen.getByLabelText('Rule YAML'), 'id: U01')
    await userEvent.click(screen.getByRole('button', { name: 'Test on this run' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('SQL does not compile')
  })
})
