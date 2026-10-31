import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AxiosError, AxiosHeaders } from 'axios'
import { renderPage } from '@/test/render'
import { sampleIncident } from '@/test/fixtures'
import { MarkdownReport } from '@/components/reports/MarkdownReport'
import { reportSummary } from '@/lib/report'
import { IncidentPage } from './IncidentPage'

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...args: unknown[]) => get(...args) } }
})

function open(url = '/incidents/1') {
  return renderPage(<IncidentPage />, { url, path: '/incidents/:id' })
}

describe('Incident page', () => {
  beforeEach(() => {
    get.mockReset()
    get.mockResolvedValue({ data: sampleIncident })
  })

  it('loads the incident by the number in the URL', async () => {
    open()
    await screen.findByRole('heading', { name: sampleIncident.title })
    expect(get).toHaveBeenCalledWith('/incidents/1')
  })

  it('shows the header: summary, chain text, risk score with its parts, merged counts', async () => {
    open()
    await screen.findByRole('heading', { name: sampleIncident.title })
    expect(screen.getByText('#1')).toBeInTheDocument()
    expect(screen.getByText(/^32\.127\.48\.11 scanned, exploited/)).toBeInTheDocument()
    expect(screen.getByText(sampleIncident.chain_text)).toBeInTheDocument()
    expect(screen.getByText('77')).toBeInTheDocument()
    expect(screen.getByText('Total 76.5 / 100')).toBeInTheDocument()
    expect(screen.getByText('Stage reached')).toBeInTheDocument()
    expect(screen.getByText('25.0 / 25')).toBeInTheDocument()       // severity part
    expect(screen.getByText('4 alerts · 940 events')).toBeInTheDocument()
    // once as the incident's start in the header, once on step 1 of the timeline
    expect(screen.getAllByText('29 Oct 2026, 01:51:23 IST')).toHaveLength(2)
  })

  it('shows the numbered chain 1..N in order on the default tab, then the gaps', async () => {
    open()
    const steps = await screen.findAllByRole('listitem', { name: /^Step \d+$/ })
    expect(steps.map((s) => s.getAttribute('aria-label'))).toEqual(['Step 1', 'Step 2', 'Step 3', 'Step 4'])

    const first = within(steps[0])
    expect(first.getByText(sampleIncident.chain[0].action)).toBeInTheDocument()
    expect(first.getByText('T1595.002')).toBeInTheDocument()
    expect(first.getByText('Blocked')).toBeInTheDocument()
    expect(within(steps[1]).getByText('Got through')).toBeInTheDocument()
    expect(within(steps[3]).getByText('600 log lines of evidence')).toBeInTheDocument()

    expect(screen.getByText('Not observed')).toBeInTheDocument()
    expect(screen.getByText(sampleIncident.gaps[0])).toBeInTheDocument()
  })

  it('switches to the report tab and renders the markdown and the triage opinion', async () => {
    open()
    await screen.findByRole('heading', { name: sampleIncident.title })
    await userEvent.click(screen.getByRole('tab', { name: 'Report' }))
    expect(await screen.findByText('Template report built from the facts')).toBeInTheDocument()
    expect(screen.getByText('AI triage opinion')).toBeInTheDocument()
    expect(screen.getByText('Chain')).toBeInTheDocument()            // **Chain** heading line from the markdown
  })

  it('shows an AI report with its model, and toggles to the template kept beside it', async () => {
    const ai = {
      ...sampleIncident,
      report_source: 'ai',
      report: {
        source: 'ai', model: 'primary:llama-3.3-70b-versatile',
        markdown: '### Summary\n\nThe AI summary of the attack.\n\n### Attack chain\n\n**1. Reconnaissance**: a scan.',
        template_markdown: '**Chain**\n1. The template line.',
        triage: { verdict: 'looks_real', confidence: 0.9, reasons: ['four linked steps'] },
      },
    }
    get.mockResolvedValue({ data: ai })
    open('/incidents/1?tab=report')
    expect(await screen.findByText(/Written by the AI narrator \(primary:llama-3.3-70b-versatile\)/)).toBeInTheDocument()
    expect(screen.getAllByText('The AI summary of the attack.').length).toBe(2)       // header and report
    expect(screen.getByText('four linked steps')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Template' }))
    expect(screen.getByText('Template report built from the facts')).toBeInTheDocument()
    expect(screen.getByText('The template line.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Template' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('opens a tab from the URL: the ATT&CK view groups techniques by tactic', async () => {
    open('/incidents/1?tab=attack')
    expect(await screen.findByText('Exploit Public-Facing Application')).toBeInTheDocument()
    expect(screen.getByText('T1048.002')).toBeInTheDocument()
    expect(screen.getAllByText('matrix')[0]).toHaveAttribute('href', '/mitre?technique=T1595.002')
  })

  it('says when a tab is planned for a later day', async () => {
    open('/incidents/1?tab=ask')
    expect(await screen.findByText(/Not built yet. Planned for day 6/)).toBeInTheDocument()
  })

  it('says when the incident does not exist', async () => {
    get.mockRejectedValue(
      new AxiosError('not found', 'ERR_BAD_REQUEST', undefined, undefined, {
        status: 404, statusText: 'Not Found', headers: {}, config: { headers: new AxiosHeaders() },
        data: { detail: 'incident 99 not found' },
      })
    )
    open('/incidents/99')
    expect(await screen.findByRole('alert')).toHaveTextContent('Incident 99 does not exist in this run.')
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })
})

describe('report rendering', () => {
  it('never renders raw HTML or javascript links from the report', () => {
    const { container } = render(
      <MarkdownReport markdown={'Hi <script>alert(1)</script><img src=x onerror=alert(1)> [bad](javascript:alert(1)) [ok](https://attack.mitre.org)'} />
    )
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    const links = container.querySelectorAll('a')
    expect(links).toHaveLength(1)
    expect(links[0]).toHaveAttribute('href', 'https://attack.mitre.org')
    expect(links[0]).toHaveAttribute('rel', 'noopener noreferrer nofollow')
  })

  it('takes the summary from the **Summary.** line', () => {
    expect(reportSummary('**Summary.** One line.\n**Chain**\n1. x')).toBe('One line.')
    expect(reportSummary('Plain first line\nmore')).toBe('Plain first line')
    expect(reportSummary('')).toBeNull()
    expect(reportSummary('### Summary\n\nThe AI summary.\n\n### Attack chain')).toBe('The AI summary.')
    expect(reportSummary('**Chain**\n1. 2026-10-29 01:51:23 IST: x\n**Gaps**\n- none')).toBeNull()
  })
})
