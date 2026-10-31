import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderPage } from '@/test/render'
import matrix from '@/test/fixtures/mitre-matrix.json'
import techniqueT1190 from '@/test/fixtures/mitre-technique-T1190.json'
import { Mitre } from './Mitre'

const get = vi.fn()
vi.mock('@/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/api')>()
  return { ...real, api: { get: (...args: unknown[]) => get(...args) } }
})

/** Answers like killchain/api over the sample run (fixtures are real API output). */
function fakeApi(url: string) {
  if (url.startsWith('/mitre/matrix')) return Promise.resolve({ data: matrix })
  if (url.startsWith('/mitre/techniques/T1190')) return Promise.resolve({ data: techniqueT1190 })
  return Promise.reject(new Error(`unexpected ${url}`))
}

describe('MITRE page', () => {
  beforeEach(() => {
    get.mockReset()
    get.mockImplementation(fakeApi)
  })

  it('asks for the 30-day window by default and shows the summary', async () => {
    renderPage(<Mitre />, { url: '/mitre' })
    expect(await screen.findByText('4/216')).toBeInTheDocument()       // techniques observed
    expect(screen.getByText('4/14')).toBeInTheDocument()               // tactics observed
    expect(get.mock.calls[0][0]).toBe('/mitre/matrix?preset=30d')
  })

  it('draws observed cells and hides unobserved ones by default', async () => {
    renderPage(<Mitre />, { url: '/mitre' })
    const grid = await screen.findByRole('group', { name: 'ATT&CK tactic by technique matrix' })
    expect(within(grid).getByRole('button', { name: /^T1190 Exploit Public-Facing Application: 1 alert/ })).toBeInTheDocument()
    expect(within(grid).queryByRole('button', { name: /^T1110 Brute Force/ })).not.toBeInTheDocument()
  })

  it('has no false-positive filter (this project has no false-positive state)', async () => {
    renderPage(<Mitre />, { url: '/mitre' })
    await screen.findByText('4/216')
    expect(screen.queryByText('Include false positives')).not.toBeInTheDocument()
  })

  it('links each tactic to its incidents', async () => {
    renderPage(<Mitre />, { url: '/mitre' })
    // "Initial Access" is a link twice: the matrix column header (to attack.mitre.org) and the coverage list.
    const links = await screen.findAllByRole('link', { name: 'Initial Access' })
    const hrefs = links.map((l) => l.getAttribute('href'))
    expect(hrefs).toContain('/incidents?tactic=initial-access')
    expect(hrefs).toContain('https://attack.mitre.org/tactics/TA0001/')
  })

  it('opens a technique from the URL and links to its incidents', async () => {
    renderPage(<Mitre />, { url: '/mitre?technique=t1190' })
    expect(await screen.findByRole('heading', { name: 'Exploit Public-Facing Application' })).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('/mitre/techniques/T1190?preset=30d', expect.anything())
    expect(screen.getByRole('link', { name: 'View incidents' })).toHaveAttribute('href', '/incidents?technique=T1190')
    expect(screen.getByRole('link', { name: 'View alerts' })).toHaveAttribute('href', '/alerts?technique=T1190')
    expect(screen.getByRole('link', { name: 'Incident 1' })).toHaveAttribute('href', '/incidents/1')
    expect(screen.getByText('Detection rules')).toBeInTheDocument()
    expect(screen.getByText('fw-web-sqli')).toBeInTheDocument()
  })

  it('opens the detail when a cell is clicked', async () => {
    renderPage(<Mitre />, { url: '/mitre' })
    const cell = await screen.findByRole('button', { name: /^T1190 Exploit Public-Facing Application/ })
    await userEvent.click(cell)
    expect(await screen.findByRole('link', { name: 'View incidents' })).toBeInTheDocument()
  })

  it('switches the period', async () => {
    renderPage(<Mitre />, { url: '/mitre' })
    await screen.findByText('4/216')
    await userEvent.click(screen.getByRole('button', { name: '24h' }))
    expect(get).toHaveBeenLastCalledWith('/mitre/matrix?preset=24h', expect.anything())
  })
})
