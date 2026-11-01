import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderPage } from '@/test/render'
import { sampleAlerts, sampleIncident } from '@/test/fixtures'
import { AlertTable } from '@/components/views/shared'
import { AttackTimeline } from '@/components/incident/AttackTimeline'
import { vendorProduct } from '@/lib/killchain'
import type { Alert, Step } from '@/types/incident'

const vendorAlert: Alert = {
  ...sampleAlerts[0],
  alert_id: 'v1', rule_id: 'vendor:sentinelone:mimikatz-credential-theft', layer: 'vendor',
  title: 'Mimikatz credential theft', technique: 'T1003.001', technique_source: 'keyword',
}

describe('vendor layer (alerts other products raised)', () => {
  it('reads the product from the rule id', () => {
    expect(vendorProduct('vendor:wazuh:sshd-authentication-success')).toBe('wazuh')
    expect(vendorProduct('R12-ips-attack')).toBeNull()
  })

  it('shows a Vendor badge with the product and label source, and no rule link', () => {
    renderPage(<AlertTable alerts={[vendorAlert, sampleAlerts[0]]} />)
    const rows = screen.getAllByRole('row').slice(1)
    const badge = within(rows[0]).getByText(/Vendor · sentinelone · label: keyword/)
    expect(badge).toHaveAttribute('title', expect.stringContaining('keyword in the alert name'))
    expect(within(rows[0]).queryByRole('link', { name: vendorAlert.rule_id })).not.toBeInTheDocument()
    expect(within(rows[0]).getByText(vendorAlert.rule_id)).toBeInTheDocument()
    expect(within(rows[1]).queryByText(/Vendor/)).not.toBeInTheDocument()
    expect(within(rows[1]).getByRole('link', { name: sampleAlerts[0].rule_id })).toBeInTheDocument()
  })

  it('marks a vendor step in the incident timeline', () => {
    const step: Step = { ...sampleIncident.chain[0], layer: 'vendor', rule_id: 'vendor:microsoft-defender:encoded-powershell' }
    renderPage(<AttackTimeline chain={[step, sampleIncident.chain[1]]} gaps={[]} />)
    expect(within(screen.getByLabelText('Step 1')).getByText('Vendor · microsoft-defender')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Step 2')).queryByText(/Vendor/)).not.toBeInTheDocument()
  })
})
