import { describe, expect, it } from 'vitest'
import { formatIst, formatSpan, inKillChainOrder, tacticLabel } from './killchain'
import { sampleIncident } from '@/test/fixtures'

describe('kill chain helpers', () => {
  it('orders tactics by kill chain stage and drops duplicates', () => {
    expect(inKillChainOrder(['exfiltration', 'reconnaissance', 'persistence', 'reconnaissance'])).toEqual([
      'reconnaissance', 'persistence', 'exfiltration',
    ])
  })

  it('labels tactics and keeps unknown values', () => {
    expect(tacticLabel('command-and-control')).toBe('Command and Control')
    expect(tacticLabel('something-else')).toBe('something-else')
  })

  it('formats IST strings with the date', () => {
    expect(formatIst('2026-10-29 01:51:23')).toBe('29 Oct 2026, 01:51:23 IST')
    expect(formatIst(null)).toBe('—')
  })

  it('formats spans', () => {
    expect(formatSpan('2026-10-28T20:21:23Z', '2026-10-28T20:22:26Z')).toBe('1 min')
    // 01:51:23 to 12:38:54 is 10 h 47 min 31 s; minutes are rounded.
    expect(formatSpan(sampleIncident.ts_start, sampleIncident.ts_end)).toBe('10 h 48 min')
    expect(formatSpan('2026-10-26T00:00:00Z', '2026-10-28T04:00:00Z')).toBe('2 d 4 h')
  })
})
