/**
 * Display helpers for threat-intel provider results. The idea comes from
 * AI-SOC's lib/threatIntelDisplay.ts (one line of highlights per provider);
 * the fields are those of killchain/enrich (local context and OTX).
 */
import type { ProviderResult, TiVerdict } from '@/types/incident'

export const PROVIDER_LABEL: Record<string, string> = {
  local: 'Local context',
  otx: 'AlienVault OTX',
}

export const VERDICT_RANK: Record<TiVerdict, number> = { 'known-malicious': 3, suspicious: 2, 'no-reports': 1, unknown: 0 }

export function providerLabel(id: string): string {
  return PROVIDER_LABEL[id] ?? id
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v : null
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : []
}

export interface OtxPulse {
  id: string | null
  name: string | null
  created: string | null
  url: string | null
}

/** The OTX answer in display form, or null when the result is not OTX's. */
export function otxView(p: ProviderResult) {
  if (p.provider !== 'otx') return null
  const d = p.detail
  return {
    pulses: num(d.pulse_count) ?? 0,
    families: strings(d.malware_families),
    adversaries: strings(d.adversaries),
    tags: strings(d.tags),
    allowListed: d.allow_listed === true,
    validation: strings(d.validation),
    country: str(d.country),
    asn: str(d.asn),
    url: str(d.otx_url),
    topPulses: (Array.isArray(d.pulses) ? d.pulses : []) as OtxPulse[],
  }
}

/** One short line per provider, like AI-SOC's summarizeProvider. */
export function providerHighlights(p: ProviderResult): string[] {
  if (!p.available) return [p.error ? `Not available: ${p.error}` : 'Not available']
  const d = p.detail
  const out: string[] = []
  if (p.provider === 'otx') {
    const o = otxView(p)!
    if (o.allowListed) out.push('Allow-listed by OTX')
    out.push(o.pulses === 1 ? '1 pulse' : `${o.pulses} pulses`)
    if (o.families.length) out.push(`Families: ${o.families.slice(0, 3).join(', ')}`)
    if (o.adversaries.length) out.push(`Adversary: ${o.adversaries.slice(0, 2).join(', ')}`)
    if (o.country) out.push(o.country)
    if (o.asn) out.push(o.asn)
  } else if (p.provider === 'local') {
    const zone = str(d.zone)
    if (zone) out.push(`Zone ${zone}${str(d.role) ? ` (${d.role})` : ''}`)
    const alerts = num(d.alerts)
    if (alerts != null) out.push(alerts === 1 ? '1 alert in this run' : `${alerts} alerts in this run`)
    const rules = strings(d.rules)
    if (rules.length) out.push(`Rules: ${rules.slice(0, 3).join(', ')}${rules.length > 3 ? ', …' : ''}`)
    if (str(d.dynamic_dns)) out.push(`Dynamic DNS (${d.dynamic_dns})`)
    if (d.unusual_tld === true) out.push(`Unusual TLD .${d.tld}`)
    if (d.random_looking === true) out.push(`Random-looking name (entropy ${d.first_label_entropy})`)
    const inLog = d.in_log as Record<string, unknown> | null | undefined
    if (inLog && typeof inLog === 'object') {
      const ev = num(inLog.events)
      if (ev != null) out.push(`${ev.toLocaleString()} log events`)
      const failed = num(inLog.failed_admin_logins)
      if (failed) out.push(`${failed.toLocaleString()} failed admin logins`)
    }
    if (d.sendable === false && str(d.not_sent_because)) out.push(`Not sent outside: ${d.not_sent_because}`)
  } else {
    if (p.score != null) out.push(`Score ${p.score.toFixed(2)}`)
    out.push(...p.tags.slice(0, 4))
  }
  return out
}

/** Sort entities worst first: verdict, then reputation. */
export function byVerdict<T extends { verdict: TiVerdict; reputation: number }>(a: T, b: T): number {
  return VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict] || b.reputation - a.reputation
}
