import { api } from '@/lib/api'
import { fileStamp, saveBlob } from '@/lib/download'
import type { MitreMatrix, MitreQuery, TechniqueDetail } from '@/types/mitre'

/** The matrix groups the whole window in one aggregation; allow more than the
 * default 25 s client timeout for a 90-day range on a busy tenant. */
const MATRIX_TIMEOUT_MS = 120_000

function params(q: MitreQuery): URLSearchParams {
  const sp = new URLSearchParams()
  if (q.start && q.end) {
    sp.set('start', q.start)
    sp.set('end', q.end)
  } else if (q.preset) sp.set('preset', q.preset)
  q.severity?.forEach((s) => sp.append('severity', s))
  q.status?.forEach((s) => sp.append('status', s))
  q.source?.forEach((s) => sp.append('source', s))
  if (q.includeFalsePositives) sp.set('include_false_positives', 'true')
  return sp
}

export async function fetchMitreMatrix(q: MitreQuery): Promise<MitreMatrix> {
  const { data } = await api.get<MitreMatrix>(`/mitre/matrix?${params(q).toString()}`, {
    timeout: MATRIX_TIMEOUT_MS,
  })
  return data
}

export async function fetchTechniqueDetail(techniqueId: string, q: MitreQuery): Promise<TechniqueDetail> {
  const { data } = await api.get<TechniqueDetail>(
    `/mitre/techniques/${encodeURIComponent(techniqueId)}?${params(q).toString()}`,
    { timeout: MATRIX_TIMEOUT_MS }
  )
  return data
}

/** Link to the alert list, filtered to the same alerts a cell counts. */
export function alertsLink(opts: { technique?: string; tactic?: string; preset?: string; start?: string; end?: string }): string {
  const sp = new URLSearchParams()
  if (opts.technique) sp.set('technique', opts.technique)
  if (opts.tactic) sp.set('tactic', opts.tactic)
  if (opts.start && opts.end) {
    // An absolute range as the list's custom range, which like the matrix goes
    // by the event time (or the arrival time when an alert has none).
    sp.set('date_range', `custom|${opts.start}|${opts.end}`)
  } else if (opts.preset === '24h' || opts.preset === '7d') {
    // The alert list speaks 1h / 24h / 7d; anything longer has no equivalent there,
    // so leave it off rather than silently narrowing what the cell showed.
    sp.set('date_range', opts.preset)
  }
  return `/alerts?${sp.toString()}`
}

// ── Exports ──────────────────────────────────────────────────────────────────

function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? '' : String(v)
  // Stop a spreadsheet evaluating log-derived text as a formula.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/** One row per tactic/technique cell, for a spreadsheet. */
export function matrixCsv(m: MitreMatrix): string {
  const head = ['Tactic ID', 'Tactic', 'Technique ID', 'Technique', 'Seen', 'Alerts', 'Open alerts',
    'Correlated alerts', 'Max severity', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown',
    'Sub-techniques seen', 'Sub-techniques total', 'Last seen', 'URL']
  const lines = [head.join(',')]
  for (const t of m.tactics) {
    for (const c of t.techniques) {
      lines.push([t.id, t.name, c.id, c.name, c.seen ? 'yes' : 'no', c.alerts, c.openAlerts,
        c.correlatedAlerts, c.maxSeverity ?? '', c.severity.critical, c.severity.high,
        c.severity.medium, c.severity.low, c.severity.info, c.severity.unknown,
        c.subtechniquesSeen, c.subtechniquesTotal, c.lastSeen ?? '', c.url].map(csvCell).join(','))
    }
  }
  return lines.join('\r\n')
}

/**
 * An ATT&CK Navigator layer, so the same picture can be opened in Navigator
 * (https://mitre-attack.github.io/attack-navigator/) or handed to someone who
 * works there. Scores are alert counts; techniques with none are left unscored
 * so Navigator shows them uncoloured.
 */
export function navigatorLayer(m: MitreMatrix, tenantName?: string): Record<string, unknown> {
  const techniques: Record<string, unknown>[] = []
  for (const t of m.tactics) {
    for (const c of t.techniques) {
      if (!c.seen) continue
      techniques.push({
        techniqueID: c.id,
        tactic: t.shortname,
        score: c.alerts,
        comment: [
          `${c.alerts} alert(s)`,
          c.maxSeverity ? `max severity ${c.maxSeverity}` : null,
          c.subtechniquesSeen ? `${c.subtechniquesSeen} sub-technique(s) seen` : null,
          c.lastSeen ? `last seen ${c.lastSeen}` : null,
        ].filter(Boolean).join('; '),
        enabled: true,
      })
      for (const s of c.subtechniques) {
        techniques.push({
          techniqueID: s.id,
          tactic: t.shortname,
          score: s.alerts,
          comment: `${s.alerts} alert(s)` + (s.maxSeverity ? `; max severity ${s.maxSeverity}` : ''),
          enabled: true,
        })
      }
    }
  }
  const scores = techniques.map((t) => Number(t.score) || 0)
  return {
    name: `${tenantName ? `${tenantName} ` : ''}observed ATT&CK ${m.period.start.slice(0, 10)} to ${m.period.end.slice(0, 10)}`,
    versions: { layer: '4.5', navigator: '4.9.0', attack: m.catalogue.attackSpecVersion ?? undefined },
    domain: m.catalogue.domain,
    description:
      'Alerts found by KillChain in the analysed logs, by ATT&CK technique. Scores are alert counts. ' +
      'An unscored technique was not observed, which is not the same as not being detectable.',
    filters: { platforms: [] },
    sorting: 3,
    hideDisabled: false,
    techniques,
    gradient: {
      colors: ['#dbeafe', '#2563eb', '#b91c1c'],
      minValue: 0,
      maxValue: Math.max(1, ...scores),
    },
    legendItems: [],
    showTacticRowBackground: false,
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  }
}

export type MitreExportFormat = 'csv' | 'json' | 'navigator'

export function exportMatrix(m: MitreMatrix, format: MitreExportFormat, tenantName?: string): void {
  const stamp = fileStamp()
  if (format === 'csv') {
    // BOM so Excel reads it as UTF-8.
    saveBlob(new Blob(['\ufeff' + matrixCsv(m)], { type: 'text/csv;charset=utf-8' }),
      `attack-matrix-${stamp}.csv`)
    return
  }
  if (format === 'navigator') {
    saveBlob(new Blob([JSON.stringify(navigatorLayer(m, tenantName), null, 2)], { type: 'application/json' }),
      `attack-navigator-layer-${stamp}.json`)
    return
  }
  saveBlob(new Blob([JSON.stringify({ exported_at: new Date().toISOString(), ...m }, null, 2)],
    { type: 'application/json' }), `attack-matrix-${stamp}.json`)
}
