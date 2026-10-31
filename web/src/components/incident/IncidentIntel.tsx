import { Link } from 'react-router-dom'
import { EntityIntelCard } from '@/components/ti/IntelCards'
import { byVerdict } from '@/lib/threatIntel'
import type { Incident } from '@/types/incident'

/** The incident's Threat intel tab: one card per entity, worst verdict first. */
export function IncidentIntel({ inc, onEntity }: { inc: Incident; onEntity: (value: string) => void }) {
  const entries = Object.entries(inc.enrichment)
    .map(([value, e]) => ({ value, ...e }))
    .sort(byVerdict)

  if (entries.length === 0) {
    return (
      <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">
        No threat intel for this incident yet. Run <code className="font-mono">python -m killchain.enrich --run …</code> and restart the API.
      </p>
    )
  }
  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">
        External reputation of the incident's entities. Private and internal values are kept local and never sent.{' '}
        <Link to="/threat-intel" className="text-blue-600 hover:underline">
          All indicators
        </Link>
      </p>
      {entries.map((e) => (
        <EntityIntelCard
          key={e.value}
          value={e.value}
          kind={e.kind}
          zone={e.zone}
          verdict={e.verdict}
          reputation={e.reputation}
          providers={e.providers}
          flags={e.flags}
          sendable={e.sendable}
          onOpen={onEntity}
        />
      ))}
    </div>
  )
}
