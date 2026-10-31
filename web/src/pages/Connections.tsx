import { Plug } from 'lucide-react'
import { PageTitle } from '@/components/views/shared'
import { SiemIntegrations } from '@/components/connectors/SiemIntegrations'

/** SIEM connections: the connector registry ported from AI-SOC. */
export function Connections() {
  return (
    <div className="space-y-5">
      <PageTitle
        icon={<Plug className="h-5 w-5" />}
        title="SIEM connections"
        subtitle="Collect records from a SIEM or firewall by API pull (the platform polls the product) or webhook (the product posts to a URL made for the connection)."
      />
      <p className="max-w-3xl text-sm text-slate-600">
        Every received record is stored. When a record carries a raw FortiGate log line, the line is
        forwarded to live mode (<span className="font-mono">data/ingest/live.log</span>) and analysed
        like any other log line. Records without a log line are kept but counted as not analysable.
      </p>
      <SiemIntegrations />
    </div>
  )
}
