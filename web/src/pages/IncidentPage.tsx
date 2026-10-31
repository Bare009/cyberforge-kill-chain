import type { ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import { AlertCircle, ArrowLeft, Construction } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RiskBandBadge, SeverityText, TacticChips, TiVerdictBadge, TriageBadge } from '@/components/incident/badges'
import { AttackTimeline } from '@/components/incident/AttackTimeline'
import { IncidentTechniques } from '@/components/incident/IncidentTechniques'
import { RiskBreakdown } from '@/components/incident/RiskBreakdown'
import { MarkdownReport } from '@/components/reports/MarkdownReport'
import { useIncident } from '@/hooks/useIncidents'
import { apiErrorMessage } from '@/lib/api'
import { formatIst, formatSpan } from '@/lib/killchain'
import { reportSummary } from '@/lib/report'
import type { Incident } from '@/types/incident'

/** Tabs in the order of docs/build-plan.md P12; `planned` ones are filled on later days. */
const TABS = [
  { id: 'timeline', label: 'Timeline' },
  { id: 'path', label: 'Attack path', planned: 'day 3: left-to-right graph of hosts, accounts and domains with numbered edges' },
  { id: 'reach', label: 'Reach next', planned: 'day 3: hosts the attacker can reach next, observed and inferred' },
  { id: 'intel', label: 'Threat intel', planned: 'day 4: provider results for every IP and domain' },
  { id: 'evidence', label: 'Evidence', planned: 'day 3: the raw log lines behind each step, with line numbers' },
  { id: 'report', label: 'Report' },
  { id: 'ask', label: 'Ask', planned: 'day 6: questions about this incident, answered from its evidence' },
  { id: 'attack', label: 'ATT&CK' },
] as const
type TabId = (typeof TABS)[number]['id']

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="text-sm text-slate-900">{children}</div>
    </div>
  )
}

function PlannedTab({ text }: { text: string }) {
  return (
    <Card>
      <CardContent className="flex items-start gap-3 p-6 text-sm text-slate-600">
        <Construction className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
        <span>Not built yet. Planned for {text}.</span>
      </CardContent>
    </Card>
  )
}

function IncidentHeader({ inc }: { inc: Incident }) {
  const summary = reportSummary(inc.report.markdown)
  return (
    <Card>
      <CardContent className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-2xl font-bold text-slate-400">#{inc.incident_number}</span>
            <h1 className="text-xl font-semibold text-slate-900">{inc.title}</h1>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <RiskBandBadge band={inc.risk_band} />
            <TriageBadge verdict={inc.report.triage?.verdict} />
            <TiVerdictBadge verdict={worstTiVerdict(inc)} />
            <span className="font-mono text-[10px] text-slate-400" title="Stable incident id">
              {inc.incident_id}
            </span>
          </div>
          {summary && <p className="text-sm leading-relaxed text-slate-700">{summary}</p>}
          <p className="font-mono text-xs text-slate-500">{inc.chain_text}</p>
          <TacticChips tactics={inc.tactics} />
          <div className="grid grid-cols-2 gap-4 pt-1 sm:grid-cols-4">
            <Fact label="Severity">
              <SeverityText severity={inc.severity} />
            </Fact>
            <Fact label="Started">{formatIst(inc.ts_start_ist)}</Fact>
            <Fact label="Lasted">{formatSpan(inc.ts_start, inc.ts_end)}</Fact>
            <Fact label="Merged">
              <span title="Raw alerts and log events merged into this incident (B-3)">
                {inc.merged.alerts} alerts · {inc.merged.events.toLocaleString()} events
              </span>
            </Fact>
          </div>
        </div>
        <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50/60 p-3">
          <div className="flex items-baseline justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-500">Risk score</span>
            <span className="font-mono text-3xl font-bold text-slate-900">{Math.round(inc.risk_score)}</span>
          </div>
          <RiskBreakdown parts={inc.risk_parts} score={inc.risk_score} />
        </div>
      </CardContent>
    </Card>
  )
}

const VERDICT_RANK = { 'known-malicious': 3, 'suspicious': 2, 'no-reports': 1, 'unknown': 0 } as const

/** The worst threat-intel verdict among the incident's entities, or null when none was checked. */
function worstTiVerdict(inc: Incident) {
  const verdicts = Object.values(inc.enrichment).map((e) => e.verdict)
  if (verdicts.length === 0) return null
  return verdicts.reduce((a, b) => (VERDICT_RANK[b] > VERDICT_RANK[a] ? b : a))
}

function ReportTab({ inc }: { inc: Incident }) {
  const triage = inc.report.triage
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <Card>
        <CardContent className="p-5">
          <p className="mb-2 text-[11px] uppercase tracking-wider text-slate-500">
            {inc.report_source === 'ai' ? 'Written by the narrator agent and checked against the facts' : 'Template report built from the facts'}
          </p>
          <MarkdownReport markdown={inc.report.markdown} />
        </CardContent>
      </Card>
      {triage && (
        <Card>
          <CardContent className="space-y-2 p-4 text-sm">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">AI triage opinion</p>
            <TriageBadge verdict={triage.verdict} />
            <p className="text-xs text-slate-500">Confidence {Math.round(triage.confidence * 100)}%. Shown for information; it never hides or reorders an incident.</p>
            {triage.reasons.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-600">
                {triage.reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export function IncidentPage() {
  const { id } = useParams()
  const [searchParams, setSearchParams] = useSearchParams()
  const { data: inc, isLoading, isError, error, refetch } = useIncident(id)

  const requested = searchParams.get('tab')
  const tab: TabId = TABS.some((t) => t.id === requested) ? (requested as TabId) : 'timeline'
  const setTab = (next: string) => {
    const sp = new URLSearchParams(searchParams)
    if (next === 'timeline') sp.delete('tab')
    else sp.set('tab', next)
    setSearchParams(sp, { replace: true })
  }

  const back = (
    <Link to="/incidents" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800">
      <ArrowLeft className="h-4 w-4" /> All incidents
    </Link>
  )

  if (isLoading) {
    return (
      <div className="space-y-4">
        {back}
        <Skeleton className="h-48 w-full rounded-xl" />
        <Skeleton className="h-96 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !inc) {
    const notFound = axios.isAxiosError(error) && error.response?.status === 404
    return (
      <div className="space-y-4">
        {back}
        <Card>
          <CardContent role="alert" className="flex items-center gap-3 p-6 text-sm">
            <AlertCircle className="h-5 w-5 shrink-0 text-red-500" />
            <span className="flex-1 text-slate-700">
              {notFound ? `Incident ${id} does not exist in this run.` : `Could not load incident ${id}: ${apiErrorMessage(error)}`}
            </span>
            {!notFound && (
              <Button variant="outline" size="sm" onClick={() => void refetch()}>
                Retry
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {back}
      <IncidentHeader inc={inc} />

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="h-auto flex-wrap justify-start">
          {TABS.map((t) => (
            <TabsTrigger key={t.id} value={t.id}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="timeline">
          <AttackTimeline chain={inc.chain} gaps={inc.gaps} />
        </TabsContent>
        <TabsContent value="report">
          <ReportTab inc={inc} />
        </TabsContent>
        <TabsContent value="attack">
          <Card>
            <CardContent className="p-4">
              <IncidentTechniques chain={inc.chain} />
            </CardContent>
          </Card>
        </TabsContent>
        {TABS.filter((t) => 'planned' in t).map((t) => (
          <TabsContent key={t.id} value={t.id}>
            <PlannedTab text={(t as { planned: string }).planned} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  )
}
