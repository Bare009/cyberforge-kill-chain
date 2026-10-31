import { useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import { AlertCircle, ArrowLeft, Construction } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RiskBandBadge, SeverityText, TacticChips, TiVerdictBadge, TriageBadge } from '@/components/incident/badges'
import { AttackTimeline } from '@/components/incident/AttackTimeline'
import { EntityDrawer } from '@/components/incident/EntityDrawer'
import { EvidenceTab } from '@/components/incident/EvidenceTab'
import { IncidentIntel } from '@/components/incident/IncidentIntel'
import { ReachNext } from '@/components/incident/ReachNext'
import { AttackPathGraph } from '@/components/path/AttackPathGraph'
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
  { id: 'path', label: 'Attack path' },
  { id: 'reach', label: 'Reach next' },
  { id: 'intel', label: 'Threat intel' },
  { id: 'evidence', label: 'Evidence' },
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

function EntityChips({ inc, onEntity }: { inc: Incident; onEntity: (v: string) => void }) {
  const groups: [string, string[]][] = [
    ['IPs', inc.entities.ips],
    ['Hosts', inc.entities.hosts.filter((h) => !inc.entities.ips.includes(h))],
    ['Accounts', inc.entities.users],
    ['Domains', inc.entities.domains],
  ]
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      {groups
        .filter(([, values]) => values.length > 0)
        .map(([label, values]) => (
          <div key={label} className="flex flex-wrap items-center gap-1">
            <span className="text-[11px] uppercase tracking-wider text-slate-500">{label}</span>
            {values.map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => onEntity(v)}
                className="rounded border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[11px] text-slate-700 hover:border-blue-300 hover:text-blue-700"
              >
                {v}
              </button>
            ))}
          </div>
        ))}
    </div>
  )
}

function IncidentHeader({ inc, onEntity }: { inc: Incident; onEntity: (v: string) => void }) {
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
          <EntityChips inc={inc} onEntity={onEntity} />
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
  const isAi = inc.report_source === 'ai'
  const template = inc.report.template_markdown
  const [show, setShow] = useState<'ai' | 'template'>('ai')
  const showingAi = isAi && (show === 'ai' || !template)
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <Card>
        <CardContent className="p-5">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">
              {showingAi
                ? `Written by the AI narrator${inc.report.model ? ` (${inc.report.model})` : ''} and checked against the facts`
                : 'Template report built from the facts'}
            </p>
            {isAi && template && (
              <div role="group" aria-label="Report version" className="flex rounded-lg border border-slate-200 p-0.5 text-xs">
                {(['ai', 'template'] as const).map((v) => (
                  <button
                    key={v}
                    aria-pressed={show === v}
                    onClick={() => setShow(v)}
                    className={`rounded-md px-2 py-0.5 ${show === v ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-50'}`}
                  >
                    {v === 'ai' ? 'AI report' : 'Template'}
                  </button>
                ))}
              </div>
            )}
          </div>
          <MarkdownReport markdown={showingAi || !template ? inc.report.markdown : template} />
          {!isAi && (
            <p className="mt-4 text-xs text-slate-400">
              No AI report for this incident: the narrator has not run, no LLM key is set, or its answer did not pass the
              fact check.
            </p>
          )}
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

  const [entity, setEntity] = useState<string | null>(null)

  const requested = searchParams.get('tab')
  const tab: TabId = TABS.some((t) => t.id === requested) ? (requested as TabId) : 'timeline'
  const stepParam = Number(searchParams.get('step'))
  const evidenceStep = Number.isInteger(stepParam) && stepParam >= 1 ? stepParam : null
  const pageParam = Number(searchParams.get('page'))
  const evidencePage = Number.isInteger(pageParam) && pageParam >= 1 ? pageParam - 1 : 0

  /** Change the tab and, for the evidence tab, its step and page; everything lives in the URL. */
  const go = (next: string, step: number | null = null, page = 0) => {
    const sp = new URLSearchParams(searchParams)
    if (next === 'timeline') sp.delete('tab')
    else sp.set('tab', next)
    sp.delete('step')
    sp.delete('page')
    if (next === 'evidence') {
      if (step != null) sp.set('step', String(step))
      if (page > 0) sp.set('page', String(page + 1))
    }
    setSearchParams(sp, { replace: true })
  }
  const setTab = (next: string) => go(next)

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
      <IncidentHeader inc={inc} onEntity={setEntity} />
      <EntityDrawer value={entity} onClose={() => setEntity(null)} />

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
        <TabsContent value="path">
          <Card>
            <CardContent className="p-4">
              <AttackPathGraph
                graph={inc.graph}
                chain={inc.chain}
                fileName={`incident-${inc.incident_number}-attack-path`}
                onNodeClick={setEntity}
                onStepClick={(n) => go('evidence', n)}
              />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="reach">
          <ReachNext next={inc.next} nodes={inc.graph.nodes} onEntity={setEntity} />
        </TabsContent>
        <TabsContent value="intel">
          <IncidentIntel inc={inc} onEntity={setEntity} />
        </TabsContent>
        <TabsContent value="evidence">
          <EvidenceTab
            incidentNumber={inc.incident_number}
            chain={inc.chain}
            step={evidenceStep}
            page={evidencePage}
            onChange={(s, p) => go('evidence', s, p)}
          />
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
