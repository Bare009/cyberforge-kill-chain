# Web UI

React app for the kill chain analyser. Started from the AI-SOC dashboard
(`AI-SOC/web_app/frontend`) with login, tenancy, licensing and the SOC-only
pages removed. Talks only to `killchain/api`.

Stack (as in AI-SOC): React 19, Vite 7, TypeScript, Tailwind 4, Radix UI
(`src/components/ui`), TanStack Query, axios, zustand, lucide-react, recharts,
react-force-graph-2d, react-markdown.

## Run

Node.js 20 or newer.

```powershell
cd web
npm install
copy .env.example .env      # optional; default API is http://localhost:8000
npm run dev                 # http://localhost:5173
npm run build               # type-check and production build into dist/
npm run lint
npm test                    # Vitest + Testing Library, API mocked with real responses
```

Tests sit next to the pages (`*.test.tsx`). They mock `@/lib/api` and answer
with the committed sample run (`examples/sample-run`) or with saved API
responses in `src/test/fixtures/` (see the README there to regenerate them).

The status bar shows whether the API answers `GET /health`.

## Pages

Routes follow `docs/build-plan.md` P12. Pages not built yet show a placeholder
saying when they are planned.

| Route | Page | State |
|---|---|---|
| `/` | Dashboard | built: KPI tiles (events, alerts, incidents, critical, log span, run time, peak memory), kill chain coverage over the 14 tactics, incidents by risk band (by severity until the run has risk scores), worst incidents, alerts per hour (rule and anomaly, IST), top attackers and targets, data quality, stage timings, TI and report status |
| `/incidents` | Incident list | built: worst first, risk bar, tactic chips in kill chain order, merged alerts and events, IST times, filters in the URL (`q`, `tactic`, `technique`, `entity`, `severity`) |
| `/incidents/:id` | Incident page | header (summary, risk parts, merged counts, clickable entities) and tabs: Timeline (numbered chain and gaps), Attack path (graph below), Reach next (ranked hosts, observed vs inferred, how each is reached, likely next tactics), Evidence (raw log lines per step with line numbers, paged; `?tab=evidence&step=2&page=3`), Report (the AI narrator's report with its model and triage opinion, with a toggle to the template; the template alone when there is no AI report), Threat intel (each entity's local context and OTX answer, or why it was kept local), Ask (questions answered from the incident's evidence, with the cited lines; a cited line opens that step's evidence; budget meter), ATT&CK. Clicking an entity opens the entity drawer (its incidents, alerts, threat intel) |
| `/mitre` | ATT&CK matrix | ported from AI-SOC; `?technique=T1190` opens a technique; links go to `/incidents?...` and `/alerts?...` |
| `/alerts` | Alerts | built: tabs All, Not in an incident, Unexplained (with the reason); filters in the URL (`q`, `tactic`, `technique`, `layer`, `severity`, `rule`, `entity`, `incident`, `sort`, `page`), 50 a page, links to the incident and the rule |
| `/threat-intel` | Threat Intel | built: provider status, last enrich run, on-demand lookup box, indicator table with verdict, kind and "checked outside" filters |
| `/rules` | Rules | built: every rule and anomaly detector with alerts, incidents, run time and last alert; `?rule=ID` opens its settings, YAML and recent alerts. Rule writer: describe a rule, draft it with AI (or write it), test it on the run (alerts, first 5 hits), then Save; Save is enabled only after a passing test. LLM budget meter beside it |
| `/live` | Live | placeholder (day 6) |
| `/evaluation` | Evaluation | placeholder (day 6) |
| `/system` | System | placeholder (day 6) |

## What came from AI-SOC

Kept: `components/ui/*`, the layout (`MainLayout`, `Sidebar`, `Topbar`,
`StatusBar`), `CommandPalette`, `Toaster`, `SeverityBadge`, `lib/utils`
(time formatting, set to IST), `lib/download`, `lib/timeRange`, and the MITRE
page with `components/mitre/*`, `lib/mitre-api.ts`, `types/mitre.ts`.

Changed: `lib/api.ts` (no auth header, `VITE_API_URL`, default port 8000),
the stores (UI state only), navigation (`lib/nav.ts`), the command palette
(jumps to an incident by number).

Day 2: the incident list follows AI-SOC's `CorrelationGraph` rows and stat
cards; the incident page takes its layout ideas from
`command-center/CommandCenter` (in the light theme) and the safe Markdown
renderer from `IncidentReportCard`. On the MITRE page the false-positive
checkbox is gone (nothing here is marked false positive) and the drill-down
links point at our incident and alert lists.

Not copied yet: `Dashboard`, `Alerts`, `SystemHealth`, `ThreatIntelPanel`,
`ExecutiveTiles`. Each is ported when its page is built.

## Attack path graph

`components/path/AttackPathGraph.tsx` draws the incident's graph with
react-force-graph-2d (as AI-SOC's correlation graph) but with a fixed
left-to-right layout from `lib/pathGraph.ts`: the source of step 1 on the
left, each target one column to the right, reach-next nodes after the node
they are reached from. Node colours follow AI-SOC's entity colours (attacker
rose, server green, internal host cyan, account violet, domain amber); size is
the asset's importance. Edges are labelled with the step number and coloured
by tactic; parallel steps between the same two nodes fan out. Reach-next nodes
and edges are dashed. Play highlights steps 1..N in order; the numbered
buttons jump to a step. Click a node for the entity drawer, an edge for that
step's evidence. PNG exports the canvas.

In tests the canvas library is replaced by `src/test/forceGraphStub.tsx`,
which renders nodes and edges as buttons with the same callbacks.
