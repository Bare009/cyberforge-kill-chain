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
| `/` | Dashboard | placeholder (day 5) |
| `/incidents` | Incident list | built: worst first, risk bar, tactic chips in kill chain order, merged alerts and events, IST times, filters in the URL (`q`, `tactic`, `technique`, `entity`, `severity`) |
| `/incidents/:id` | Incident page | header (summary, risk parts, merged counts) and tabs; Timeline (numbered chain and gaps), Report and ATT&CK built; Attack path, Reach next, Evidence (day 3), Threat intel (day 4), Ask (day 6) say when they arrive. `?tab=` opens a tab |
| `/mitre` | ATT&CK matrix | ported from AI-SOC; `?technique=T1190` opens a technique; links go to `/incidents?...` and `/alerts?...` |
| `/alerts` | Alerts | placeholder (day 5) |
| `/threat-intel` | Threat Intel | placeholder (day 4) |
| `/rules` | Rules | placeholder (day 5) |
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
