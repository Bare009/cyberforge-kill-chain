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
```

The status bar shows whether the API answers `GET /health`.

## Pages

Routes follow `docs/build-plan.md` P12. Pages not built yet show a placeholder
saying when they are planned.

| Route | Page | State |
|---|---|---|
| `/` | Dashboard | placeholder (day 5) |
| `/incidents` | Incident list | placeholder (day 2) |
| `/incidents/:id` | Incident page | placeholder (days 2-3) |
| `/mitre` | ATT&CK matrix | ported from AI-SOC; needs the P11 `/mitre/*` endpoints |
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

Not copied yet: the AI-SOC pages the plan builds from (`Dashboard`,
`CorrelationGraph`, `command-center/CommandCenter`, `Alerts`,
`SystemHealth`, `ThreatIntelPanel`, `ExecutiveTiles`, `IncidentReportCard`).
Each is ported when its page is built, because they call AI-SOC's API and
need rewiring to ours.
