# Architecture

The detailed version, with contracts and phases, is in `docs/build-plan.md`.
This page is the overview.

```
data/raw/*.log
  │ 1 parse (built): multiprocess byte ranges → Parquet, ts_quality, parse_issue
  ▼
data/parsed/<run>/{firewall,windows}/*.parquet
  │ DuckDB view `events` (+ ts_valid, ts_ist, ist_hour, zones)
  │ 2 detect: rules/**/*.yaml compiled to DuckDB SQL
  │   specific rules (one per attack shape) + anomaly layer (generic detectors)
  ▼
alerts.parquet + alert_evidence.parquet   (every raw line behind every alert)
  │ 3 correlate: hub cap, link weights, time rule, union-find, promotion bar
  │ 4 chain: numbered steps 1..N, gaps, path graph
  │ 5 reach next: access graph (controls, admin_port, allowed_flow, inferred), BFS 2 hops
  │ 6 threat intel: local context + cached OTX, AbuseIPDB, VirusTotal, GreyNoise,
  │   abuse.ch, Shodan InternetDB, GeoIP (context only)
  │ 7 score + report: weighted risk score; template report
  │ 7b agents: checked narrator, triage opinion (display only); Q&A and rule writer on demand
  ▼
data/runs/<run>/incidents/<n>.json + index.json
  │ 8 API (FastAPI, files loaded at start)
  ▼
9 React UI (from AI-SOC): Dashboard, Incidents, Incident page with attack path graph,
  MITRE ATT&CK (ported as is), Alerts, Threat Intel, Rules, Live, Evaluation, System

eval: silver truth (or an organisers' manifest) vs alerts and incidents → metrics.json
live: tail a growing log, rerun stages 2-5 on recent windows, push changes to the UI
docker compose: pipeline, api, web (nginx), live
```

## Rules that hold across the pipeline

1. **Event time only.** Windows use the time in the logs. Rows with a bad
   `ts_quality` or a `parse_issue` stay out of time-window rules.
2. **Every result points to its raw lines** (`source`, `line`, `byte_offset`),
   for scoring and evidence.
3. **Deterministic core.** Detection, labels and incident membership come from
   rules and fixed logic. Threat intel and LLMs only add context and wording.
4. **No per-line cost beyond a column operation.** Network and LLM calls run
   per incident or per distinct entity.

## Technology

| Need | Choice | Why |
|---|---|---|
| Parsing | Python, pyarrow, 14 worker processes | Built: 6.54 GB in 55 s, 4.5 GB peak |
| Storage | Parquet (zstd) | Columnar, compact (497 MB for the 6.54 GB file), no server |
| Rules and queries | DuckDB over Parquet | SQL window functions, out-of-core, named in the PRD |
| Incident and attack graphs | NetworkX | Small graphs (thousands of alerts) |
| Detection format | Sigma-style YAML, five kinds (`match`, `count`, `distinct`, `sequence`, `sql`) | B-4: a new rule is a new file |
| Labels | MITRE ATT&CK Enterprise catalogue (691 techniques) | FR-3 |
| API | FastAPI | Precomputed files, millisecond responses |
| UI | React 19, Vite, Tailwind, Radix, react-force-graph-2d, recharts (the AI-SOC frontend, auth removed) | A UI as good as AI-SOC's; MITRE page reused as is |
| Packaging | Docker Compose | Judges start it from the README |
| LLM (optional) | OpenAI-compatible: Groq, NeevCloud fallback | Report wording, triage opinion, Q&A, rule drafts; all checked and cached |

## Folders

| Path | Holds |
|---|---|
| `killchain/parser/` | streaming parser (built) |
| `killchain/attack/` | ATT&CK catalogue, stage order, 7-phase map |
| `killchain/detect/` | rule engine and validator |
| `killchain/anomaly/` | helpers for the generic detectors |
| `killchain/correlate/` | incident builder |
| `killchain/graph/` | numbered chain, path graph, access graph, reach next |
| `killchain/enrich/` | local context and threat-intel providers with SQLite cache |
| `killchain/score/` | risk score and numbering |
| `killchain/report/` | template report |
| `killchain/agents/` | LLM client, narrator, triage opinion, Q&A, rule writer |
| `killchain/api/` | FastAPI app and bundle step |
| `killchain/eval/` | silver truth, manifest loader, metrics |
| `killchain/live/` | live mode |
| `config/` | `network.yaml`, `killchain.yml`, `rare_events.yaml` |
| `rules/` | `firewall/`, `anomaly/`, `windows/` |
| `eval/` | `silver_truth.yaml`, `reviewed.yml` |
| `web/` | React app (from AI-SOC), its Dockerfile and nginx config |
| `docker/`, `docker-compose.yml` | images for pipeline and API; Compose file |
| `examples/` | a small sample bundle so the UI runs on a fresh clone |
| `tools/` | parser checks, explorer |
| `data/` | raw, parsed, runs, cache (git-ignored) |
