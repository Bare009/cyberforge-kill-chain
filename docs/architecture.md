# Architecture

One batch pipeline per data set tier, then a small API that serves the
precomputed results. Each stage reads the previous stage's files from `data/`,
so stages can be rerun on their own.

```
raw logs ──► parser ──► data/parsed/<run>/{firewall,windows}/*.parquet
                              │
               rules/*.yaml ──► detect ──► data/runs/<run>/detections.parquet
                              │
                          correlate ──► incidents (steps, entities, merged-alert count)
                              │
                 graph (path + reach-next) ──► score ──► report
                              │
                     data/runs/<run>/incidents/<id>.json + index.json
                              │
                         api (FastAPI) ──► web (React UI)

eval: detections + incidents vs the organisers' manifest → metrics.json
live: tails a growing log and reruns the stages on the new lines
```

## Folders

| Path | Holds | Status |
|---|---|---|
| `killchain/parser/` | Streaming raw-log parser (FortiGate key=value, JSON lines) | built |
| `killchain/attack/` | ATT&CK catalogue (from AI-SOC) and the tactic-to-stage order | catalogue copied |
| `killchain/detect/` | Rule engine that runs `rules/*.yaml` over the Parquet tables | planned |
| `killchain/correlate/` | Groups detections into incidents by shared entities and time | planned |
| `killchain/graph/` | Ordered attack paths, host/user graph, reach-next search | planned |
| `killchain/score/` | Per-incident risk score | planned |
| `killchain/report/` | Plain-English incident report (template; LLM optional) | planned |
| `killchain/api/` | FastAPI app: `/incidents`, `/incidents/{id}`, `/incidents/{id}/path`, `/mitre/matrix` | planned |
| `killchain/eval/` | Scoring harness against the manifest | planned |
| `killchain/live/` | Live mode (B-5) | planned |
| `rules/` | YAML detection rules, one file per rule | planned |
| `web/` | Trimmed AI-SOC React UI | planned |
| `tools/` | Developer checks, e.g. `verify_parse.py` | started |
| `docs/` | Requirements, architecture, data notes | started |
| `data/` | All inputs and outputs. Not committed (see `.gitignore`) | local only |

## Local data layout (not in git)

```
data/
  raw/        organisers' files (firex-*.log, *.win.jsonl, *.manifest.json)
  parsed/     parser output, one folder per run
  runs/       detections, incidents and metrics, one folder per run
```

## Contracts between stages

- **Parsed tables**: see the README section *Output*. Key columns are `ts`
  (UTC), `ts_quality`, `source`, `line`, `byte_offset`.
- **Detection** (one row per rule hit): rule id, technique, tactic, stage,
  first/last time, entity columns (`src_ip`, `dst_ip`, `user`, `host`,
  `domain`), count of raw events, and the list of `(source, line,
  byte_offset)` behind it.
- **Incident JSON**: id, risk score, merged-alert count, ordered steps (time,
  technique, tactic, stage, hosts, users, evidence lines), graph nodes and
  edges, reach-next list, report text.
