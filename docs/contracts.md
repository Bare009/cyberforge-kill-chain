# Contracts between the two tracks

**Frozen on day 1.** These are the files track A (pipeline) writes and track B
(API and UI) reads. The source of truth is `killchain/contracts.py`; this page
explains it. A change needs agreement from both tracks and is made in one
commit together with `killchain/contracts.py` and `examples/sample-run/`.

Check any file against the contracts:

```python
from killchain.contracts import validate_bundle, validate_incident, validate_alert
errors = validate_bundle(incident, index, alerts)   # [] when valid
```

`tests/test_contracts.py` runs this on the sample.

## Conventions

- **Times:** `ts_*` fields are UTC, ISO 8601 with microseconds and a `Z`
  (`2026-10-29T01:51:23.000000Z`). `*_ist` fields are the same instant for
  display, `YYYY-MM-DD HH:MM:SS` in IST (+05:30). The UI shows IST.
- **Evidence:** a raw log line is `{source, line, byte_offset, ts}`. `line` is
  1-based, `byte_offset` 0-based, the same as the organisers' manifest. The API
  reads the raw text by seeking to `byte_offset` in `source`.
- **Techniques:** ATT&CK ids (`T1190`, `T1110.001`), or `unknown` for anomaly
  alerts without a label. Tactics are ATT&CK short names (`initial-access`).
- **Nulls:** a field marked nullable is present with `null`, never left out.

## Run layout

```
data/runs/<run>/                      (examples/sample-run/ has the same layout)
  index.json                          list of incidents for the list page
  incidents/<n>.json                  one file per incident (contract C)
  alerts.json                         every alert (contract B), list form for the API
  alerts.parquet                      same, for queries
  alert_evidence.parquet              every evidence line of every alert
  evidence_sample.json                (sample only) the evidence rows as JSON
  run_summary.json                    stage timings, memory, counts, data quality
  incidents.parquet                   (track A) correlation output, read by the bundle step
  incident_alerts.parquet             (track A) correlation output, read by the bundle step
  unexplained.parquet                 (track A) correlation output, read by the bundle step
  chains.json                         (track A) chain, gaps and path graph per incident, read by the bundle step
  incident_lines.parquet              (track A) every evidence line of every chain step; supporting
                                      alerts' lines carry the parent step's number
  chain/_stats.json                   (track A) chain stage timings and counts
  access_graph.parquet                (track A) access graph edges: src, dst, kind, strength, count, ports, lines
  access_hosts.parquet                (track A) every internal IP in the logs with zone, role, /24, event count
  reach.json                          (track A) footholds, reach next and merged path graph per incident
  reach/_stats.json                   (track A) reach stage timings and counts
  score.json                          (track A) per incident_id: number_before, incident_number, risk score,
                                      band and parts; threat_intel_source (enrichment.json or null), offline
  score/_stats.json                   (track A) score stage timings, bands
  report/_stats.json                  (track A) report stage timings, markdown size
  enrichment.json                     (track B, enrich) threat intel per entity, read by score and bundle
  report.json                         (track B, narrator) {incidents: {incident_id: {source, markdown, triage}}}
  unexplained.json                    (bundle) anomaly alerts in no incident, alert rows plus reason, group_id
  ti.json                             (bundle) enrichment.json bound to the current incident numbers
  bundle/_stats.json                  (bundle) stage timing
  live/status.json                    (track A, P15; proposed) the live process's state, read by the API
  events.duckdb                       (track A internal) prepared event tables
  truth.parquet, metrics.json         (track A) silver truth and evaluation result;
                                      the API serves metrics.json at GET /metrics
```

Stage order: `detect → correlate → chain → reach → score → report`, then the bundle step.
`python -m killchain chain` writes provisional `incidents/<n>.json`, `index.json` and `alerts.json` (with
`incident_number` filled); their risk, threat intel, report and reach next fields are contract-valid
placeholders. `python -m killchain reach` then rewrites them with the real reach next and the path graph
merged with reach nodes and edges. `chain` and `reach` reset risk and report to placeholders, so `score`
and `report` run after them. `python -m killchain score` fills the risk fields and renumbers the bundle
by risk (`incidents/<n>.json`, `index.json`, `alerts.json`: bundle numbers = risk rank). The
intermediates (`incidents.parquet`, `incident_alerts.parquet`, `chains.json`, `reach.json`,
`incident_lines.parquet`) keep correlate's numbers; join on `incident_id` (`score.json` maps the two).
`python -m killchain report` writes the template report. The P11 bundle step
(`python -m killchain.bundle --run <run>`) runs last and is the final writer of these files: it merges
threat intel and reports in and writes the bundle-only files above. It never changes detection fields.
It binds `enrichment.json` to incidents by value; a run served without the bundle step needs
`python -m killchain.enrich` re-run after `score`, because enrich's per-incident lists use the numbers
of the moment.

## Contract B: alert

One rule hit, in the shape of an OCSF Detection Finding.

| Field | Type | Meaning |
|---|---|---|
| `alert_id` | string | stable hash of rule, group key and first time |
| `rule_id` | string | the rule file's `id` |
| `layer` | `rule` \| `anomaly` | specific rule or generic detector |
| `title` | string | rule title |
| `technique` | string | primary ATT&CK technique, or `unknown` |
| `alt_techniques` | list of strings | other acceptable ids (parent, alternates) |
| `technique_name` | string, nullable | from the ATT&CK catalogue |
| `tactic` | string | one of the 14 ATT&CK tactics |
| `stage_no` | int 1-14 | tactic order (reconnaissance 1 ... impact 14) |
| `kill_chain_stage` | string | 7-phase label (`Reconnaissance`, `Weaponization`, `Delivery`, `Exploitation`, `Installation`, `Command and Control`, `Actions on Objectives`) |
| `severity` | int 1-5 | |
| `confidence` | number 0-1 | |
| `ts_start`, `ts_end` | UTC time | first and last member event |
| `src_ip`, `dst_ip`, `host`, `user`, `domain`, `url` | string, nullable | entities |
| `event_count` | int | raw events behind the alert |
| `blocked_share` | number 0-1 | share of events denied, dropped or blocked |
| `success` | bool | any event got through |
| `summary`, `action_text` | string | one sentence on what the attacker did |
| `incident_number` | int, nullable | incident it belongs to; null if none |

`alert_evidence.parquet`: `alert_id, source, line, byte_offset, ts, technique,
role` (`trigger` | `window` | `context`). Every member line is listed.

## Contract C: incident (`incidents/<n>.json`)

| Field | Type | Meaning |
|---|---|---|
| `incident_number` | int | 1..N by risk, worst first; used in URLs (`/incidents/12/path`) |
| `incident_id` | string | stable hash of the member alert ids |
| `title` | string | |
| `risk_score` | number 0-100 | sum of `risk_parts[*].points` |
| `risk_band` | `critical` \| `high` \| `medium` \| `low` | ≥ 75, ≥ 50, ≥ 25, below |
| `risk_parts` | object | `severity, stage, breadth, success, asset, reach, threat_intel`, each `{value 0-1, weight, points}` and an optional `detail` (string: why the part has its value); see "Risk score" below |
| `severity` | int 1-5 | highest alert severity |
| `ts_start`, `ts_end`, `ts_start_ist`, `ts_end_ist` | times | |
| `merged` | `{alerts, events}` | raw alerts and events merged into the incident (B-3) |
| `entities` | `{ips, hosts, users, domains}` | lists of strings |
| `tactics`, `techniques` | lists | in chain order |
| `chain_text` | string | `1. Reconnaissance → 2. Initial Access → ...` |
| `chain` | list of steps | below |
| `gaps` | list of strings | phases with no evidence; never numbered |
| `graph` | `{nodes, edges}` | below |
| `enrichment` | object | entity value → threat-intel result (below) |
| `next` | `{reachable, sentence, likely_tactics}` | reach next (below) |
| `report` | `{source, markdown, triage}` | narrator or template report, triage opinion |
| `report_source` | `ai` \| `template` | |
| `layers` | list | `rule`, `anomaly` |

### Step (`chain[]`)

`n` (1..N, in order), `ts_start`, `ts_end`, `ts_start_ist`, `ts_end_ist`,
`ongoing` (runs past later steps), `action` (sentence), `rule_id`, `alert_id`,
`technique`, `technique_name`, `tactic`, `stage_no`, `kill_chain_stage`, `src`,
`dst`, `event_count`, `success`, `line_sample` (up to 20 evidence lines),
`line_total`, `enrichment_flags` (short strings), `confidence`, `layer`.
`ts_start` never decreases along the chain.

Optional `supporting` (list, `[]` when none): anomaly alerts shown as evidence
for this step. Each entry has `alert_id`, `rule_id`, `layer`, `title`,
`action`, `technique`, `technique_name` (nullable), `tactic`, `stage_no`,
`kill_chain_stage`, `ts_start`, `ts_end`, `ts_start_ist`, `ts_end_ist`, `src`
(nullable), `dst` (nullable), `event_count`, `success`, `line_total`,
`confidence` and `relation` (`during` | `before` | `after` the step), filled
like the step fields of the same name. When an incident has a rule-layer
alert, only rule alerts are numbered and every anomaly alert is attached to one
rule step; an incident with only anomaly alerts numbers them and has empty
`supporting` lists. An anomaly goes to the rule step that first shares an
entity (`src_ip`, `dst_ip`, `user`, `host`, `domain`), then has the smallest
time gap (0 when the ranges overlap or touch), then the same tactic, then the
nearest start, then the lower `n`. An alert id appears at most once across all
steps and supporting entries, and every supporting `alert_id` is in
`alerts.json`.

`supporting`, the edge flag below and the risk part `detail` were added after
day 1 as optional, backward-compatible fields, agreed with the user for both tracks.
`examples/sample-run/` predates them and stays valid.

### Graph

- **Node:** `id`, `label`, `kind` (`external_ip`, `internal_host`, `server`,
  `firewall`, `account`, `domain`), `zone` (`internet`, `dmz`, `server`,
  `desktop`, `iot`, `lan`, `mgmt`, `public`, `unknown`), `importance` 0-1;
  optional `reach` (`observed` | `inferred`) on nodes that are only reachable.
- **Edge:** `source`, `target` (node ids), `step` (int, null for reach edges),
  `technique`, `tactic`, `label` (`2. web sqli x60`), `kind` (`step`,
  `reach_observed`, `reach_inferred`); optional `supporting` (bool, `true`
  only on edges drawn for a supporting anomaly: `step` is the parent step's
  number, `technique`/`tactic` are the anomaly's, the label ends in
  ` (anomaly)`).

### Reach next (`next`)

- `reachable[]`: `host`, `zone`, `hop` (1-2), `kind` (`observed` | `inferred`),
  `via[]` (`from`, `edge`, `count`, `lines`).
- `sentence`: one line for the UI.
- `likely_tactics`: heuristic list of the next tactics.

### Enrichment (`enrichment[value]`)

`kind` (`ip`, `domain`, `url`, `hash`), `zone`, `verdict` (`known-malicious`,
`suspicious`, `no-reports`, `unknown`), `reputation` 0-1, `providers[]`
(`provider`, `available`, `malicious`, `score`, `tags`, `detail`).

### Risk score (`risk_score`, `risk_band`, `risk_parts`)

Written by `python -m killchain score` (`killchain/score/risk.py`). Fixed weights; each part is
`{value 0-1 (4 dp), weight, points = round(value × weight × 100, 2), detail}`, `risk_score` = sum of the
points (1 dp). "Steps" are the numbered `chain[]` steps; supporting anomalies do not raise stage,
breadth or success.

| Part | Weight | Value |
|---|---|---|
| `severity` | 0.25 | incident `severity` / 5 (highest alert severity) |
| `stage` | 0.20 | highest step `stage_no` / 14 |
| `breadth` | 0.10 | 1 when there are 3 or more distinct step tactics, else distinct step tactics / 6 |
| `success` | 0.15 | 1 when any step got through, else 0 |
| `asset` | 0.15 | highest `importance` among graph nodes of kind `internal_host`, `server` or `firewall` without a `reach` key; 0 when none |
| `reach` | 0.10 | important reachable hosts (importance ≥ 0.75: server, DMZ, management) / 3, capped at 1; observed count 1, inferred 0.5 |
| `threat_intel` | 0.05 | highest `reputation` among `enrichment.json` entities whose value is in the incident (entities, step and supporting `src`/`dst`) and whose verdict is not `unknown`; 0 when none match; 0 when `enrichment.json` is missing (the `detail` says so) |

Bands: `critical` ≥ 75, `high` ≥ 50, `medium` ≥ 25, else `low`. Incidents are numbered 1..N by
`(-risk_score, ts_start, incident_id)`. Threat intel is matched by value, never by enrich's incident
numbers, so renumbering cannot misplace it.

### Report (`report`)

`source` (`ai` | `template`), `markdown`, `triage` (`verdict`: `looks_real` |
`likely_noise`, `confidence`, `reasons[]`, nullable while there is no LLM).

`python -m killchain report` writes `source: template`, `triage: null` and `report_source: template`.
The template markdown has these sections, in order: `## Summary` (one sentence), `## Risk` (score and
the parts table with each `detail`), `## Attack chain` (numbered steps with IST times, supporting
anomalies as sub-bullets), `## Gaps`, `## Reach next`, `## Entities`, `## Threat intel`, `## Evidence`
(up to 5 lines per step with line and byte offset), `## Recommended actions` (one per tactic, in chain
order). It is built only from the incident's facts and stays the fallback when the narrator
(`source: ai`) is not available.

## `index.json`

`{run, incidents[]}`, each row: `incident_number`, `incident_id`, `title`,
`risk_score`, `risk_band`, `severity`, `ts_start`, `ts_end`, `ts_start_ist`,
`ts_end_ist`, `merged`, `tactics`, `techniques`, `triage_verdict` (nullable),
`ti_verdict` (nullable). Sorted by `incident_number`.

## The sample run

`examples/sample-run/` holds incident 1: chain A (`32.127.48.11` against the
portal `10.10.20.20` on 29 Oct): port sweep (240 events), SQL injection (60),
web shell (40), large transfer (600). Times, counts, line numbers and byte
offsets are real, made by `tools/make_sample_run.py` from the parsed log. The
risk score, threat intel, reach next and report are placeholders in the right
shape, and every file carries `"sample": true` where it applies.
Rebuild with `python tools/make_sample_run.py`.

## Live mode: `live/status.json` (proposed by track B, to agree with track A)

The live process (`python -m killchain live`, P15) rewrites the run's bundle files as new
alerts and incidents appear, the same way the bundle step does (whole files, replaced by
rename). The API watches those files and reloads them; it needs nothing else for the UI to
update. For the Live page the process also keeps `<run>/live/status.json` current, rewriting
it (by rename) at least every 5 s while it runs:

| Field | Type | Meaning |
|---|---|---|
| `state` | `running` \| `stopped` | `stopped` written once on a clean exit |
| `updated_at` | UTC time | when this file was written; older than 15 s reads as "stale" |
| `source` | string | log file being tailed |
| `offset`, `size` | int | bytes read so far, and the file's size |
| `lines_total` | int | lines read since the start |
| `lines_per_sec` | number | over the last poll |
| `last_line_ts` | UTC time, nullable | event time of the newest parsed line |

Extra fields are shown as they are; every field but `state` and `updated_at` may be missing.
