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
  events.duckdb                       (track A internal) prepared event tables
  truth.parquet, metrics.json         (track A) silver truth and evaluation result;
                                      the API serves metrics.json at GET /metrics
```

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
| `risk_parts` | object | `severity, stage, breadth, success, asset, reach, threat_intel`, each `{value 0-1, weight, points}` |
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

### Graph

- **Node:** `id`, `label`, `kind` (`external_ip`, `internal_host`, `server`,
  `firewall`, `account`, `domain`), `zone` (`internet`, `dmz`, `server`,
  `desktop`, `iot`, `lan`, `mgmt`, `public`, `unknown`), `importance` 0-1;
  optional `reach` (`observed` | `inferred`) on nodes that are only reachable.
- **Edge:** `source`, `target` (node ids), `step` (int, null for reach edges),
  `technique`, `tactic`, `label` (`2. web sqli x60`), `kind` (`step`,
  `reach_observed`, `reach_inferred`).

### Reach next (`next`)

- `reachable[]`: `host`, `zone`, `hop` (1-2), `kind` (`observed` | `inferred`),
  `via[]` (`from`, `edge`, `count`, `lines`).
- `sentence`: one line for the UI.
- `likely_tactics`: heuristic list of the next tactics.

### Enrichment (`enrichment[value]`)

`kind` (`ip`, `domain`, `url`, `hash`), `zone`, `verdict` (`known-malicious`,
`suspicious`, `no-reports`, `unknown`), `reputation` 0-1, `providers[]`
(`provider`, `available`, `malicious`, `score`, `tags`, `detail`).

### Report (`report`)

`source` (`ai` | `template`), `markdown`, `triage` (`verdict`: `looks_real` |
`likely_noise`, `confidence`, `reasons[]`, nullable while there is no LLM).

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
