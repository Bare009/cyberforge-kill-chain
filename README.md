# killchain

Kill chain and attack path analysis over large security log sets (CyberForge PRD
"Kill Chain and Attack Path Analysis"). Built in stages; this README grows with
each one.

| Stage | Status |
|---|---|
| 1. Streaming log parser (FR-1) | done: `killchain.parser` |
| 1b. DuckDB event views, `python -m killchain`, explorer | done: `killchain.db`, `tools/explore.py` |
| 1c. Evaluation: silver truth (25 incidents) and the PRD metrics | done: `killchain.eval` |
| 2a. ATT&CK labels and the rule engine (5 kinds, validator) | done: `killchain.attack`, `killchain.detect`; rules format in `rules/README.md` |
| 2b. Rules for every planted incident (FR-2, FR-3, B-4) | done: 24 rules in `rules/firewall/`; on firex-10G all 25 incidents found, 0 background alerts, 2 s |
| 2c. Anomaly layer (11 detectors, `rules/anomaly/`) | done: generic `kind: sql` detectors, `layer: anomaly`, confidence 0.3-0.5, never promoted; on firex-10G 25 anomaly alerts (rare 6, first-seen pair 1, user-country 4, outlier sessions 3, destinations 3, ports 0, failed logins 0, bytes out 2, denied-then-allowed 1, lopsided 3, too regular 2), 0 background, 10,289 evidence lines; the 32 rule alerts unchanged; recall 100%, labels 100%, false alarms 0%; detection 6.1 s for all 35 rules |
| 3. Incidents, attack paths, reach-next (FR-4 to FR-6) | planned |
| 4. API and UI (FR-7) | in progress: `killchain.api` (health, incidents, path), `web/` scaffold |
| 5. Scoring harness against the ground-truth manifest | planned |

Requirements and targets: `docs/requirements.md`. Pipeline and stage
contracts: `docs/architecture.md`. What the organisers' data looks like:
`docs/data-notes.md`.

## Layout

```
killchain/          Python package, one sub-package per pipeline stage
  parser/           raw logs -> Parquet (built)
  contracts.py      alert and incident formats shared by both tracks (frozen)
  attack/           ATT&CK catalogue and kill chain stage order
  detect/           YAML rule engine
  anomaly/          generic detectors for attacks no rule covers
  correlate/        incident builder
  graph/            attack paths and reach-next
  score/            risk score
  report/           template reports when no LLM is reachable
  enrich/           local context and threat intel
  agents/           LLM narrator with triage opinion, Q&A, rule writer
  api/              FastAPI app
  eval/             scoring against the silver truth or a manifest
  live/             live mode
config/             network zones and hubs, kill chain stage order
rules/              detection rules: firewall/, anomaly/, windows/
eval/               silver truth and reviewed incidents
examples/           sample-run/: one real incident in the contract format
web/                React UI (from AI-SOC)
docker/             images for the pipeline and the API
tools/              developer checks and the sample-run builder
tests/              pytest suite
docs/               plan, contracts, requirements, architecture, data notes
data/               local inputs and outputs, never committed
```

The two people building this work in parallel tracks; see
`docs/build-plan.md` section 5. The files they exchange are defined in
`docs/contracts.md`, and `examples/sample-run/` is a valid example of them.

## Setup

Python 3.11 or newer.

```powershell
pip install -r requirements.txt
copy .env.example .env      # optional keys for threat intel and the LLM agents
python -m pytest -q         # contract and sample checks
```

Put the organisers' files under `data/raw/` (for example
`data/raw/firex-10G.log`). `data/` is ignored by git.

## Stage 1: parse raw logs into Parquet

```powershell
python -m killchain.parser data\raw\firex-10G.log --out data\parsed\firex-10G
```

Useful options: `--workers N` (default: CPUs minus 2, at most 14), `--max-mb 512`
to parse only the start of a file, `--start BYTES` to begin further in (line
numbers stay correct), `--overwrite` to replace an earlier run. `--help` lists
the rest.

Each input file is split into byte ranges that start on line boundaries. A first
parallel pass counts newlines so every row carries its true line number; worker
processes then parse the ranges and write Parquet parts. No process holds more
than one 16 MB read block plus one 65,536-row batch, so memory does not grow
with file size.

### Output

```
data/parsed/<name>/
  firewall/part-*.parquet   FortiGate key=value lines
  windows/part-*.parquet    JSON lines (Windows events, ECS/EDR exports)
  _stats.json               counts, timings, peak memory, junk byte ranges, samples of rejected lines
```

Columns in both tables:

| Column | Meaning |
|---|---|
| `ts` | event time, UTC, microseconds |
| `ts_quality` | `ok`, `stuck`, `backwards`, `eventtime_mismatch`, `date_missing`, `missing`, `tz_assumed` |
| `source`, `line`, `byte_offset` | file name, 1-based line number, 0-based byte offset of the line start |
| `line_hash` | 64-bit BLAKE2b of the raw line, for duplicate checks |
| `parse_issue` | empty for clean lines; otherwise `truncated_binary_tail`, `stray_text`, `duplicate_key`, `bad_number` or `bad_time` (comma-separated) |
| `extra` | JSON object with every key that has no column of its own, plus what a flagged line would otherwise lose (`_dropped_bytes`, `_stray`, `_dup_<key>`, `_bad_<column>`) |

`line` and `byte_offset` use the same conventions as the organisers' manifest
(`at: [line, byte, stream]`), so detections can be scored against it exactly.
The raw line is not stored; seek to `byte_offset` to show it as evidence.

`firewall` renames FortiGate keys to snake_case: `srcip` becomes `src_ip`,
`dstport` becomes `dst_port`, `logdesc` becomes `log_desc`, `sentbyte` becomes
`sent_bytes`, and so on (see `FIELDS` in `killchain/parser/fortigate.py`).
`windows` maps common Windows/ECS paths to columns such as `event_id`, `host`,
`target_user`, `logon_type`, `src_ip`, `service_name`, `share_name`,
`relative_target` and `ticket_encryption` (see `ALIASES` in
`killchain/parser/jsonlog.py`). No sample of the organisers' Windows stream has
been shared yet, so that mapping is provisional.

### Data problems the parser handles

Found in `firex-10G.log`, the organisers' 6.5 GB file:

| Bytes | Content | Handling |
|---|---|---|
| 0 to 2.03 GB | 3.85 M FortiGate lines, 7 days, in time order | parsed, `ts_quality=ok` |
| 2.03 to 4.82 GB | 5.28 M lines whose clock is stuck at the window end (2026-10-30 08:48:25.999999 +0530) | parsed, `ts_quality=stuck`; detection rules must skip these rows |
| 4.82 to 6.54 GB | 1,602 Debian `.deb` packages appended to the log | rejected as `binary`, reported as one junk range; the last text line, cut off by the first package, is kept with `parse_issue=truncated_binary_tail` |

Other details:

- `eventtime` holds the local wall clock as if it were UTC (it is exactly `tz`
  ahead of `date`+`time`). The parser checks both readings against
  `date`+`time` and keeps the one that agrees, which preserves sub-second
  precision.
- A line never stops the run: malformed lines are counted by reason, sampled in
  `_stats.json`, and coalesced into byte ranges.

### Measured speed

Windows 11, 16 logical CPUs, 14 workers, file in the OS cache:

| Run | Wall time | Peak RSS (all processes) |
|---|---|---|
| full `firex-10G.log` (6.54 GB, 15.8 M lines, 9.1 M rows) | 55 s | 4.5 GB |
| first 512 MB (1.02 M lines) | 5.1 s, of which about 3 s is worker start-up | 3.7 GB |

Peak memory depends on the number of workers, not on the file size. Output for
the full file is 497 MB of Parquet.

### Check a run

```powershell
python tools\verify_parse.py data\parsed\firex-10G firewall 2000
python tools\audit_parse.py data\raw\firex-10G.log data\parsed\firex-10G 30000
python tools\test_parser_edges.py
```

- `verify_parse.py` re-reads sampled rows from the source file at `byte_offset`
  and checks the line hash, the line number and the main columns.
- `audit_parse.py` checks independently of the parser's code: a full-file scan
  counts every line, line numbers and offsets are checked over the whole table,
  every column of a random sample is compared with a separate tokenizer,
  timestamps are recomputed, and the stuck-clock flags are compared with the
  frozen value. Results go to `_audit.json`. On `firex-10G.log`: 0 lines lost,
  0 mismatches in 1.35 M field checks.
- `test_parser_edges.py` parses a small file with every damaged-line case and
  checks the flags and the values kept in `extra`.

## Query a parsed run

Every stage reads the parsed Parquet through DuckDB views (`killchain/db.py`).
The session runs in UTC; IST is a derived column.

```powershell
python -m killchain              # list the stages and which are ready
python -m killchain db --parsed data\parsed\firex-10G          # counts, time range, zones
python -m killchain db --parsed data\parsed\firex-10G --sql "SELECT src_zone, count(*) FROM events WHERE ts_valid GROUP BY 1"
python tools\explore.py data\parsed\firex-10G --where "log_desc = 'Admin login successful'" --cols ts_ist,src_ip,user,src_country
python tools\explore.py data\parsed\firex-10G --where "log_desc = 'Admin login failed' AND NOT src_internal" --group src_net24 --top 10
python tools\explore.py data\parsed\firex-10G --around "2026-10-29 01:51:00" --minutes 5 --where "src_ip = '32.127.48.11'" --raw 3
```

Views: `events` (the firewall table), `firewall_events`, `windows_events`. On
top of the parser's columns they add:

| Column | Meaning |
|---|---|
| `ts_valid` | usable for time windows: `ts_quality` is `ok` or `tz_assumed`, and no `parse_issue` |
| `ts_utc`, `ts_ist` | the event time as plain UTC, and in IST |
| `ist_hour` | hour of `ts_ist`, 0-23 |
| `src_internal`, `dst_internal` | address is in a private range |
| `src_zone`, `dst_zone`, `src_role`, `dst_role`, `src_importance`, `dst_importance` | from `config/network.yaml` |
| `src_net24`, `dst_net24` | the address's /24 |

On `firex-10G.log`: 9,125,383 rows, 3,848,247 with `ts_valid`.

The views compute the zone columns on every query, which takes 10-35 s on the
full file. For repeated work, prepare the run once (58 s, 779 MB on disk):

```powershell
python -m killchain db --parsed data\parsed\firex-10G --prepare      # writes data\runs\firex-10G\events.duckdb
python -m killchain db --run data\runs\firex-10G --sql "SELECT src_zone, count(*) FROM events WHERE ts_valid GROUP BY 1"
```

Later stages use the prepared file automatically when it exists; queries on it
take milliseconds.

## Evaluate a run

The PRD's seven metrics, measured against the planted attacks:

```powershell
python -m killchain eval silver --parsed data\parsed\firex-10G     # build the silver truth, check every count
python -m killchain eval score --run data\runs\firex-10G --parsed data\parsed\firex-10G
python -m killchain eval score --run data\runs\firex-10G --manifest data\raw\<manifest>.json --raw firewall=data\raw\<log>
python -m killchain eval score --run data\runs\firex-10G --api http://localhost:8000   # also time GET /incidents/{n}/path
```

- **Silver truth** (`eval/silver_truth.yaml`): the 25 planted incidents found by
  hand in `firex-10G.log`, each step a SQL condition with its exact line count.
  `eval silver` checks every count (32,200 lines, all 32 steps match) and writes
  `truth.parquet` into the run folder.
- **Manifest:** an organisers' manifest is used as is; one whose byte offsets do
  not point at line starts of the given log is refused rather than scored as zero.
- **Output:** a table with each metric's value and grade against the PRD's Good
  and Great targets, label accuracy three ways (exact, parent technique, any
  accepted alternate), the incidents not found, attack paths and whether they
  were rebuilt in order, false alarms (with `eval/reviewed.yml` for incidents
  confirmed real or false by hand), and alerts per rule split into truth hits
  and background. Everything is also in `metrics.json`.

## API

Serves one run bundle (`docs/contracts.md`) over HTTP, no login. Every file
is loaded once at start-up, so a request is a dictionary lookup.

```powershell
python -m killchain.api --run sample-run --port 8000   # the committed sample
python -m killchain.api --run data\runs\firex-10G      # a pipeline run
```

`--run` takes a folder or a run name, looked up in `data/runs/<name>` and then
`examples/<name>`; without it, `KILLCHAIN_RUN` or `sample-run` is used. Use
`--host 0.0.0.0` inside Docker. If port 8000 is taken (Splunk uses it), pick
another with `--port` and set `VITE_API_URL` in `web/.env` to match.
Swagger UI: `http://localhost:<port>/docs`.

| Endpoint | Returns |
|---|---|
| `GET /health` | run name, counts, contract problems found while loading |
| `GET /incidents` | incidents worst first; filters `severity` (minimum), `tactic`, `technique` (a parent matches its sub-techniques), `entity`, `q`, `limit`, `offset` |
| `GET /incidents/{id}` | the full incident; `id` is the number or the stable hash |
| `GET /incidents/{id}/path` | numbered chain, attack path graph, reach next |
| `GET /mitre/catalogue` | the ATT&CK release behind the matrix, with MITRE's attribution |
| `GET /mitre/matrix` | tactic x technique alert counts (same shape as AI-SOC); `preset` `24h`/`7d`/`30d`/`90d` counts back from the run's last alert, or `start`+`end`; filters `severity`, `status` (`open` = not in an incident, `correlated`), `source` (`rule`, `anomaly`) |
| `GET /mitre/techniques/{id}` | one technique: trend by IST day, sub-techniques, alerts per rule and target, recent alerts with their incident |

The MITRE endpoints run DuckDB `GROUP BY` queries over the run's alerts
(`killchain/api/mitre.py`). The other endpoints in `docs/build-plan.md` P11
are added as their pages are built. `GET /incidents/1/path` on the sample: p50 20 ms, p95 27 ms over HTTP
from PowerShell on Windows (target p95 < 500 ms).
