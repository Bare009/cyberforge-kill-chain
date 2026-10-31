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
| 3a. Correlation (FR-4, B-3) | done: `killchain.correlate`, `python -m killchain correlate --run <run>`, settings in `config/correlate.yaml`; on firex-10G 57 alerts become 25 incidents (24 anomaly alerts joined as supporting evidence, 1 unexplained, 0 below the bar, largest 8 alerts), chain A (32.127.48.11, R02 > R16 > R20 > R12) and chain B (10.10.10.118, R24 > R11 > R12) each one incident; attack paths 25/25, multi-step 4/4, no incident spans two truth incidents; recall 100%, labels 100%, false alarms 0%; 0.1 s |
| 3b. Attack chains, path graphs, reach-next (FR-5, FR-6) | chains and path graphs done (P7): `killchain.graph`, `python -m killchain chain --run <run> [N]`; only rule alerts are numbered, each anomaly alert is `supporting` evidence on the nearest rule step (shared entity, then time overlap, then same tactic, then nearest start) and is still drawn in the path graph; an anomaly-only incident numbers its anomaly alerts; on firex-10G 25 incidents, 32 numbered steps (2 ongoing), 24 supporting, 19 gaps, 44,622 evidence lines, 0 contract errors in 0.28 s; chain A reads `1. Discovery → 2. Initial Access → 3. Persistence → 4. Exfiltration` (R02 > R16 > R20 > R12), chain B `1. Execution → 2. Command and Control → 3. Exfiltration` (R24 > R11 > R12); writes provisional `incidents/<n>.json`, `index.json`, `alerts.json` (risk, threat intel and report are placeholders); recall 100%, labels 100%, attack paths 25/25 (multi-step 4/4), false alarms 0%. Access graph and reach next done (P8): `python -m killchain reach --run <run> [N] [--parsed DIR] [--force]`, settings in `config/reach.yaml`; on firex-10G the access graph has 3 `controls` edges (svc_backup30, parul.sinha, Deepika.Khan to the firewall 10.10.99.1) and 90 `admin_port` edges from 10.10.10.44 and 10.10.10.63 (2,580 sessions), 1,387 internal hosts, built in 0.7 s; 11 incidents get a reach list (83 hosts), 14 a stated reason; incidents #3, #6, #11 say the account controls the firewall; chain A (#1) lists inferred 10.10.20.x servers, chain B (#2) is empty with its reason; 0 contract errors, stage 1.2 s; metrics unchanged. Desktop reach (Track A item 2): `neighbour_zones` now includes `desktop`, so a desktop foothold gets its subnet neighbours (inferred, 0 reach points) and the servers they reach at hop 2 (inferred, half points); on firex-10G 15 incidents get a reach list, 10 a stated reason; chain B and the other desktop footholds (10.10.10.112, 10.10.10.88, 10.10.10.51) each list 10 inferred 10.10.20.x servers |
| 3c. Risk score and template report (B-1, B-2) | done (P10): `killchain.score`, `killchain.report`; `python -m killchain score --run <run> [N]` (fixed weights severity 0.25, stage 0.20, breadth 0.10, success 0.15, asset 0.15, reach 0.10, threat intel 0.05; each part stored with a `detail`; incidents renumbered 1..N by risk) and `python -m killchain report --run <run> [N]` (Markdown: summary, risk table, numbered chain with IST times, gaps, reach next, entities, threat intel, 5 evidence lines per step, actions per tactic); breadth is full at 3 or more distinct tactics, else tactics / 6 (Track A item 2); on firex-10G 25 incidents: critical 3, high 17, medium 5; chain A #1 89.8, chain B #2 82.3, large one-way transfer #3 81.5, lone port scan #24 45.8; R24 step text names the malware (`JS/Nemucod.A!tr.dldr`); threat intel 0 for every incident (offline enrich: 58 indicators, all `unknown`); 25 template reports (73,066 characters); 0 contract errors; score 0.05 s, report 0.04 s; recall 100%, labels 100%, attack paths 25/25 (multi-step 4/4), false alarms 0% |
| 4. API and UI (FR-7) | in progress: `killchain.api` (health, incidents, path), `web/` scaffold |
| 5. Scoring harness against the ground-truth manifest | done: `eval score --manifest` on firex-30G (37.2 M events, 29 planted incidents): recall 99.0%, labels 94.9%, attack paths 79.3% (23/29), false alarms 0%, 10 min 1 s, 2.4 GB, open p95 3 ms. Not found: the 4 Windows-only incidents (#24-27), and the 2 chains miss their Windows steps, because the Windows log (`firex-30G.win.jsonl`, 10.4 GB) was not supplied |
| 6. One-command run (P13) | done: `python -m killchain run --input <log> [--name N] [--offline] [--no-llm] [--reuse-parsed] [--from STAGE]` (see [Full run](#full-run)); exit codes 0 done, 1 a required stage failed, 2 usage or input error, 3 no events in the input; on firex-10G with `--offline --no-llm`: 187 s end to end with a cold file cache (parse 88.6 s, prepare 58.7 s, detect 16.4 s, the other stages 1.6-4.6 s each), peak 6.2 GB (during prepare); 25 incidents, recall 100%, labels 100%, attack paths 25/25 (multi-step 4/4), false alarms 0%; the 50 GB tier run is still to do |

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
  bundle/           last stage: merges every stage's output into the files the API serves
  api/              FastAPI app
  eval/             scoring against the silver truth or a manifest
  live/             live mode
config/             network zones and hubs, kill chain stage order
rules/              detection rules: firewall/, anomaly/, windows/
eval/               silver truth and reviewed incidents
examples/           sample-run/: one real incident in the contract format
web/                React UI (from AI-SOC)
docker/             Dockerfile (pipeline and api targets), pipeline.sh (every stage for one log)
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

## Docker

Docker Desktop (or Docker Engine with Compose v2.24 or newer). `.env` is optional.

```powershell
docker compose up -d --build                      # UI http://localhost:8080, API http://localhost:8000/docs
$env:KILLCHAIN_RUN = "firex-10G"; docker compose up -d   # serve data/runs/firex-10G instead of the sample
docker compose down
```

| Service | Image | Does |
|---|---|---|
| `api` | `docker/Dockerfile` target `api` | serves `data/runs/$KILLCHAIN_RUN` (else `examples/sample-run`) on 8000; reloads it when its files change |
| `web` | `web/Dockerfile` (node build, nginx) | the UI on 8080; proxies `/api/` to `api`, the live stream unbuffered |
| `pipeline` | `docker/Dockerfile` target `pipeline` | one stage: `docker compose run --rm pipeline detect --run data/runs/firex-10G` |
| `pipeline-all` | same | every stage for one log: `docker compose run --rm pipeline-all firex-10G.log` (parse → db → detect → correlate → chain → reach → enrich → score → report → [narrate] → bundle) |
| `live` | same, profile `live` | `python -m killchain live` (P15); needs `--input <log>` or `KILLCHAIN_LIVE_INPUT`, and a run folder of its own (see [Live mode](#live-mode)) |
| `live-ingest` | same, profile `live` | live mode over `data/ingest/live.log` into `data/runs/live-ingest` (see [SIEM connections](#siem-connections)) |

Mounts: `./data` (the api reads it read-only, except `data/cache`,
`data/connectors` and `data/ingest`), `./rules`
(rules saved from the rule writer land here), and the logs folder at
`/app/logs`, read-only (`LOGS_DIR`, default `./logs`). Without the logs the
Evidence tab lists line numbers but no raw text. Other settings: `API_PORT`
(8000; use another when Splunk holds 8000), `WEB_PORT` (8080),
`PARSE_WORKERS` (4; more workers need more memory), `TI_OFFLINE=1`.
The build context leaves out `data/`, `logs/` and every log file, so images stay
small (api 690 MB, web 50 MB) whatever sits in those folders.

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
  `truth.parquet` into the run folder. It names the 10G file's addresses, so it
  does not fit another file (on firex-30G it matches 5 incidents and reads the
  other 21 as false alarms); score other files with their manifest.
- **Manifest:** an organisers' manifest is used as is; one whose byte offsets do
  not point at line starts of the given log is refused rather than scored as zero.
  An incident the manifest lists only as a line range (the 30G manifest's
  syn and HTTP floods, 9,000 and 6,000 events) is resolved from the run's
  `events.duckdb`: the lines in that range between its `src` and `peer`,
  narrowed to the largest group with one traffic signature, and used only
  when the count equals the manifest's. Planted lines in a log that was not
  given (the 30G Windows log, `--raw windows=<file>`) count as not found.
  Each such decision is printed as a note and shown on the Evaluation page.

  ```powershell
  python -m killchain eval score --run data\runs\firex-30G --manifest logs\firex-30G.log.manifest.json --raw firewall=logs\firex-30G.log --api http://127.0.0.1:8010
  ```
- **Output:** a table with each metric's value and grade against the PRD's Good
  and Great targets, label accuracy three ways (exact, parent technique, any
  accepted alternate), the incidents not found, attack paths and whether they
  were rebuilt in order, false alarms (with `eval/reviewed.yml` for incidents
  confirmed real or false by hand), and alerts per rule split into truth hits
  and background. Everything is also in `metrics.json`.

## Full run

One command runs every stage on one log file:

```powershell
python -m killchain run --input data\raw\firex-10G.log --name firex-10G --offline --no-llm
python -m killchain run --input data\raw\firex-10G.log --reuse-parsed     # keep the earlier parse (and events.duckdb)
python -m killchain run --input data\raw\firex-10G.log --from score       # rerun score .. bundle only
```

Stage order: parse → db prepare → detect → correlate → chain → reach → score →
report → enrich → narrate → bundle. Each stage runs as its own process; its
output is printed with a `[stage]` prefix and kept in `<run>/logs/<stage>.log`.
Paths are `<data>/parsed/<name>` and `<data>/runs/<name>` (`--data-dir`,
default `data`; `--name` defaults to the file name without extension).

| Flag | Does |
|---|---|
| `--offline` | enrich uses the cache and local context only; the narrator is skipped |
| `--no-llm` | the narrator is skipped; incidents keep their template reports |
| `--reuse-parsed` | skips parse when `<data>/parsed/<name>` was parsed from the same file (same path and size; else exit 2), and db prepare when `events.duckdb` is newer than that parse |
| `--from STAGE` | skips the stages before STAGE and reuses their outputs (needs an earlier parse) |
| `--workers N`, `--ti-cache FILE` | passed to the parser and to enrich |

Enrich and the narrator are optional: when one fails (or enrich's lookups fail
because the network is down) the run records a warning and goes on, since
bundle works without their files. The narrator runs only when `LLM_ENABLED=true`
and `.env` has an LLM key; with LLM on and no key it is skipped with a warning.
Any other failed stage stops the run.

| Exit | Meaning |
|---|---|
| 0 | done (status `ok`, or `ok_with_warnings`) |
| 1 | a required stage failed; its last 20 output lines are printed and kept in the record |
| 2 | usage or input error (not a file, bad name, `--reuse-parsed` mismatch, `--from` without a parse); nothing is written |
| 3 | the input holds no events (empty, or no line is a FortiGate or JSON event, e.g. only binary) |

The run's record (per stage: status, reason, exit code, wall time, peak memory,
counts, command, log) goes under the `pipeline` key of `<run>/run_summary.json`,
added after bundle so every bundle field stays as bundle wrote it, and to
`<run>/pipeline.json`. Bundle rebuilds `run_summary.json` from scratch, so a
later `python -m killchain.bundle` drops the `pipeline` key; `pipeline.json`
keeps it. Peak memory per stage is the summed RSS of the run process and the
stage's processes, so it includes the orchestrator itself.

## Live mode

`python -m killchain live` tails one growing log file and keeps a run folder's
bundle current, so the API (which reloads changed bundle files) and every page
show new attacks while the log is written.

```powershell
python -m killchain live --input data\raw\live-demo.log --run data\runs\live-demo
```

| Option | Does |
|---|---|
| `--input FILE` | log file to tail (default `KILLCHAIN_LIVE_INPUT`) |
| `--run DIR` | run folder the bundle is written to |
| `--interval S`, `--window-hours H` | tick length (2 s) and the event-time window kept in memory (72 h); defaults in `config/live.yaml` |
| `--config`, `--rules`, `--assume-tz` | live settings file, rule folders, zone for timestamps without one |
| `--from-start` | ignore the checkpoint and read the file from the top |
| `--overwrite` | take over a run folder that holds a batch bundle |
| `--once` | start, one tick, stop |

Exit codes: 0 clean stop (Ctrl+C, SIGTERM or Ctrl+Break), 1 rule errors or a
fatal error, 2 usage error or a refused run folder.

Demo recipe (the chain A replay; needs the firex-10G batch run):

```powershell
python tools\replay.py slice --raw data\raw\firex-10G.log --run data\runs\firex-10G --ip 32.127.48.11 --out data\live\chainA.log
New-Item -ItemType File -Force data\raw\live-demo.log
python -m killchain live --input data\raw\live-demo.log --run data\runs\live-demo     # terminal 1
python -m killchain.api --run data\runs\live-demo --port 8000                         # terminal 2, after live's first publish
python tools\replay.py play --slice data\live\chainA.log --to data\raw\live-demo.log --rate 500 --step-pause 6
```

The slice holds chain A's 940 evidence lines plus 2,000 background lines from
the same span; the incident appears with the port scan and then grows to
R02 > R16 > R20 > R12. `tools\live_latency.py` plays the slice and measures how
long each step takes to show up.

How it works:

- **One process, in-process stages.** Each tick (2 s) reads the new complete
  lines, then runs detect, correlate, chain, reach, score, report and bundle
  in-process, about 0.5 to 0.8 s per tick on the demo. Enrich and the narrator
  are not run: threat intel adds 0 to the risk score and every report is the
  template.
- **The window is a table, by event time.** An in-memory DuckDB holds the last
  72 h of event time (replayed logs carry old timestamps) with the derived
  columns computed once per row on insert; a cap of 2,000,000 rows drops the
  oldest lines.
- **Rules that fit the window.** Count, distinct and sequence rules whose
  window is at most 72 h, and every match and sql rule, rerun over the whole
  window when it changed. R13 (growth over several days), A01 (rarity across
  the whole run) and A02 and A03 (a 2-day baseline) are skipped
  (`config/live.yaml: skip_rules`). The same lines give the same alert ids as
  the batch run.
- **Whole-window correlation.** When any alert is new or changed (alert id,
  event count, end time, success), correlation reruns over every alert in the
  window, not only those of the affected entities: hub detection and the
  incident boundaries are global, and this keeps live incidents identical to
  batch ones. The affected entities are recorded and decide which incidents
  count as changed.
- **Staged, then published.** Stages write to `<run>/live/work/<run>/`; the
  files are then copied into the run folder by rename, the files the API
  watches last and `index.json` last of all, so the API never loads a
  half-built bundle. A rename blocked by a reader is retried (Windows).
- **Run folder guard.** A folder with `index.json` and no
  `live/checkpoint.json` (a batch run) is refused without `--overwrite`.
- **Rotation and truncation** (new inode, a changed first line, or a shorter
  file) clear the window and the parser's clock state, and the file is read
  from line 1, so evidence always points into the current file. Incidents from
  the old file disappear at the next publish.

Files in `<run>/live/`: `status.json` (rewritten every tick), `events.jsonl`
(one record per publish that changed something, append-only; see
`docs/contracts.md`, "Live mode"), `checkpoint.json` (resume point, saved after
each successful publish; a restart backfills the window from it) and
`published.json`. The API reads raw evidence text from `data/raw` by file name,
so keep the live input there (or pass `--raw-dir`).

Measured on the chain A replay (3 runs, 12 steps, Core Ultra 7 255H): from a
step's last line written to its rule showing in `GET /alerts` with an incident
number, median 3.7 s, max 4.1 s; to the live publish, median 1.8 s, max 2.1 s. The
API side includes the API's own wait for the files to stay unchanged for one
1 s poll.

## SIEM connections

`killchain/connectors/` is AI-SOC's connector backend (Settings → SIEM
Integrations), copied and moved from MongoDB onto files. Connectors live in
`data/connectors/connectors.json`. Everything they deliver lands in
`data/ingest/`: every record in `<connector_id>/records.ndjson`, and the raw log
line a record carries in the shared `data/ingest/live.log`, which live mode
tails. No login, like the rest of the API.

| Vendor | Transports |
|---|---|
| Fortinet FortiGate | webhook, syslog |
| Wazuh | webhook, syslog |
| SentinelOne | API pull (threats or cloud-detection alerts), webhook, syslog |
| Sumo Logic | API pull (Cloud SIEM signals or insights), webhook |
| AlienVault USM Anywhere | API pull (alarms), webhook, syslog |
| Cybolt, custom | API pull (configurable REST client), webhook, syslog |

- **Webhook**: the source POSTs JSON to `/ingest/webhook/{connector_id}`. It can send
  one object, a JSON string (one log line), an array of objects or strings, or an
  object holding the array under `alerts`, `events`, `records`, `messages`, `data`,
  `items` or `results`. The limits are 8 MiB and 500 records per request. The
  endpoint returns 202, or 400 for bad JSON, 401 for bad credentials or a disabled
  connector, and 413 when a limit is exceeded. `GET .../ping` checks the
  credentials without ingesting anything.
- **API pull**: the API process polls the vendor every `interval_seconds` (60 s
  minimum, `KILLCHAIN_CONNECTORS=0` turns it off). Each poll resumes from a
  watermark, and re-read items are skipped by id. Vendor credentials are encrypted
  with `CONNECTOR_CREDENTIALS_KEY`. When that is unset, a key is generated once
  into `data/connectors/.credentials_key`; that is fine for a demo but not for
  real credentials. Targets must use https and must not resolve to link-local
  addresses (cloud metadata). Loopback and private addresses are refused unless
  `COLLECTOR_ALLOW_PRIVATE_TARGETS=true`, and http needs `COLLECTOR_ALLOW_HTTP=true`.
- **Syslog** (off by default; set `KILLCHAIN_SYSLOG=1`): plain UDP and TCP on
  `SYSLOG_UDP_PORT` / `SYSLOG_TCP_PORT` (5514). A sender is matched to a connector
  by its allowed IP or CIDR, and messages from unmatched senders are dropped.
  There is no TLS listener. Point a FortiGate at it with `config log syslogd
  setting`, `set status enable`, `set server <host>`, `set port 5514`, `set mode udp`.

Create a webhook connector from the UI, or with curl. The secret is returned
only in this response. If you lose it, call `rotate-secret`.

```powershell
$c = Invoke-RestMethod -Method Post http://localhost:8000/settings/siem-integrations -ContentType application/json `
  -Body '{"vendor":"fortigate","name":"Edge FW","transport":"webhook","auth_mode":"bearer"}'
$c.webhookUrl; $c.secret          # http://localhost:8000/ingest/webhook/<id>, soar_...
```

Send records with a bearer token (`Authorization: Bearer <secret>`, or the
header `X-SOAR-Token: <secret>`):

```powershell
$line = Get-Content data\raw\firex-10G.log -TotalCount 1
$body = @{ records = @(@{ full_log = $line }, @{ rule = "plain JSON, stored only" }) } | ConvertTo-Json -Compress
Invoke-RestMethod -Method Post $c.webhookUrl -Headers @{ Authorization = "Bearer $($c.secret)" } -ContentType application/json -Body $body
```

```bash
curl -X POST "$URL" -H "Authorization: Bearer $SECRET" -H 'Content-Type: application/json' \
  -d '["date=2026-10-23 time=08:48:26 devname=\"FGT60F\" logid=\"0000000013\" type=\"traffic\" ..."]'
```

An `hmac` connector expects `X-SOAR-Signature: sha256=<hex>`: the HMAC-SHA256
of the exact body bytes, keyed with the lowercase hex SHA-256 of the secret.
The key is the hash of the secret, not the secret itself:

```bash
KEY=$(printf %s "$SECRET" | sha256sum | cut -d' ' -f1)
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$KEY" | sed 's/^.* //')
curl -X POST "$URL" -H "X-SOAR-Signature: sha256=$SIG" -H 'Content-Type: application/json' -d "$BODY"
```

```powershell
$key = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($secret)) | % { $_.ToString('x2') })
$h = New-Object Security.Cryptography.HMACSHA256 (,[Text.Encoding]::UTF8.GetBytes($key))
$sig = -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($body)) | % { $_.ToString('x2') })
Invoke-RestMethod -Method Post $url -Headers @{ 'X-SOAR-Signature' = "sha256=$sig" } -ContentType application/json -Body $body
```

**How the data reaches the pipeline.** Each record's raw line goes into
`data/ingest/live.log`. The sink takes the first non-empty string among
`full_log`, `_raw`, `raw`, `message`, `log` and `event.original`, or the record
itself when it is a plain string. For syslog it takes the message body. Run live
mode on that file:

```powershell
python -m killchain live --input data\ingest\live.log --run data\runs\live-ingest
python -m killchain.api --run data\runs\live-ingest --raw-dir data\ingest     # after live's first publish
```

The API creates an empty `live.log` at startup, so live mode can start first.
Live mode publishes a bundle on its first tick. Connectors are stored apart from
runs, so the API can be restarted on `live-ingest` without losing them. With
Docker, run `docker compose --profile live up -d live-ingest`, then serve that
run with `KILLCHAIN_RUN=live-ingest`.

**Only FortiGate lines are analysed.** The parser reads FortiGate key=value
lines only. A record with no raw line is stored and counted as `notAnalysable`
on the connector row. Raw lines in other formats (CEF, Linux syslog, Wazuh
`full_log`) do reach `live.log`, but the parser counts them as unparsed and
detection ignores them. API pull from SentinelOne, Sumo Logic or USM Anywhere
returns those vendors' JSON, so it is stored but not analysed.

AI-SOC features left out: mTLS client certificates, the forwarding agent
(`/agents` always returns `[]`), TLS syslog, tenancy, licensing, audit and source
health. The settings routes and their camelCase responses are AI-SOC's. Each row
also carries `linesForwarded`, `notAnalysable` and `duplicates`.

## Bundle

The last pipeline stage. It merges every stage's output in a run folder into
the files the API serves, checks them against the contracts, and writes them
all or nothing (about 1 s on the 6.5 GB run).

```powershell
python -m killchain.bundle --run data\runs\firex-10G            # after chain (and reach, enrich, score, report)
python -m killchain.bundle --run data\runs\firex-10G --check    # check only, write nothing
```

| Writes | From |
|---|---|
| `incidents/<n>.json`, `index.json` | the stage files, with threat intel (`enrichment.json`) and narrator reports (`report.json`) merged in; `ti_verdict` and `triage_verdict` filled |
| `alerts.json` | `incident_number` from `incident_alerts.parquet` |
| `unexplained.json` | `unexplained.parquet` joined with the alerts |
| `ti.json` | `enrichment.json` matched to the incidents by value, so a renumbering by the risk score cannot misplace it |
| `run_summary.json` | every `_stats.json` (parse stats from `--parsed`, default `data/parsed/<run>`), counts, data quality, threat intel and LLM status |

Detection fields (chain, graph, reach next, risk score, numbering) are copied
unchanged. Rerunning it gives the same files. Stage order:
chain → reach → enrich → score → report → bundle.

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
| `GET /incidents/{id}/events` | evidence lines in time order, with the raw log text read at `byte_offset`; `step`, `offset`, `limit` (max 200); per-step line counts |
| `GET /entities/{value}` | every incident (with the value's role and steps) and alert involving an IP, host, account or domain, plus its threat intel |
| `GET /ti/status` | threat intel providers, when the run was enriched, verdict counts, cache stats |
| `GET /ti/indicators` | every indicator in the run with its verdict; filters `q`, `verdict`, `kind`, `sendable`, `limit` |
| `GET /ti/indicators/{value}` | one indicator: local context and the OTX answer |
| `POST /ti/lookup` | look up any IP, domain, URL or hash (`{"value": ...}`); private and internal values are kept local; 20 per minute, then 429 with `Retry-After` |
| `GET /dashboard/summary` | KPI tiles, incidents by risk band and by severity, kill chain coverage (14 tactics), alerts per hour, top attackers and targets, worst incidents, data quality, stage timings, TI and LLM status |
| `GET /alerts` | every alert, newest first; filters `incident` (a number, `none` or `any`), `technique`, `tactic`, `rule`, `layer`, `severity`, `entity`, `q`, `sort` (`newest`, `oldest`, `severity`), `limit`, `offset`; counts for the tabs |
| `GET /unexplained` | anomaly alerts that did not become or join an incident, with the reason |
| `GET /rules` | every rule in `rules/` with its alerts, incidents, run time and (after `eval score`) background alerts; filters `layer`, `q` |
| `GET /rules/{id}` | one rule: settings, YAML text and its 20 most recent alerts |
| `GET /incidents/{id}/report` | the report Markdown; `source=ai` or `template` (the template is kept beside an AI report) |
| `POST /incidents/{id}/ask` | `{"question": ...}`: an answer from the incident's facts and up to 60 evidence lines, with the cited lines; `rejected: true` when it cited lines or IPs outside the incident |
| `POST /rules/draft` | `{"description": ...}`: a YAML rule written by the LLM, validated and test-run on this run; nothing is saved |
| `POST /rules/test` | `{"yaml": ...}`: validate a rule and run it on this run's events: alerts, evidence lines, time, first 5 hits |
| `POST /rules/save` | `{"yaml": ...}`: save a valid rule as `rules/<firewall|anomaly>/<id>.yaml`; 409 if the id exists |

| `GET /metrics` | `metrics.json` from `eval score` with the PRD's Good and Great target per metric; `available: false` until eval ran |
| `GET /system` | stages with time and memory, data quality, TI and LLM status, raw-log availability, the run's files, the API's versions |
| `GET /live/status` | whether the API watches the run, bundle reloads, the live process's state from `<run>/live/status.json`, recent changes |
| `GET /live/stream` | Server-Sent Events: `hello`, then `bundle` (new, changed and removed incidents, new alerts) and `status`; `since`, `limit` |

**Live reload.** `python -m killchain.api` watches the run folder every second
(`--no-watch` turns it off). When the bundle files change and then stay the
same for one more check, it reloads the bundle for every endpoint and sends a
`bundle` event; the UI then refreshes every page and marks the changed
incidents. Rerunning any stage and the bundle step shows up in the open UI
within about 3 s (measured on the real run). The live process (P15) only has to
rewrite the bundle and keep `live/status.json` current.

Ask and draft share a cap of 6 a minute (`config/llm.yaml`), then 429 with
`Retry-After`; without an LLM key they answer 503. Rule SQL from the UI or the
LLM runs only on a read-only connection to the run's `events.duckdb` with file
access, `ATTACH` and extensions turned off, the configuration locked, a 2 GB
memory cap and a 60 s limit.

`GET /health` also has an `llm` block: whether the agents are on, the
configured models (never the keys), AI and template report counts, and today's
budget per model (requests and tokens used against the daily limit).

Evidence comes from `alert_evidence.parquet` in the run (every member line),
else `evidence_sample.json`, else each step's `line_sample`. The raw text is
read from the log named in each row, inside `--raw-dir` (default
`KILLCHAIN_RAW_DIR`, else `data/raw`); only plain file names in that folder
are opened. Without the log the lines are listed with line numbers and byte
offsets and `raw_available` is false.

Threat intel comes from `<run>/ti.json` (bundle step), or from
`<run>/enrichment.json` when enrich ran after the last bundle, and is merged
into the incidents at start-up (entity verdicts, step flags, `ti_verdict` in
the list). It never changes the risk score. `GET /path` on the real run
(25 incidents): p50 1.4 ms, p95 17.5 ms.

### AI narrator and triage opinion (agents)

```powershell
python -m killchain.agents narrate --run data\runs\firex-10G --facts   # prompt size per incident, no call
python -m killchain.agents narrate --run data\runs\firex-10G --llm     # write report.json
python -m killchain.bundle --run data\runs\firex-10G                   # merge it into the incidents
```

One LLM call per incident returns a two-sentence summary, one sentence per
numbered step with the evidence lines it rests on, what may happen next, and a
triage opinion (`looks_real` or `likely_noise`, shown only). The model sees a
fact sheet (chain, entities, counts, TI verdicts, reach next, risk parts,
gaps; no raw log lines; 600 to 1,200 tokens on the real run). A guard rejects
an answer that drops or adds a step, leaves out a chain IP or account, names an
IP, account, domain or technique that is not in the facts, or cites a line that
is not the step's evidence. A rejected answer gets one retry with the problems
listed, then the incident keeps its template report.

Models come from `.env` (`LLM_PRIMARY_*` for Groq, `LLM_FALLBACK_*` for
NeevCloud) and are tried in order: primary large, primary small, fallback
large, fallback small. Limits per model are in `config/llm.yaml` (used to 90%).
Every answer is cached in `data/cache/llm.sqlite`; a rerun keeps reports whose
facts did not change and makes no call for them. A 429 waits for `Retry-After`
when it is under 20 s, else the next model; a refused key pauses that provider
for 10 minutes. The batch narrator is off unless `LLM_ENABLED=true` or
`--llm` is given; the on-demand agents below work whenever a key is set.

**Incident Q&A** (Ask tab, small model): the question, the fact sheet and up
to 60 evidence lines read from the log; the answer must cite the line numbers
it rests on, and one that cites a line it was not given, or names an IP found
in neither the facts nor those lines, is rejected after one retry. Answers are
cached per question, so rehearsed demo questions cost nothing.

**Rule writer** (Rules page, large model): a plain-English description, the
`events` columns and three example rules (R01, R16, R07) go in; the YAML that
comes back is validated like any rule file, its SQL compiled (one retry with
the problems), then run on the run's events. The analyst can edit and test it
again; it is saved only with the Save button and never over an existing rule.
Run `detect` and the later stages to add a saved rule's alerts to the run.

### Threat intel (enrich)

```powershell
python -m killchain.enrich --run sample-run             # live OTX, needs OTX_API_KEY in .env
python -m killchain.enrich --run sample-run --offline   # local context only
```

Providers are local context (zones and roles from `config/ti.yaml`, alerts
and incidents in the run) and AlienVault OTX. Private, reserved and
documentation addresses, internal domains (`.local`, `.corp`, ...) and
internal URLs are never sent outside. Answers are cached in
`data/cache/ti.sqlite`. OTX score = min(pulses / 5, 1); allow-listed values
score 0. Verdicts: known-malicious (score ≥ 0.8), suspicious (≥ 0.4 or
flagged), no-reports, unknown (not checked). Without a key, or with
`KILLCHAIN_TI_OFFLINE=1`, only local context is used.

The MITRE endpoints run DuckDB `GROUP BY` queries over the run's alerts
(`killchain/api/mitre.py`). The other endpoints in `docs/build-plan.md` P11
are added as their pages are built. `GET /incidents/1/path` on the sample: p50 20 ms, p95 27 ms over HTTP
from PowerShell on Windows (target p95 < 500 ms).
