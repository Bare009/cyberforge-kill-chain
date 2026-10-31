# killchain

Kill chain and attack path analysis over large security log sets (CyberForge PRD
"Kill Chain and Attack Path Analysis"). Built in stages; this README grows with
each one.

| Stage | Status |
|---|---|
| 1. Streaming log parser (FR-1) | done: `killchain.parser` |
| 2. Detection rules with ATT&CK labels (FR-2, FR-3, B-4) | next |
| 3. Incidents, attack paths, reach-next (FR-4 to FR-6) | planned |
| 4. API and UI (FR-7) | planned |
| 5. Scoring harness against the ground-truth manifest | planned |

Requirements and targets: `docs/requirements.md`. Pipeline and stage
contracts: `docs/architecture.md`. What the organisers' data looks like:
`docs/data-notes.md`.

## Layout

```
killchain/          Python package, one sub-package per pipeline stage
  parser/           raw logs -> Parquet (built)
  attack/           ATT&CK catalogue and kill chain stage order
  detect/           YAML rule engine
  correlate/        incident builder
  enrich/           local context and threat intel
  graph/            attack paths and reach-next
  score/            risk score
  agents/           LLM narrator, triage opinion, Q&A, rule writer
  report/           template reports when no LLM is reachable
  api/              FastAPI app
  eval/             scoring against the ground-truth manifest
  live/             live mode
rules/              detection rules, firewall/ and windows/
web/                React UI
tools/              developer checks
docs/               requirements, architecture, data notes
data/               local inputs and outputs, never committed
```

## Setup

Python 3.11 or newer.

```powershell
pip install -r requirements.txt
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
