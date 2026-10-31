# Final build plan

The single working plan for the kill chain project. It combines our plan
(`docs/architecture.md`, earlier `build-plan.md`) with the merged plan written
by the team (`Kill Chain & Attack Path Merged Build Plan.md`), keeps whichever
choice is faster or more accurate on each point, and corrects both against the
real data.

Evidence labels: **[measured]** checked on `firex-10G.log`; **[decision]** our
choice; **[assumption]** not yet checked.

---

## 0. Decisions at a glance

| Topic | Our plan | Merged plan | Final | Why |
|---|---|---|---|---|
| Parser | Built, verified | Planned from scratch, `ts_valid`, naive local time | **Keep ours as is** | Done: 55 s, 4.5 GB, 0 mismatches in 1.35 M field checks; UTC is correct and unambiguous |
| Event table | snake_case, `ts` UTC, `ts_quality` | FortiGate names, naive time, `ts_valid` | Ours, plus a DuckDB view adding `ts_valid`, `ts_ist`, `ist_hour`, `is_internal_src/dst` | No re-parse; rules get both forms |
| Query engine | polars | DuckDB SQL | **DuckDB over Parquet** | Rules need SQL for the hard kinds anyway; window functions; named in the PRD |
| Rule format | Sigma-style, six declarative kinds | Five kinds incl. raw `sql` | Merged plan's five kinds + validator + a Sigma import for single-event rules (T2) | Declarative where easy, SQL where hard; B-4 stays credible |
| Ground truth | 30 GB manifest + `plant.py` | Silver truth of 17 hand-found incidents | **Silver truth of all 25 firewall incident types**, checked against the manifest's event counts | Found in the data [measured]; plant.py would cost a day and test synthetic shapes |
| Unknown attacks | not covered | not covered | **Anomaly layer** (generic detectors, lower trust) | Insurance for anything the rules miss on the judges' file |
| Labels | technique + tactic + stage | + 7-phase kill chain + `alt_techniques` | All of those; primary technique = the manifest's, parent and alternates in `alt_techniques` | Maximises exact label accuracy |
| Correlation | weights, 2 h / 48 h windows, hub cap, promotion bar | union-find, source-host rule | Combined | The source-host rule is needed for chain B |
| Attack story | steps per (stage, technique) | dense numbered chain, `gaps`, `ongoing` | Numbered chain with our overlap tie-break | Easy to read in a minute |
| Reach next | access graph, BFS 2 hops | same + likely next tactics | Same, **widened** to all allowed internal flows and admin-of edges, plus labelled inferred reach | The admin-port graph is almost empty in this file [measured] |
| Enrichment | 7 providers | local + OTX + AbuseIPDB | **Full threat-intel engine**: local context + OTX, AbuseIPDB, VirusTotal, GreyNoise, abuse.ch (URLhaus, ThreatFox), Shodan InternetDB, GeoIP; a Threat Intel page | 7-day schedule has room; adds context per entity, never changes detection |
| LLM | 4 agents | fact-checked report only | **Four agents**: checked narrator, triage opinion (display only), incident Q&A, rule writer | Time allows; all cached, all optional |
| UI | port AI-SOC React | static page, Cytoscape | **AI-SOC React app, trimmed and extended**; MITRE page ported as is | Owner requirement: a UI as good as AI-SOC |
| Live mode | phase 10 | stretch | **T1** | Bonus B-5, 7 days is enough |
| Docker | last | T1 | **T0**: Compose with pipeline, API and web | Judges start it from the README |
| Normalisation | flat tables + OCSF-shaped alerts | flat events | Same: one typed flat schema for events, OCSF Detection Finding shape for alerts; no OCSF/ULF conversion of events | The scoring tiers have the same format as `firex-10G.log`; conversion would slow every query and score nothing |
| Time budget | 16 days | 24 h | **7 days, 2 people in parallel** | The hackathon length |

---

## 1. Priority tiers and cut order

- **T0, must ship:** parser (done), evaluation, rule engine, rules for all
  silver incidents, labels, correlation, numbered chain and path graph, reach
  next, risk score, template report, API, the full React UI (section P12),
  the MITRE page, threat-intel engine, Docker Compose, full run within
  targets, README.
- **T1, should ship:** anomaly layer, the four LLM agents, live mode.
- **T2, stretch:** Sigma import, Windows adapter rules (only if a Windows log
  arrives), extra UI polish (themes, saved views).

**Cut in this order when behind:** Sigma import → Windows rules → live mode →
rule-writer agent → Q&A agent → triage opinion → anomaly layer.

**Never cut:** evaluation, rule engine, the silver-incident rules, correlation,
chain, reach next, risk score, API, the React UI and MITRE page, threat intel,
template report, Docker, README.

---

## 2. The data

### 2.1 Format and regions [measured]

FortiGate `key=value` lines from one device. Parsed output:
`data/parsed/firex-10G/firewall/*.parquet` (36 files, 497 MB).

| Region | Bytes | Rows | Handling |
|---|---|---|---|
| Real timeline, 23 Oct 08:48 to 30 Oct 08:48 IST | 0 to 2,030,829,674 | 3,848,247 | `ts_quality=ok` |
| Frozen clock (eventtime 1793350105999999000) | to 4,815,675,419 | 5,277,136 (812,235 exact duplicates) | `ts_quality=stuck`; excluded from window rules |
| 1,602 Debian `.deb` packages | to 6,543,120,032 | 0 (6.7 M lines rejected) | one junk range in `_stats.json` |

The last text line is cut off by the first package; it is flagged
`parse_issue=truncated_binary_tail`.

Network [measured]: user desktops `10.10.10.0/24`; servers and the DMZ
`10.10.20.0/24` with the web portal `10.10.20.20`; other LAN
`10.10.30-50.0/24` (IoT-like hosts in `10.10.40.0/24`); firewall management
`10.10.99.1`; the firewall's public address `203.0.113.5`.

### 2.2 Noise traps [measured]

| Trap | Evidence | Rule of thumb |
|---|---|---|
| IPS signatures everywhere | about 2,950 hits each for Eicar, Cobalt Strike, Mirai, Log4j, ...; about **20% not dropped**; about 1,220 sources each | A single IPS event, blocked or not, is never a detection. Use concentration from one source and the planted families' own signature names (`HTTP.URI.SQL.Injection`, not the noise's `Generic.SQL.Injection.Attempt`) |
| AV blocks | 57,107 blocked, only 3 `detected` | `detected` (not blocked) is rare and meaningful |
| Suspicious-looking domains in background | `kjhsdf.duckdns.org`, `update-svc-duckdns.net` blocked from dozens of hosts | A bad-looking domain alone is not a signal |
| Steady scanners | 264 sources, 534,261 failed admin logins; `45.74.28.0/24` alone 280,854 | Compare a source with its own rate; the busiest 10-minute count outside the attack is 25 |
| Labels that lie | `service`, `app`, `appcat`, `apprisk` do not match ports; `policyid` is random | Use `dst_port`, direction, bytes, timing |
| Time | `eventtime` is local time written as UTC | The parser already resolves it; never re-apply `tz` |

**Golden rule:** a single IPS, AV or webfilter event is never a detection.
Only concentration, rarity, sequence or a rare action (`detected`, success)
is.

### 2.3 Silver truth: every firewall incident type, found [measured]

Event counts match the organisers' 30 GB manifest for the same incident type,
which is strong evidence these are the planted attacks.

| # | Incident | Key evidence (IST) | Events | Primary (alternates) |
|---|---|---|---|---|
| 1 | Brute-force burst | `15.199.16.197` failed admin logins, 27 Oct 12:58-13:08 | 2,000 | T1110.001 (T1110) |
| 2 | Port scan | `194.102.163.167` → `10.10.20.20`, 1,024 ports, all denied, 27 Oct 21:07-21:09 | 1,024 | T1046 (T1595.001) |
| 3 | Known-bad destination (IoT → botnet) | 52 hosts in `10.10.40.0/24` → `154.35.54.115:23`, dropped, 23 Oct 20:36-21:16 | 60 | T1071.001 (T1071) |
| 4 | Malware download (exe served as PDF) | `10.10.10.51` ← `hoguyusebavox.info/pkg/invoice_2026.pdf.exe`, blocked, 24 Oct 06:31-06:46 | 12 | T1105 |
| 5 | Admin login at an odd hour | `Deepika.Khan` from `171.104.84.193` (Russia), 28 Oct 03:17, 03:47, 04:17 | 3 | T1078.001 (T1078) |
| 6 | Slow credential stuffing | `71.54.76.0/24`: 79 sources, 51 users, about one try each, 27 Oct 09:40-15:28 | 90 | T1110.004 (T1110) |
| 7 | Success after failures | `8.42.69.0/24`: 29 failures 19:49-19:59, then `parul.sinha` logs in from `8.42.69.77` 19:59:30, 24 Oct | 30 | T1110.001, success line T1078 |
| 8 | Impossible travel | `keerat.ghughal` VPN tunnel-up alternating Türkiye / US, 28 Oct 02:15-02:37 | 4 | T1078.004 (T1078) |
| 9 | Lateral movement | `10.10.10.63` → 30 servers on SMB/RDP, 25 Oct 02:04-02:30 | 180 | T1021.002; 3389 lines T1021.001 |
| 10 | DNS tunnel | `10.10.10.88`, 40-char labels under `doqotobitum.com`, 24 Oct 19:58-21:12 | 1,500 | T1071.004 (T1048.003) |
| 11 | C2 beaconing | `10.10.10.112` → `198.79.124.52:443`, every 300 s (std 4.6 s), 23-29 Oct | 1,612 | T1071.001 (T1573) |
| 12 | Staged exfiltration | `10.10.20.31` → `7.93.184.183:443`, 41 MB out vs 1 MB in, 26-29 Oct | 2,000 | T1048.002 (T1030, T1048) |
| 13 | Insider drift | `10.10.10.44` → 60 servers on admin ports, growing, 27-29 Oct | 2,400 | T1078.002 (T1083) |
| 14 | Logging disabled around a change | `Tejas.Roy`: log disk off 16:31, policies purged 18:28, back on 20:36, 23 Oct | 3 | T1562.002 (T1070, T1562) |
| 15 | Rogue admin account | `Rakes` adds `svc_backup30` 03:55, it logs in 04:02, deleted 04:07, 29 Oct | 3 | T1136.001 (T1098) |
| 16 | SQL injection | `131.228.119.59` → portal, 20 not dropped, 25 Oct 20:04 | 220 | T1190 (T1595.002) |
| 17 | Cross-site scripting | `178.50.251.250` → portal, 23 Oct 16:22 | 60 | T1189 (T1059.007, T1190) |
| 18 | Path traversal | `72.90.113.105` → portal, 12 not dropped, 28 Oct 11:15 | 80 | T1190 (T1083) |
| 19 | Command injection | `72.7.116.239` → portal, 11 not dropped, 26 Oct 16:59 | 55 | T1190 (T1059.004) |
| 20 | Web shell in use | `202.36.226.247` → portal, passthrough to `/uploads/img_0931.php`, `/tmp/update.jsp`, ..., 27 Oct 06:47 | 120 | T1505.003 (T1071.001) |
| 21 | SYN flood | `189.238.0.0/16` → portal:443, 8,424 sources, all denied, 25 Oct 09:39-10:23 | 9,000 | T1498.001 |
| 22 | HTTP flood | about 6,000 sources → portal:443, one accepted session each, 24 Oct 07:21-07:35 (normal: 1 a minute) | 6,000 | T1498.001 (T1499.002) |
| 23 | DNS amplification | 4,000 sources, UDP from port 53 → `203.0.113.5`, denied, 25 Oct 19:46-19:56 | 4,000 | T1498.002 |
| 28 | Chain A, web to domain admin (firewall part) | `32.127.48.11` → portal, 29 Oct: 240 ports 01:51 → SQLi 60 02:07 → web shell 40 02:41 → 600 sessions, 12.3 MB in, 10:09-12:38 | 940 | per step: T1595.002, T1190, T1505.003, T1048.002 |
| 29 | Chain B, ransomware precursor (firewall part) | `10.10.10.118`: `JS/Nemucod` `detected` from `kjhsdf.duckdns.org/invoice/...zip` 26 Oct 08:22 → 803 sessions to `7.154.5.35:443` (8.4 MB out) 26-28 Oct | about 806 | per step: T1566.001/T1204.002, T1071.001, T1048.002 |

Corrections to earlier notes: `parul.sinha` is incident 7, not
unclassified; lateral movement (`10.10.10.63`) and insider drift
(`10.10.10.44`) are two incidents, not one.

Missing from this file: the four Windows-only incident types (24 to 27) and the
Windows stages of both chains, because no Windows log was shared.

**Hold-out discipline [decision]:** rule thresholds must sit far from both the
planted count and the background, and every rule is written to the attack's
behaviour, not to these IPs. The judges' file has the same attack shapes (PRD:
"same planted attack sequences at every tier") but may have different IPs and
times.

---

## 3. Architecture

```
data/raw/*.log
  │ P1 parser (built) ── multiprocess, byte ranges, Parquet, ts_quality, parse_issue
  ▼
data/parsed/<run>/{firewall,windows}/*.parquet                    contract A
  │ DuckDB view `events` (+ ts_valid, ts_ist, ist_hour, zones)
  │ P3 rule engine ◄── rules/**/*.yaml, ATT&CK catalogue
  │ P4 specific rules  +  P4b anomaly layer
  ▼
data/runs/<run>/alerts.parquet + alert_evidence.parquet            contract B
  │ P6 correlate (hub cap, weights, windows, promotion bar)
  │ P7 numbered chain + path graph
  │ P8 access graph + reach next
  │ P9 enrich (local + cached TI)   P10 risk score + report
  ▼
data/runs/<run>/incidents/<n>.json + index.json                    contract C
  │ P11 FastAPI (reads files, sub-ms lookups)
  ▼
P12 React UI (AI-SOC based)              P2 eval ── metrics.json
P15 live mode: tail → parse → detect → correlate → rebundle (seconds)
```

Tooling: Python 3.11+, pyarrow, polars (parser), **DuckDB** (rules and
queries), NetworkX (incidents, chains, reach), FastAPI and Uvicorn, PyYAML,
psutil, httpx, orjson, openai (LLM client); web: React 19, Vite 7, TypeScript,
Tailwind 4, Radix UI, TanStack Query, react-force-graph-2d, recharts,
react-markdown (all as in AI-SOC). Every stage is `python -m killchain <stage>` and
writes `_stats.json` (wall time, peak RSS of all processes, row counts).
Stages are restartable: they skip if their output exists, `--force` redoes.

### Folder layout

```
killchain/                  repo root
  killchain/                package: parser/ attack/ detect/ anomaly/ correlate/ graph/
                            enrich/ score/ report/ agents/ api/ eval/ live/
  config/                   network.yaml, killchain.yml (7-phase map), techniques.json
  rules/firewall/*.yaml     specific rules
  rules/anomaly/*.yaml      generic detectors
  rules/windows/*.yaml      only if a Windows log arrives
  eval/                     silver_truth.yaml, reviewed.yml (committed)
  web/                      React app (from AI-SOC web_app/frontend), Dockerfile, nginx.conf
  docker/                   Dockerfile.api, Dockerfile.pipeline
  docker-compose.yml        pipeline, api, web (and live, profile `live`)
  tools/                    verify_parse.py, audit_parse.py, test_parser_edges.py, explore.py
  tests/                    unit tests and small fixtures
  docs/                     this plan, architecture, requirements, data notes
  data/                     raw/, parsed/, runs/, cache/  (git-ignored)
```

`data/` is git-ignored, so all configuration lives in `config/` and `eval/`.

### Contract A: events (built)

The parser's columns: `ts` (UTC), `ts_quality`, `parse_issue`, `source`,
`line`, `byte_offset`, `line_hash`, `log_id`, `log_type`, `log_subtype`,
`level`, `action`, `status`, `reason`, `src_ip`, `src_port`, `src_intf`,
`src_intf_role`, `src_country`, `dst_ip`, `dst_port`, `dst_intf`,
`dst_intf_role`, `dst_country`, `proto`, `service`, `policy_id`, `session_id`,
`app`, `app_cat`, `app_risk`, `duration`, `sent_bytes`, `rcvd_bytes`,
`sent_pkts`, `rcvd_pkts`, `hostname`, `url`, `cat_desc`, `attack`,
`attack_id`, `severity`, `cr_score`, `virus`, `user`, `ui`, `method`,
`log_desc`, `msg`, `extra`.

The DuckDB view `events` adds:

```sql
ts_valid      = ts_quality IN ('ok', 'tz_assumed') AND parse_issue IS NULL
ts_ist        = ts + INTERVAL 330 MINUTE
ist_hour      = hour(ts_ist)
src_internal  = src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR ...   -- full RFC 1918
dst_internal  = same for dst_ip
src_zone, dst_zone  from config/network.yaml (desktop, server, dmz, iot, mgmt, public, internet)
```

### Contract B: alerts

`alerts.parquet`, one row per detection:
`alert_id` (hash of rule, group key, first ts), `rule_id`, `layer`
(`rule` | `anomaly`), `title`, `technique`, `alt_techniques`,
`technique_name`, `tactic`, `stage_no` (1-14), `kill_chain_stage` (7-phase),
`severity` (1-5), `confidence` (0-1), `ts_start`, `ts_end`, `src_ip`,
`dst_ip`, `host`, `user`, `domain`, `url`, `event_count`, `blocked_share`,
`success` (bool: any member event got through), `summary`, `action_text`,
`group_key` (JSON).

`alert_evidence.parquet`: `alert_id`, `source`, `line`, `byte_offset`, `ts`,
`technique`, `role` (`trigger` | `window` | `context`). Every member line, so
an alert for 2,000 failed logins has 2,000 rows here.

### Contract C: incident JSON

`incident_number` (1..N worst first), `incident_id` (stable hash), `title`,
`risk_score`, `risk_parts`, `severity`, `ts_start`, `ts_end`,
`merged {alerts, events}`, `entities {ips, hosts, users, domains}`,
`chain_text`, `chain[]`, `gaps[]`, `graph {nodes, edges}`, `enrichment`,
`next {reachable[], sentence, likely_tactics}`, `report`, `report_source`
(`ai` | `template`), `layers` (rule, anomaly). Full evidence stays in
`incident_lines.parquet`; the JSON carries a sample of 20 lines per step.

---

## 4. Phases

Hours are single-person effort. A = pipeline and detection, B = evaluation,
graph and product.

### P0. Setup (day 1 morning, T0, both)

1. `pip install duckdb httpx openai` and add them to `requirements.txt`;
   Node.js 20 LTS for `web/`; Docker Desktop.
2. Create the folders in section 3 that do not exist yet: `config/`,
   `killchain/anomaly/`, `killchain/agents/`, `killchain/enrich/`,
   `rules/anomaly/`, `eval/`, `web/`, `docker/`, `tests/`, `examples/`.
3. Move the logs into `killchain/data/raw/`.
4. Freeze contracts B and C (contract A is built).
5. `.env.example` with every key from P9 and P10b, all empty.
6. Git habit: short branch per task, `git pull --rebase` before merging,
   one-line plain-English commits; every merge touching `rules/` posts the new
   metrics in chat.

**Manual work:** add the teammate on GitHub; copy `logs.zip` (2.3 GB) to the
second laptop; send the organiser questions (section 7).

### P1. Parser (done; leftovers half a day, T0, A)

Built and verified (`tools/audit_parse.py`): 15,848,040 lines accounted for,
9,125,383 rows, line numbers contiguous, 0 mismatches in 1.35 M field checks,
stuck flags exact, 55 s and 4.5 GB peak. Remaining:

1. `killchain/__main__.py` with sub-commands (`parse`, `detect`, `correlate`,
   `chain`, `reach`, `enrich`, `score`, `report`, `bundle`, `eval`, `run`,
   `serve`, `live`).
2. `killchain/db.py`: opens DuckDB, creates the `events` view over a run's
   Parquet (section 3), sets `memory_limit='6GB'`, `threads` = CPUs − 2,
   `temp_directory='data/tmp'`.
3. `tools/explore.py`: SQL over the view from the command line, for writing
   rules.

**Done when:** `python -m killchain parse ...` works and
`SELECT count(*) FROM events WHERE ts_valid` returns 3,848,247.

### P2. Evaluation harness (half a day, T0, A)

1. **`eval/silver_truth.yaml`**: the 25 incidents of section 2.3, each as one
   or more DuckDB `WHERE` clauses (e.g. `src_ip = '15.199.16.197' AND log_desc =
   'Admin login failed'`), plus primary technique, alternates, step list for
   the chains, and the expected event count.
2. **`killchain/eval/silver.py`**: runs the clauses, writes
   `data/runs/<run>/silver_truth.parquet` (incident, step, technique, line);
   fails loudly if a clause's count differs from the expected count by more
   than 1%.
3. **`killchain/eval/manifest.py`**: reads an organisers' manifest; refuses one
   whose offsets do not point at line starts in the file (prints "manifest
   does not belong to this file").
4. **`killchain/eval/score.py`** reports:

   | Metric | Definition |
   |---|---|
   | Step recall | truth lines covered by any alert's evidence / truth lines; per incident and per class |
   | Incident recall | truth incidents with ≥ 80% of lines covered |
   | Label accuracy | covered truth lines whose alert technique matches: exact primary, parent, any alternate (three numbers) |
   | Path order | for incidents with steps: one incident covers every step, and its numbered chain has them in the truth order |
   | False alarms | our incidents with no truth overlap, split into `reviewed-false` (in `eval/reviewed.yml`) and `unreviewed` |
   | Per rule | truth lines found, alerts, background alerts (no truth overlap) |
   | Layer | truth lines found only by the anomaly layer; anomaly-only incidents and how many are false |
   | Time, memory | from every stage's `_stats.json` |
   | Open time | p50 and p95 of `GET /incidents/{n}/path` (once P11 exists) |

5. Writes `metrics.json` and prints a table. Works with empty alerts (all
   zeros) so it can be built before rules.

**Manual work:** review the 25 silver incidents; whenever `score` lists
unreviewed incidents, mark each true or false in `eval/reviewed.yml`.

### P3. Rule engine and validator (1 day, T0, A)

**Rule file:**

```yaml
id: fw-bruteforce-burst
title: Brute force on firewall admin login
status: stable                      # experimental | test | stable
attack:
  technique: T1110.001
  alt_techniques: [T1110]
  tactic: credential-access         # checked against the technique's tactics
severity: 4                         # 1-5
confidence: 0.9                     # 0-1, used by the promotion bar
promote: false                      # true: a single hit is enough for an incident
logsource: firewall
kind: count                         # match | count | distinct | sequence | sql
where: "log_desc = 'Admin login failed' AND NOT src_internal"
group_by: [src_ip]
window: 10m
having: {gte: 100}
entities: {src_ip: src_ip, dst_ip: dst_ip, user: user}
evidence: window                    # window = every member line; trigger = matching lines only
time_quality: valid                 # valid (default) | any
action_text: "{src_ip} tried {event_count} admin passwords in {minutes} minutes"
tuning: "planted 2,000 in 10 min; background max 25 per 10 min"
```

**Kinds, compiled to DuckDB SQL:**

| Kind | Meaning | SQL shape |
|---|---|---|
| `match` | matching lines, one alert per group per `bucket` (default 1 h) | filter → group by key and time bucket |
| `count` | count per group in a sliding window meets `having` | `count(*) OVER (PARTITION BY key ORDER BY ts RANGE window PRECEDING)`, then runs of qualifying windows merged into one alert |
| `distinct` | distinct values of `field` per group in a window | same, with a self-join on the window or `count(DISTINCT)` per merged run |
| `sequence` | named steps in order for the same key within `within` | one CTE per step, joined on key with `ts` ordering |
| `sql` | raw SQL returning the contract B columns plus `lines` | used for periodic, volume, baseline and drift |

**Engine:** load `rules/**/*.yaml`; validate; run each rule against
`events`; merge overlapping windows of one group, and split a group into
separate alerts when its hits are more than `split_gap` apart (default 1 h);
write `alerts.parquet` and `alert_evidence.parquet`; fill `technique_name`,
`stage_no`, `kill_chain_stage` from `killchain/attack`; fill `action_text`;
compute `blocked_share` and `success`; per-rule timings in `_stats.json`.

**Validator:** required keys; technique in the catalogue; tactic is one of the
technique's tactics; `window` parses; `where` compiles (DuckDB `EXPLAIN`);
`sql` rules return the required columns. One-line errors with the file name.

**CLI:**

```
python -m killchain detect --run data\runs\firex-10G
python -m killchain detect --run ... --only fw-bruteforce-burst
python -m killchain detect --validate
```

**Done when:** two rules (`count` and `match`) run on the full table in
seconds; a broken rule fails with a one-line error.

**Manual work:** A and B agree the rule format (30 minutes) before writing rules.

### P4. Specific rules (1.5 days, T0, A)

**Procedure for every rule:** find the planted lines; measure the background
for the same pattern; set the threshold with a wide margin on both sides; write
the YAML with a `tuning:` note; run `--only` then `eval score`; read the first
20 background hits by eye; post before/after numbers with the commit.

| Rule | Incident | Kind | Logic (starting point) | Measured separation |
|---|---|---|---|---|
| R01 | 1 | count | `Admin login failed`, external source, per `src_ip`, 10 min, ≥ 100 | planted 2,000; background max 25 |
| R02a | 2 | distinct | `dst_port` per (`src_ip`, `dst_ip`), 5 min, ≥ 200 | planted 1,024 |
| R02b | 28 step 1 | distinct | same, 15 min, ≥ 100, external source | planted 240 |
| R03 | 3 | distinct | internal sources → one external `dst_ip` on 23/2323, 1 h, ≥ 10 sources | planted 52 sources |
| R04 | 4 | match | `utm/virus` where `url` has a double extension (`.pdf.exe`, `.doc.exe`, ...); group (`src_ip`, `hostname`) | planted 12 |
| R05 | 5 | match | `Admin login successful`, external source, `ist_hour` 0-5, `src_country` not India | planted 3 of 5 successes |
| R06 | 6 | distinct | `Admin login failed` per source /24, 8 h, ≥ 20 sources and ≥ 20 users and ≤ 3 tries per source | planted 79 sources, 1.1 tries each; the steady /24 has 3,384 per source |
| R07 | 7 | sequence | per /24: ≥ 20 failures, then `Admin login successful` within 15 min | planted 29 then 1 |
| R08 | 8 | sql | VPN `tunnel-up` per `user`: two countries within 30 min | planted 4 |
| R09 | 9 | sql | internal source → ≥ 10 distinct internal destinations on 445/3389/22/135/5985/5986 within 1 h | planted 30 in 26 min; no other source does this |
| R10 | 10 | count | `utm/dns`, first label ≥ 30 chars, per (`src_ip`, registered domain), 1 h, ≥ 100 | planted 1,500 |
| R11 | 11 | sql | internal → external pair, ≥ 50 flows, interval CV ≤ 0.05, bytes per flow CV ≤ 0.2 | planted 1,612, std 4.6 s on 300 s |
| R12 | 12, 28 last step, 29 last step | sql | internal-or-portal pair with an external peer: sent/received ≥ 5 and ≥ 5 MB sent over the run | planted 41 MB / 8.4 MB / 12.3 MB |
| R13 | 13 | sql | internal source, distinct internal destinations on admin ports per day, rising for ≥ 2 days, ≥ 20 total | planted 60 over 3 days |
| R14 | 14 | sequence | same `user`: `log disk` disabled, then `purged`, then `log disk` enabled, within 8 h | planted 3 |
| R15 | 15 | sequence | `Add system.admin X`, login by X, `Delete system.admin X`, within 1 h | planted 3 + login |
| R16 | 16, 28 step 2 | match | `utm/ips`, `attack` in SQL-injection family, one external source, ≥ 20 per 30 min | planted 220 and 60 |
| R17 | 17 | match | XSS family or `url` with `<script`/`onerror=` | planted 60 |
| R18 | 18 | match | path traversal family or `../`, `..%2F`, `php://filter` | planted 80 |
| R19 | 19 | match | command-injection family or `;`, `|`, `$(` in a parameter | planted 55 |
| R20 | 20, 28 step 3 | sql | webfilter `passthrough` from one external source to the portal on URL paths that no other source requests; ≥ 20 hits | planted 120 and 40 |
| R21 | 21 | sql | `deny` to one destination from ≥ 1,000 sources in one /16 within 10 min | planted 8,424 sources |
| R22 | 22 | sql | sessions per minute to one internal host ≥ 20× its p99 minute, from ≥ 500 sources | planted about 660 a minute; p99 227 (from the same flood); median 1 |
| R23 | 23 | sql | UDP from source port 53 to one internal or own address from ≥ 500 sources in 10 min | planted 4,000 |
| R24 | 29 step 1 | match | `utm/virus` with `action = 'detected'` (not blocked) | planted 3 of 3 |

Note on R22: compute the baseline from minutes outside any candidate burst, or
use the median, so a flood does not raise its own baseline.

**Owner:** A writes all rules; B reviews background hits with A (M6).

**Done when:** every row of section 2.3 is found with ≥ 95% of its lines; no
rule raises more than 5 background alerts over the 7 days without a written
reason; every file has its `tuning:` note.

**Manual work:** 15 minutes per rule reading background hits; decide
trade-offs together when the numbers are shown.

### P4b. Anomaly layer (half a day, T1, A)

Generic detectors in `rules/anomaly/`, run by the same engine with
`layer: anomaly`, lower `confidence` (0.3-0.5) and `promote: false`.

| Detector | Flags | Default label |
|---|---|---|
| Rare event | `log_id` / `log_desc` / `action` values seen < 20 times in the run | from `config/rare_events.yaml`, else `unknown` |
| First-seen pair | internal source → destination on an admin port, user → country, never seen in the first 2 days | T1021 / T1078 |
| Per-entity outlier | an hour where a source's sessions, distinct destinations, distinct ports, failed logins or bytes out exceed median + 6 MAD of its own hours | by feature: ports → T1046, destinations → T1021, failures → T1110, bytes out → T1048 |
| Denied then allowed | a source denied ≥ 50 times, then allowed to the same destination | T1190 |
| Lopsided pair | sent/received ≥ 10 and ≥ 1 MB over the run | T1048 |
| Too regular | ≥ 30 sessions with interval CV ≤ 0.1 | T1071 |

Rules for its alerts:
- An anomaly alert sharing entities and time with a rule alert joins that
  incident as supporting evidence on the nearest rule step (P7).
- Alone, it becomes an incident only when ≥ 2 detectors fire on the same
  entity within an hour; otherwise it is listed as **unexplained activity**
  in the API and UI, not as an incident.
- `eval score` reports truth lines found only by this layer and false
  anomaly-only incidents. Thresholds are tuned with that.

**Why:** the judges' file may contain shapes or variants we did not see. This
layer finds unusual behaviour without a specific rule and needs no training.

### P5. Labels (2 h, T0, A)

`killchain/attack/`:
- catalogue lookup (`attack_catalogue.json`, 691 techniques): name, tactics,
  parent;
- `stage_no` from the 14-tactic order (reconnaissance 1 ... impact 14);
- `kill_chain_stage` from `config/killchain.yml`:

  | 7-phase | ATT&CK tactics |
  |---|---|
  | 1 Reconnaissance | Reconnaissance |
  | 2 Weaponization | Resource Development |
  | 3 Delivery | Initial Access |
  | 4 Exploitation | Execution |
  | 5 Installation | Persistence, Privilege Escalation, Defense Evasion |
  | 6 Command and Control | Command and Control |
  | 7 Actions on Objectives | Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact |

- per-line technique overrides inside a rule (`technique_by: {dst_port:
  {3389: T1021.001}}`, `{log_desc: {'Admin login successful': T1078}}`), so
  one alert can label its lines more precisely;
- tactic names accepted in any form (`Credential Access`, `credential-access`,
  `TA0006`).

The UI shows the ATT&CK tactic first and the 7-phase label beside it.

### P6. Correlation (half a day, T0, A)

1. One row per (alert, entity): `src_ip`, `dst_ip`, `user`, `host`, `domain`,
   each tagged with zone and role.
2. **Hub cap:** entities in more than 10% of alerts, plus a fixed list
   (`10.10.20.20`, `10.10.99.1`, `203.0.113.5`, `admin`), do not link alerts on
   their own. They stay on the alert as context.
3. **Link weights:** shared external attacker IP 1.0; shared internal host as
   the source of both alerts 1.0; shared account 0.8; shared domain 0.7; shared
   internal host as target 0.5. Two alerts link when the summed weight ≥ 1.0
   and the time rule holds.
4. **Time rule:** gap ≤ 2 h between one alert's end and the next one's start,
   widened to 72 h when the later alert's `stage_no` is ≥ the earlier one's and
   they share an attacker IP, a source host or an account (multi-day chains,
   beaconing, exfiltration).
5. **Components:** union-find over linked alerts.
6. **Promotion bar:** a component is an incident if it has ≥ 2 distinct rules,
   or ≥ 2 tactics, or one rule alert with severity ≥ 4 and confidence ≥ 0.7, or
   a `promote: true` rule. Anomaly-only components follow P4b's rule.
7. `merged {alerts, events}` (B-3); stable id = hash of sorted member alert
   ids.
8. Output: `incidents.parquet`, `incident_alerts.parquet`.

**Verify:** chain A and chain B each come out as one incident with all their
firewall steps; the 23 single-type incidents stay separate; total incidents is
about 25-35; no giant component.

**Manual work:** read the one-line-per-incident list and flag wrong merges or
splits.

### P7. Numbered chain and path graph (3 h, T0, A)

- One step per **rule** alert. Sorted by `ts_start`; ties and overlaps put the lower
  `stage_no` first; then `rule_id`. Numbered 1..N, no gaps.
- Anomaly alerts are `supporting` evidence on the nearest rule step: shared
  entity first, then the smallest time gap (overlap = 0), then the same tactic,
  then the nearest start, then the lower step number. An anomaly-only incident
  numbers its anomaly alerts.
- A long step (beaconing, exfiltration) gets one number at its start, shows
  `ts_end`, and `ongoing: true` if it runs past later steps.
- Unobserved phases go in `gaps` ("no credential-access evidence in the
  logs"). Never numbered, never invented.
- Step fields: `n`, `ts_start`, `ts_end`, `ongoing`, `action`, `rule_id`,
  `technique`, `technique_name`, `tactic`, `stage_no`, `kill_chain_stage`,
  `src`, `dst`, `event_count`, `success`, `line_sample`, `line_total`,
  `enrichment_flags`, `confidence`, `layer`.
- `chain_text`: `1. Reconnaissance → 2. Initial Access → ...`.
- Path graph (NetworkX, exported as nodes and edges): nodes are external IPs,
  internal hosts, accounts and domains, coloured by zone; directed edges carry
  the step number and a short label (`2. SQL injection x60`).
- CLI: `python -m killchain chain 1` prints the text form.

**Verify (`tests/test_chain.py`):** numbers 1..N consecutive; `ts_start`
non-decreasing; every step has evidence; chain A reads scan → SQLi → web shell
→ data out, in that order.

**Manual work:** read the top 5 chains; mark sentences a non-expert would not
follow.

### P8. Access graph and reach next (3 h, T0, A)

**Access graph**, built once per run into `access_graph.parquet`:

| Edge | From | Strength |
|---|---|---|
| `controls` | account → `10.10.99.1` from `Admin login successful` | 1.0 (the firewall controls every zone) |
| `admin_port` | allowed internal → internal session on 22, 135, 445, 3389, 5985, 5986 | 0.8 |
| `allowed_flow` | any allowed internal → internal session, other ports | 0.4 |
| `zone_neighbour` | inferred: hosts in the same server, DMZ or desktop /24 as a compromised host, from `config/network.yaml` | 0.2, labelled **inferred** |
| Windows edges (`logs_on`, `admin_on`, `member_of`) | only if a Windows log arrives | 0.9 |

Why widened [measured]: internal-to-internal admin-port traffic is only 2,580
flows in the 7 days, all from the two planted attackers, so admin-port edges
alone would leave reach next empty for most incidents.

**Reach next:**
1. Start from compromised nodes: targets of successful steps (`success =
   true`), the source host for internal attackers, accounts that logged in.
2. Breadth-first search, 2 hops, skipping nodes already in the incident.
   Hosts reached at hop 2 through an inferred neighbour are also inferred, so
   an infected desktop's reach to servers through its neighbours is labelled
   inferred and counts half in the risk score.
3. Rank = importance(target) × edge strength × (1.0 for hop 1, 0.5 for hop 2)
   × log(1 + edge count). Importance from `network.yaml`: mgmt 1.0, server and
   DMZ 0.75, IoT 0.5, desktop 0.25.
4. Output `{host, zone, hop, kind (observed | inferred), via [edges with
   evidence lines]}`, a one-line sentence from a template, and
   `likely_tactics` (the stages after the furthest one reached, marked
   heuristic).
5. Empty result: "no internal reach observed in the logs" and the reason.

**Done when:** every incident has a reach list or a stated reason; the
admin-account incidents (5, 7, 15) state that the account controls the
firewall.

### P9. Threat-intel engine (1.5 days, T0, B)

Adds outside and local context to every entity in every incident, and powers
the Threat Intel page. It never changes which incidents or steps exist.

**Scope and safety**
- Look up only public IPs, domains, URLs and file hashes that appear in
  incidents (tens to a few hundred indicators), plus on demand from the UI.
- Private, reserved and documentation ranges (10/8, 172.16/12, 192.168/16,
  127/8, 192.0.2/24, 198.51.100/24, 203.0.113/24) are classified locally and
  never sent. Never send usernames, internal IPs, URL paths of internal hosts
  or log lines.
- Keys come from `.env` (git-ignored). A provider without a key is skipped with
  a note; a network failure never fails the run.

**Providers** (`killchain/enrich/providers/<name>.py`, one interface
`lookup(kind, value) -> {provider, available, malicious, score 0-1, tags,
detail, fetched_at}`), request logic ported from
`AI-SOC/backend/services/enrichment/providers/` with httpx instead of aiohttp
and SQLite instead of Redis:

| Provider | Indicator kinds | Key | Free tier | Score |
|---|---|---|---|---|
| local (always on) | all | none | - | in-log context, see below; no score |
| AlienVault OTX | IP, domain, URL, hash | `OTX_API_KEY` | free | min(pulses / 5, 1) |
| AbuseIPDB | IP | `ABUSEIPDB_API_KEY` | 1,000 checks a day | confidence / 100 |
| VirusTotal | domain, URL, hash, IP | `VIRUSTOTAL_API_KEY` | 4 a minute, 500 a day | min(malicious engines / 10, 1) |
| GreyNoise Community | IP | `GREYNOISE_API_KEY` | limited daily | malicious 1.0, benign 0.0, unknown none |
| abuse.ch URLhaus, ThreatFox | URL, domain, hash, IP | `ABUSECH_AUTH_KEY` | free | listed 1.0 |
| Shodan InternetDB | IP | none | free | at most 0.3 (exposure: ports, CVEs) |
| GeoIP (MaxMind GeoLite2 or ip-api) | IP | `MAXMIND_LICENSE_KEY` optional | free | none (country, ASN for context and impossible travel) |

**Local context** (no network): IP class and zone, country from the logs, ASN
from GeoIP, odd TLD or dynamic-DNS suffix, domain length and entropy, in-log
history (IPS, AV, webfilter, failed-login counts, distinct targets, first and
last seen), whether first seen falls inside the incident window, rarity (how
many internal hosts ever contacted it).

**Engine:** unique indicators → every enabled provider in a thread pool of 4,
5 s timeout, 2 retries with backoff on 429/5xx, per-provider rate limits from
`config/ti.yaml`, cache `data/cache/ti.sqlite` (TTL per provider: OTX 6 h,
AbuseIPDB 24 h, VirusTotal 24 h, others 24 h). `--offline` uses only the cache
and local context. `run_summary.json` counts lookups, cache hits, failures and
skipped providers.

**Per entity:** `reputation` = highest score among the providers that
answered; verdict `known-malicious` (≥ 0.8), `suspicious` (≥ 0.4),
`no-reports`, `unknown` (no provider answered); `tags`, malware families,
first/last seen elsewhere; per-step flags such as `OTX: 12 pulses (Cobalt
Strike)` or `dynamic-DNS domain`.

**Honest caveat:** the data set's IPs and domains are synthetic. Most will
come back `no-reports`; some are real addresses with unrelated history. The UI
says "external reputation" and the risk score gives it 5%.

**Verify:** offline run completes; a second online run makes 0 network calls;
a mocked client proves private IPs and `203.0.113.5` are never sent; `eval
score` is identical with enrichment on and off.

**Manual work (M9):** create the keys below and put them in `.env`; ask the
organisers whether outside calls are allowed while judging (if not, the demo
uses `--offline` with the cache from an earlier run).

| Provider | Sign up | `.env` |
|---|---|---|
| OTX | https://otx.alienvault.com → Settings | `OTX_API_KEY` |
| AbuseIPDB | https://www.abuseipdb.com/register → API | `ABUSEIPDB_API_KEY` |
| VirusTotal | https://www.virustotal.com → profile → API key | `VIRUSTOTAL_API_KEY` |
| GreyNoise | https://viz.greynoise.io → account | `GREYNOISE_API_KEY` |
| abuse.ch | https://auth.abuse.ch | `ABUSECH_AUTH_KEY` |
| MaxMind (optional) | https://www.maxmind.com → GeoLite2 | `MAXMIND_LICENSE_KEY` |

### P10. Risk score and template report (0.5 day, T0, A)

**Risk score (B-1)**, 0-100, parts stored and shown in the UI:

| Part | Weight | Value 0-1 |
|---|---|---|
| Severity | 0.25 | max alert severity / 5 |
| Stage reached | 0.20 | max `stage_no` / 14 |
| Breadth | 0.10 | distinct tactics / 6; full marks at 3 or more |
| Success | 0.15 | 1 if any step got through |
| Asset importance | 0.15 | highest importance of hosts touched |
| Reach next | 0.10 | observed important reachable hosts / 3, capped (inferred counts half) |
| Threat intel | 0.05 | highest entity reputation; 0 offline |

As built (`killchain/score/risk.py`, `docs/contracts.md` "Risk score"):
- steps are the numbered steps; supporting anomalies do not raise stage, breadth or success;
- breadth: 1 at 3 or more distinct tactics (a real multi-stage chain), else one sixth per tactic;
- asset: graph nodes of kind internal host, server or firewall, ignoring reach nodes;
- reach: "important" = importance ≥ 0.75 (server, DMZ, management); desktop footholds get inferred
  same-/24 neighbours (P8);
- threat intel: matched by entity value in `enrichment.json` (verdict not `unknown`); 0 when the file is
  missing; offline cache answers count;
- each part stores a `detail` sentence; ties go by first time, then `incident_id`.

Incidents sorted by score and numbered 1..N (ties by first time). Measured
after tuning (track A item 2, firex-10G): chain A #1 (89.8), chain B #2
(82.3), next is the large one-way transfer to 7.93.184.183 (81.5).
**Manual work (M10):** agree the weights.

**Template report (B-2, always built):** SUMMARY (one sentence), CHAIN (Step 1
... Step N), REACH NEXT, EVIDENCE (5 lines per step with line numbers),
THREAT INTEL, GAPS. Deterministic, offline, cannot invent facts; the fallback
for every agent.

### P10b. Agents (2 days, T1, B)

**Client** `killchain/agents/llm.py`: OpenAI-compatible (`openai` package with
`base_url`), Groq primary, NeevCloud fallback; tiers and cooldown after auth
errors following `AI-SOC/backend/services/agentic/config/llm_service.py`;
temperature 0; 30 s timeout; a queue with retry and backoff for free-tier
token limits; every call cached in `data/cache/llm.sqlite` by hash of model +
prompt, and copied into the run bundle so the UI works without a key.

| Agent | When | Input | Output | Guard |
|---|---|---|---|---|
| Narrator (B-2) | batch, per incident | fact sheet: chain, entities, merged counts, TI verdicts, reach next, score parts, gaps (no raw lines) | 2-sentence summary for a manager, one sentence per step, what happens next, which evidence supports it | every step number, chain IP and account must appear; no IP, account or technique ID outside the facts; one retry, then the template |
| Triage opinion | batch, per incident, **in the same call as the narrator** | same fact sheet | `{verdict: looks_real \| likely_noise, confidence, reasons[]}` | display only; never hides or reorders an incident |
| Incident Q&A | on demand (UI) | question + incident JSON + up to 200 evidence lines read from the log by `byte_offset` | answer citing line numbers | cited lines must belong to the incident; otherwise the answer is rejected |
| Rule writer (B-4 demo) | on demand (UI) | plain-English description + the `events` columns + 3 example rules | YAML rule | validated, run with `--only`, shows alert count and first 5 hits; saved only on a button press |

Prompts live in `killchain/agents/prompts/*.md`. Tests: mocked LLMs that add an
IP, drop a step, or cite a foreign line must all be rejected.

**Free-tier budget.** We run on free tiers of Groq and NeevCloud. Groq's free
limits are per model (August 2026; check https://console.groq.com/docs/rate-limits
when setting up): `llama-3.3-70b-versatile` 30 requests/min, 1,000/day, about
12K tokens/min and **100K tokens/day**; `llama-3.1-8b-instant` 30/min,
14,400/day, 500K tokens/day. NeevCloud's limits are read from its dashboard.
The 70B daily token limit is the constraint, not requests.

| Batch run, 35 incidents | Per incident | Total |
|---|---|---|
| Uncontrolled (full JSON in, long report out, separate triage call) | ~3,500 tokens | ~120K: over the 70B daily limit |
| Planned (fact sheet ~1,200 in, ~450 out, triage in the same call) | ~1,700 tokens | ~60K: fits, with room for retries |

How we stay within the limits:
1. **One call per incident:** the narrator returns the report and the triage
   verdict as one JSON object.
2. **Small prompts:** the fact sheet has no raw lines; `max_tokens` caps the
   output; prompt length is checked in a test.
3. **Cache everything** by hash of model + prompt. A rerun calls the LLM only
   for incidents whose fact sheet changed, so rule tuning costs almost nothing.
   The cache is bundled with the run, so the UI and demo work without a key.
4. **LLM off while building:** `--no-llm` is the default during development
   (template reports); the LLM runs at most once a day and for the final run.
5. **Rate limiter per model:** token buckets for requests and tokens per minute
   and per day, set from `config/llm.yaml`; reads Groq's `x-ratelimit-*`
   headers; on 429 waits for `retry-after` with backoff instead of retrying at
   once.
6. **Fallback chain, each with its own quota:** Groq 70B → Groq 8B →
   NeevCloud → template report. A report never fails; a template is labelled
   as such (`report_source`).
7. **Right model per job:** 70B for the narrator and rule writer; 8B for Q&A,
   with evidence capped at about 60 lines and answers cached per question.
8. **Limits on on-demand agents:** a small per-minute cap on Q&A and rule
   drafts from the UI, with a clear "limit reached, try again in N s" message.
9. **Budget meter:** tokens used today and remaining, per model, on the System
   page and in `GET /health`.
10. **Demo safety:** all batch reports are prebuilt and bundled; 2-3 Q&A
    questions and one rule draft are rehearsed beforehand so they are cached.
11. **One key per provider for the app.** Each person uses their own key only
    for their own development; we do not rotate several free accounts to get
    around limits, which is likely against the providers' terms.

**Manual work (M10):** create Groq and NeevCloud keys; set
`LLM_PRIMARY_BASE_URL=https://api.groq.com/openai/v1`, `LLM_PRIMARY_API_KEY`,
`LLM_PRIMARY_MODEL_LARGE` (e.g. `llama-3.3-70b-versatile`),
`LLM_PRIMARY_MODEL_SMALL` (e.g. `llama-3.1-8b-instant`), and the same four
`LLM_FALLBACK_*` values from the NeevCloud dashboard; set
`LLM_MAX_REQUESTS_PER_MINUTE` under the provider limit. Read 5 narrator
reports beside their templates and fix the prompt, not the output.

### P11. Bundle and API (1 day, T0, B)

**Bundle:** `python -m killchain bundle --run ...` writes
`incidents/<n>.json`, `index.json`, `incident_lines.parquet`, `alerts.json`
(list rows), `unexplained.json`, `ti.json`, `run_summary.json`.

**API (FastAPI, no login)** loads the bundle at start; incident files are kept
in a dict, so lookups take microseconds. Response shapes follow AI-SOC's where
an AI-SOC component is reused, so components port with minimal changes.

| Endpoint | Returns | Used by |
|---|---|---|
| `GET /health` | run name, counts, data quality, TI and LLM status | top bar, System page |
| `GET /dashboard/summary` | KPI tiles, incidents by risk band, tactic coverage, alerts per hour, top attackers and targets | Dashboard |
| `GET /incidents` | list by risk; filters `severity`, `tactic`, `technique`, `entity`, `q`, `limit`, `offset` | Incidents |
| `GET /incidents/{id}` | full incident (`id` = number or stable hash) | Incident page |
| `GET /incidents/{id}/path` | chain, graph nodes and edges, reach next | Incident page (FR-5, FR-6, the PRD example) |
| `GET /incidents/{id}/events?step=&offset=&limit=` | evidence lines, raw text read at `byte_offset` | Evidence tab |
| `GET /incidents/{id}/report?source=ai\|template` | report Markdown | Report tab |
| `POST /incidents/{id}/ask` | Q&A answer | Ask tab |
| `GET /alerts` | alerts with filters, including `incident=none` | Alerts |
| `GET /unexplained` | anomaly alerts not promoted | Alerts → Unexplained |
| `GET /mitre/catalogue`, `GET /mitre/matrix`, `GET /mitre/techniques/{id}` | **same shapes as AI-SOC** (`web_app/backend/app/routes/mitre.py`) | MITRE page, unchanged |
| `GET /ti/indicators`, `GET /ti/indicators/{value}`, `POST /ti/lookup` | indicators, provider results, on-demand lookup | Threat Intel |
| `GET /rules`, `GET /rules/{id}`, `POST /rules/draft`, `POST /rules/test`, `POST /rules/save` | rules with hit stats; rule writer | Rules |
| `GET /entities/{value}` | every incident and alert involving an IP, user or domain | entity drawer |
| `GET /live/status`, `GET /live/stream` (Server-Sent Events) | live-mode state and changed incident ids | Live page, incident list |
| `GET /metrics` | the eval `metrics.json` | Evaluation page |

**MITRE backend:** reuse the pure half of
`AI-SOC/web_app/backend/app/services/mitre_matrix.py` (catalogue loading,
`normalise_technique`, `technique_url`, the shaping after the Mongo query) and
replace the Mongo aggregation with one DuckDB `GROUP BY technique,
subtechnique` over `alerts.parquet` returning the same row shape (count, max
severity, per-severity counts, last seen, open, correlated). The technique
detail `$facet` becomes 5-6 small `GROUP BY` queries. Drop tenancy, RBAC and
`ReportFilters`; keep the query parameters the frontend sends (`preset`,
`start`, `end`, `severity`) and map "open" to "alert not in an incident" and
"correlated" to "alert in an incident".

404 for unknown ids, CORS for the dev server, Swagger at `/docs`, gzip. The
`eval` open-time check calls `/incidents/{n}/path` for every incident (target
p95 < 500 ms).

### P12. UI: the AI-SOC React app, trimmed and extended (3 days, T0, B with A on day 6)

**Base.** Copy `AI-SOC/web_app/frontend` into `web/`. Keep the stack and look:
React 19, Vite 7, TypeScript, Tailwind 4, Radix UI, `components/ui/*`,
TanStack Query, axios, lucide-react, recharts, react-force-graph-2d,
react-markdown, the dark theme and layout (`MainLayout`, `Sidebar`,
`Topbar`, `StatusBar`, `CommandPalette`).

**Remove** (half a day): login, register, `authStore`, `RequireAuth`,
`AuthBootstrap`, tenant switcher, licence screens, MSSP, compliance, admin
users, settings for SIEM/response, review queue, gamification and every page
not listed below. `lib/api.ts`: base URL from `VITE_API_URL` (default
`http://localhost:8000`), no auth header.

**Pages:**

| Route | Page | Built from | Content |
|---|---|---|---|
| `/` | Dashboard | `pages/Dashboard.tsx`, `components/dashboard/ExecutiveTiles.tsx` | KPI tiles (events parsed, alerts, incidents, critical incidents, time span, run time, peak memory), incidents by risk band, kill chain coverage bar (tactics reached across incidents), alerts per hour (recharts), top attackers and targets, data-quality card (frozen-clock rows excluded, junk bytes), TI status |
| `/incidents` | Incident list | `pages/CorrelationGraph.tsx` (`IncidentRow`, stat cards, search) | number, title, risk bar and band, tactic chips in kill chain order, merged alerts and events (B-3), first/last time (IST), triage verdict badge, TI verdict; sort by risk (default, B-1), filter by tactic, technique, entity; live badge for changed incidents |
| `/incidents/:id` | Incident page | `pages/command-center/CommandCenter.tsx` (`IncidentDetailsPanel`, `NarrativeHeader`, `AttackTimeline`, `CorrelationSidebar`), `components/reports/IncidentReportCard.tsx` | **Header:** summary sentence, risk score with its parts, severity, time span, merged counts. **Tabs:** Attack path (new graph, below), Timeline (AttackTimeline with date and time, step number, technique, tactic, kill chain stage, success badge, evidence count), Reach next (ranked list with the sentence and edge paths, observed vs inferred), Threat intel (per entity, provider cards), Evidence (paged raw lines with line numbers, from the API), Report (narrator Markdown, toggle to template), Ask (Q&A box), ATT&CK (mini matrix of this incident's techniques) |
| `/mitre` | MITRE ATT&CK | **`pages/Mitre.tsx`, `components/mitre/AttackMatrix.tsx`, `heat.ts`, `TechniqueDetailPanel.tsx`, `lib/mitre-api.ts`, `types/mitre.ts`, ported as is** | heatmap, technique drill-down, CSV / Navigator / JSON export; links go to `/alerts?technique=` and `/incidents?technique=` instead of AI-SOC's alert list |
| `/alerts` | Alerts | `pages/Alerts.tsx` (table, filters), trimmed | every alert with rule, technique, entities, time, incident link; tabs All / Not in an incident / Unexplained (anomaly) |
| `/threat-intel` | Threat Intel | `components/alerts/ThreatIntelPanel.tsx`, `lib/threatIntelDisplay.ts` | indicator table (value, kind, verdict, providers that flagged it, incidents), detail drawer with each provider's result, on-demand lookup box |
| `/rules` | Rules | new, using `components/ui/*` | rule list (id, technique, kind, status, alerts, background alerts, last run time), YAML viewer, rule-writer agent with test results and Save |
| `/live` | Live | new | live-mode switch, tail position, lines per second, newest alerts streaming in (SSE), changed incidents |
| `/evaluation` | Evaluation | new | the seven PRD metrics against Good and Great, per-incident recall and label table, per-rule table, timings and memory per stage |
| `/system` | System | `pages/SystemHealth.tsx`, trimmed | pipeline stages with status, time and memory; data quality; TI provider status and cache hits; LLM status |

**The attack path graph** (new component `components/path/AttackPathGraph.tsx`,
react-force-graph-2d as in AI-SOC's `GlobalAlertsGraph`):
- left-to-right layout (`dagMode="lr"`) so the story reads in order;
- node types: external attacker, internal host, server, firewall management,
  account, domain; colours from AI-SOC's `ENTITY_COLORS`; size by importance;
- edges directed and labelled with the step number and short action
  (`3. web shell x40`), coloured by tactic; a play button highlights steps 1..N
  in order;
- reach-next nodes drawn dashed, observed in one colour and inferred in another;
- click a node to open the entity drawer (all incidents and alerts with it,
  TI result); click an edge to see its evidence lines;
- PNG export.

**Shared pieces:** `SeverityBadge`, tactic chip in kill chain order, risk bar,
entity drawer, IST time formatting (date and time, not time only), loading
skeletons and empty states on every page, keyboard shortcuts via
`CommandPalette` (jump to incident by number).

**Done when:** all pages run against the real bundle; someone who has not seen
the project explains incident 1 within a minute; the MITRE page behaves as in
AI-SOC.

**Manual work (M11):** click through every page with the real run; A checks
against FR-5, FR-6, B-1, B-2, B-3; screenshots for the README.

### P13. Full run and performance (0.5 day, T0, A)

- `python -m killchain run --input data\raw\firex-10G.log --name firex-10G
  [--offline] [--no-llm]` runs every stage and writes `run_summary.json`.
- Targets: under 1 h and under 8 GB on the 50 GB tier. Estimates for 50 GB
  [assumption]: parse about 7-8 min (about 8x the 6.54 GB file), peak about
  4.5 GB (memory depends on workers, not file size); detection a few minutes.
  DuckDB is capped at 6 GB and runs after the parser exits.
- If slow: per-rule timings; prefilter heavy rules by `log_type` /
  `log_subtype`; materialise the `ts_valid` subset once as a DuckDB table.
- Re-run `eval score`; fix misses by changing rules, never the evaluation.
- Failure modes to test: empty file, truncated file, no stuck region, only
  binary, no network, no LLM key.
- Status: development half done (Track A item 3). `python -m killchain run`
  (`killchain/run/`) runs every stage, writes the `pipeline` record into
  `run_summary.json` and `pipeline.json`, and has `--reuse-parsed` and
  `--from STAGE`; every failure mode above is covered by `tests/test_run.py`
  on small synthetic logs. On firex-10G (`--offline --no-llm`): exit 0,
  187 s, peak 6.2 GB, metrics unchanged. The 50 GB tier run is deferred
  by the user.

### P14. Docker, README, demo (1 day, T0, both)

**Docker Compose** (`docker-compose.yml`):

| Service | Image | Does |
|---|---|---|
| `pipeline` | `docker/Dockerfile.pipeline` (python:3.12-slim) | one shot: `python -m killchain run --input /data/raw/<file>`; mounts `./data`; reads `.env` |
| `api` | `docker/Dockerfile.api` | `python -m killchain serve --run /data/runs/<run>` on 8000; mounts `./data` read-only (cache read-write) |
| `web` | `web/Dockerfile` (node build, then nginx) | serves the React build on 8080, proxies `/api` to `api` |
| `live` | same as `pipeline`, profile `live` | tails a log file and updates the run |

`docker compose up` serves the bundled run; `docker compose run pipeline`
processes a new file. A sample bundle (a small run) is committed under
`examples/` so the UI works on a fresh clone before the 6.5 GB file is
processed.

**README:** what it does; quick start with Docker and without; the measured
results table (all seven PRD metrics, the tier, silver truth stated); pipeline
stages and timings; screenshots; how to add a rule (B-4) with a full example;
optional keys (`.env`) and what changes without them; data-quality findings;
limits.

**Demo (5 min):** one command → run summary → Dashboard → incident 1 (chain A):
summary, path graph playing steps 1..N, reach next, threat intel, report →
MITRE page → write a rule with the rule writer and test it → live mode replay
showing a new incident appear → Evaluation page. Tag `v1.0`.

**Manual work (M13):** Docker Desktop; clean-clone test on the second laptop
following only the README; submission rules; rehearse twice; backup video.

### P15. Live mode (1 day, T1, A)

- Tailer adapted from `FileTailer` in `AI-SOC/agent/soar_agent.py` (follows
  appends, rotation, truncation; checkpoints offsets).
- Every 2 s: parse new lines with the parser's line functions; append to an
  in-memory DuckDB table holding the last 72 h; rerun rules whose window fits;
  rerun correlation for affected entities; rebundle changed incidents; push
  their ids over `GET /live/stream`.
- `tools/replay.py` appends lines from a saved slice at a chosen speed, for the
  demo.
- Target: a new attack appears in the UI within 5 s of its lines being written.

### P16. Stretch (T2)

1. Sigma import for single-event Sigma rules with a field-name map.
2. Windows adapter rules, only if a Windows log arrives: field aliases first,
   then 4625/4624, 5145 on IPC$ and ADMIN$, 4769 RC4, 7045, 4688,
   4720/4728/4732, 1102; host-name map; `logs_on` / `admin_on` edges.
3. UI polish: saved views, light theme, shareable incident links with the graph
   state.

---

## 5. Two tracks, built in parallel

The work is split into two tracks. Each person owns one track and works through
its phases in order. Phase numbers give the order **inside** a track, not
across tracks: while A does P1, B does P12, not P1.

| | Track A: pipeline and detection | Track B: product |
|---|---|---|
| Owner | **you** (fill in the name) | **teammate** (fill in the name) |
| Goal | turn raw logs into correct alerts, incidents, chains and reach next, and prove it with the evaluation | show those results through the API and a UI as good as AI-SOC's, with threat intel, agents and Docker |
| Phases, in order | P0 (A part) → P1 → P2 → P3 → P5 → P4 → P4b → P6 → P7 → P8 → P10 → P13 → P15 → P16 | P0 (B part) → P12 (scaffold) → P11 → P12 (pages) → P9 → P10b → P14 |
| Writes code in | `killchain/parser`, `db.py`, `__main__.py`, `attack`, `detect`, `anomaly`, `correlate`, `graph`, `score`, `report`, `eval`, `live`; `rules/`, `config/`, `eval/`, `tests/` | `killchain/api`, `enrich`, `agents`; `web/`, `docker/`, `docker-compose.yml`, `examples/` |
| Reads but does not edit | `killchain/api` | everything in track A's folders |
| Shared | `docs/`, `README.md`, `requirements.txt`, `.env.example`, `docs/contracts.md` | same |

P5 (labels) comes before P4 in track A because every rule needs the label
helper; it is about 2 hours.

### 5.1 Where the tracks meet

Only through files, never through each other's code:

| Hand-off | Produced by | Used by | When |
|---|---|---|---|
| `docs/contracts.md` (contracts B and C, exact field names and types) | A | B | end of P0, day 1 |
| `examples/sample-run/` (one hand-written incident in contract C, plus `index.json`, `alerts.json`, `run_summary.json`) | A | B builds the API and every UI page against it | end of P0, day 1 |
| `alerts.parquet`, `alert_evidence.parquet` | A (P3, P4) | B's MITRE backend and Alerts page | day 3 onward |
| `data/runs/<run>/` complete bundle input (incidents, chains, reach next, scores) | A (P6-P10) | B's bundle step and API | day 5 |
| `enrichment.json` (per-entity threat intel) | B (P9) | A's risk score (5% weight) | day 4; until then the score uses 0 for threat intel |
| `report.json` (narrator output and triage verdict per incident) | B (P10b) | bundled with the run | day 5-6; until then the template report |

**Contract rule:** contracts B and C are frozen at the end of day 1. A change
after that is agreed in chat first, written into `docs/contracts.md`, and the
sample in `examples/` updated in the same commit.

### 5.2 Who does what in P0

P0 takes about an hour and is split so neither person waits:

| You (track A) | Teammate (track B) |
|---|---|
| 1. Create the folders from section 3 (`config/`, `eval/`, `web/`, `docker/`, `examples/`, `tests/`, `rules/anomaly/`, `killchain/{agents,enrich,anomaly}/`) | 1. Clone the repo; install Node.js 20 LTS and Docker Desktop |
| 2. Add `duckdb`, `httpx`, `openai` to `requirements.txt`; write `.env.example` with every key name from P9 and P10b | 2. Copy `logs.zip` and unzip into `data/raw/`; `pip install -r requirements.txt` |
| 3. Write `docs/contracts.md` and the sample run in `examples/sample-run/` (incident 1 = chain A with its real IPs and times) | 3. Sign up for OTX, AbuseIPDB, VirusTotal, GreyNoise, abuse.ch, Groq, NeevCloud keys (some take a day); fill `.env` |
| 4. Push; post "contracts frozen" in chat | 4. Copy `AI-SOC/web_app/frontend` into `web/`, strip login, tenancy and unused pages |
| 5. Start P1 | 5. Pull the contracts and sample; start P11 (API serving the sample) |

### 5.3 Git rules for two tracks

- Each person works on short branches named after the track: `a/<task>`,
  `b/<task>`. Merge into `main` when the task's checks pass; `git pull
  --rebase origin main` before merging.
- Stay inside your track's folders. A change in the other track's folder is
  made by its owner, on request.
- Shared files (`requirements.txt`, `.env.example`, `README.md`, `docs/`):
  small commits, pulled before editing.
- Track A posts `eval score` numbers in chat after every rule or correlation
  change. Track B posts a screenshot after every new page.
- `main` must run end to end every evening (`python -m killchain run` on the
  sample or real data, and the UI against it).

### 5.4 7-day schedule

| Day | Track A (you) | Track B (teammate) |
|---|---|---|
| 1 | P0 (A part: folders, requirements, `.env.example`, **contracts and sample run**); P1 leftovers (CLI, DuckDB view, explorer); start P2 silver truth | P0 (B part: tools, data, API keys); copy AI-SOC frontend to `web/` and strip auth and unused pages; P11 API skeleton serving the sample run |
| 2 | P2 finish (`eval score`); P5 labels; P3 rule engine and validator; first rules R01, R05 | Incident list and incident page (header, timeline, tabs) on the sample; MITRE backend on DuckDB and the MITRE page ported |
| 3 | P4 rules R02-R12 with background review | Attack path graph component; reach-next tab; evidence tab; entity drawer |
| 4 | P4 rules R13-R24; P4b anomaly layer | P9 threat-intel engine (providers, cache, local context); Threat Intel page |
| 5 | P6 correlation; P7 chain; P8 access graph and reach next; first real bundle | Wire every page to the real bundle; Dashboard, Alerts, Rules pages; P10b LLM client and narrator |
| 6 | P10 risk score and template; P13 full run and tuning; P15 live mode | P10b triage, Q&A, rule writer; Live, Evaluation, System pages; P14 Docker Compose |
| 7 | Tuning on `eval score`; README results; help with UI review (M11) | UI polish and empty states; clean-clone test (M13); demo rehearsal and video |

Daily: 15-minute sync at start and end; `eval score` posted after every rule
change; `main` must run end to end every evening.

---

## 6. Manual work at a glance

| # | When | Who | What |
|---|---|---|---|
| M1 | Day 1 | A | Add B on GitHub |
| M2 | Day 1 | both | Copy `logs.zip` to the second laptop; `pip install -r requirements.txt`; Node.js 20 LTS; Docker Desktop |
| M3 | Day 1 | A | Send the organiser questions (section 7) |
| M4 | Day 1-7 | both | Review the 25 silver incidents; keep `eval/reviewed.yml` up to date |
| M5 | Day 2 | both | Agree the rule format (30 min) |
| M6 | Day 3-4 | both | Read background hits per rule; decide threshold trade-offs |
| M7 | Day 5 | both | Flag wrong merges or splits in the incident list |
| M8 | Day 5 | both | Read the top 5 chains for unclear sentences |
| M9 | Day 1, used day 4 | B | Create OTX, AbuseIPDB, VirusTotal, GreyNoise, abuse.ch (and optionally MaxMind) keys; put them in `.env` |
| M10 | Day 1, used day 5 | B | Create Groq and NeevCloud keys and fill the `LLM_*` values; agree risk weights; compare narrator reports with templates |
| M11 | Day 6-7 | both | Click through every page; screenshots |
| M12 | Day 6 | A | Timed full run with other apps closed |
| M13 | Day 7 | both | Clean-clone test with Docker; submission rules; rehearse twice; backup video |

---

## 7. Open questions for the organisers

None block the build.

1. Will the scoring file contain a Windows log or only FortiGate lines?
2. Are the frozen-clock region and the appended `.deb` packages intended, and
   can planted events fall inside them?
3. How are detections matched to planted events (line, byte offset,
   incident)? Is a "step" one event or one stage?
4. Which ATT&CK IDs count as correct when an incident lists several, and does
   the parent technique count?
5. Are outside services (threat intel, an LLM) allowed during judging?
6. Which tier are we scored on, given `firex-10G.log` is 6.54 GB?
7. Can we have the manifest that matches `firex-10G.log`?

---

## 8. Targets and how we prove them

| PRD metric | Good | Great | Proof |
|---|---|---|---|
| Detection | > 70% | > 90% | step recall on the silver truth (25 incidents) |
| Correct labels | > 60% | > 85% | exact, parent and alternate label accuracy |
| Attack path | half | all | path order on every multi-step incident |
| False alarms | < 30% | < 10% | reviewed-false incidents / all incidents |
| Processing time | < 3 h | < 1 h | `run_summary.json` |
| Memory | < 16 GB | < 8 GB | peak RSS of the process tree, per stage |
| Investigation speed | < 2 s | < 500 ms | p95 of `GET /incidents/{n}/path` |

Our aim: all "great". Measured so far: parsing 55 s at 4.5 GB.

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| Judges' file has variants we did not see | Behaviour-based thresholds with wide margins; anomaly layer; the shapes are the same at every tier per the PRD |
| Unrelated attacks merge | Hub cap, source-aware weights, time rule, promotion bar, tuned on the false-alarm metric |
| Frozen clock fires rate rules | `ts_valid` in the view, on by default for every window rule |
| Labels differ from the judges' | Primary = the manifest's technique; `alt_techniques`; per-line overrides; one edit per rule |
| Reach next empty | Widened access graph, `controls` edges, inferred reach clearly labelled |
| LLM or TI fails in the demo | Caches bundled in the run, template report, `--offline` |
| UI work overruns | B starts on day 1 against a sample bundle; pages ranked: Incident page, Incidents, MITRE, Dashboard first; Live, Evaluation, System last |
| A rule is slow on a bigger tier | Per-rule timings, prefilters, materialised `ts_valid` table |
| One person blocked | Contracts let both build in parallel; take the next item in the schedule |

---

## 10. Checklist

- [ ] P0 setup, contracts B and C frozen
- [ ] P1 CLI, DuckDB view, explorer (parser done)
- [ ] P2 silver truth for 25 incidents, `eval score` table
- [ ] P3 rule engine and validator
- [ ] P4 rules R01-R24, every silver incident ≥ 95% of its lines, background reviewed
- [x] P4b anomaly layer
- [ ] P5 labels, 7-phase stage, per-line overrides
- [x] P6 incidents: both chains whole, no giant merge
- [x] P7 numbered chains and path graphs
- [x] P8 access graph and reach next for every incident
- [ ] P9 threat-intel engine (7 providers) online, offline and cached; Threat Intel page
- [x] P10 risk score and template report
- [ ] P10b narrator, triage opinion, Q&A, rule writer, all with guards and caches
- [ ] P11 bundle and API, p95 < 500 ms
- [ ] P12 React UI: Dashboard, Incidents, Incident page with attack path graph, MITRE (as in AI-SOC), Alerts, Threat Intel, Rules, Live, Evaluation, System
- [ ] P13 full run within targets, failure modes tested
- [ ] P14 Docker Compose (pipeline, api, web, live); README tested on a clean clone; demo rehearsed; `v1.0`
- [x] P15 live mode: new attack visible within 5 s (chain A replay: API-visible max 4.1 s after a step's last line, 12 of 12 steps)
- [ ] P10b LLM budget: one call per incident, cache, rate limiter, fallback chain, budget meter
