# P8 verify: access graph and reach next

All commands ran in PowerShell with cwd `c:\Users\hegde\Nishant\Projects\CyberForge_Hackathon\killchain`,
miniconda `python`, run folder `data\runs\firex-10G` (prepared `events.duckdb` present). First iteration
(no `docs/tasks/p8-review.json` existed).

## What was built

- `config/reach.yaml`: admin ports, edge strengths, hop factors, caps, neighbour zones, foothold skip
  tactics, login description, denied actions (plan item 9).
- `killchain/graph/access.py`: `load_settings`, `build_access(con, settings) -> (edges, hosts)` per D10.
  DuckDB 2.0 safe (`con.sql(sql).pl()`, `con.execute(sql).fetchone()`), session TimeZone UTC via
  `db.configure`.
- `killchain/graph/reach.py`: `footholds`, `touched`, `likely_tactics`, `access_digraph`, `reach_next`
  (NetworkX `bfs_layers`, rank with `math.log`), `merge_graph` per D11.
- `killchain/graph/cli.py`: `compute_reach` and `reach_main`; `python -m killchain reach --run <run> [N]
  [--parsed DIR] [--force]` registered in `killchain/__main__.py` (removed from `PLANNED`).
- `tests/test_reach.py`: 19 tests (access edges and hosts, ranking, hop halving, importance, session
  count, cap and k/m counts, inferred-only and "connections only inside the incident" sentences, touched
  nodes, foothold rules, desktop footholds, the `controls` exception, the three empty reasons,
  likely_tactics, merged graph and idempotency, `validate_bundle` on an assembled incident, CLI build /
  reuse / `--force` / print / missing inputs, contract error writes nothing, real-run checks).
  `tests/test_db.py::test_cli_lists_stages` now expects `reach      ready` and uses `score` / P10 as the
  planned example.
- Docs: `README.md` row 3b, `docs/build-plan.md` checklist P8 ticked, `docs/contracts.md` run layout
  (access_graph.parquet, access_hosts.parquet, reach.json, reach/_stats.json). The prompt names
  `killchain/killchain/README.md`; that file does not exist, so the phase row in the repo `README.md`
  (the one P7 updated) was updated.

## Commands and results

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `python -m killchain detect --run c:\...\data\runs\firex-10G` | 0 | 57 alerts, 44,623 evidence lines from 35 rules in 13.0 s (peak 991 MB); rule layer 32, anomaly layer 25 |
| 2 | `python -m killchain correlate --run c:\...\data\runs\firex-10G` | 0 | 25 incidents (0 anomaly-only) from 57 alerts; unexplained 1, below bar 0, largest incident 8 alerts; 0.27 s (unchanged from P6/P7) |
| 3 | `python -m killchain chain --run c:\...\data\runs\firex-10G` | 0 | 25 incidents, 56 steps (14 ongoing), 19 gaps, 44,622 evidence lines, 0 contract errors; 0.28 s (unchanged from P7) |
| 4 | `python -m killchain reach --run data\runs\firex-10G --force` | 0 | access graph `{admin_port: 90, controls: 3}` built in 0.72 s, 1,387 internal hosts; 11 incidents with reach, 14 with a stated reason, 0 contract errors; 1.22 s |
| 5 | `python -m killchain reach --run data\runs\firex-10G` (no `--force`) | 0 | access files reused (0.12 s to read), 0.94 s; same output |
| 6 | `python -m killchain reach --run data\runs\firex-10G 1` (also 2, 3, 6, 11) | 0 | reach list and sentence printed (below) |
| 7 | `python -m killchain chain --run data\runs\firex-10G 1` / `2` / `3` | 0 | text form now ends with the real reach sentence |
| 8 | `python -m killchain eval score --run c:\...\data\runs\firex-10G --parsed c:\...\data\parsed\firex-10G` | 0 | see metrics table |
| 9 | `python data\tmp\p8_api_check.py` and `python data\tmp\p7_api_check.py` (not committed) | 0 | all assertions pass |
| 10 | `python -m pytest -q` | 0 | **213 passed** in 45.5 s (194 before P8 + 19 new) |

### Access graph (measured)

- `controls`: 3 edges to 10.10.99.1: Deepika.Khan 3 logins, svc_backup30 1, parul.sinha 1.
- `admin_port`: 90 edges from 2 sources (10.10.10.44 to 60 servers, 2,400 sessions; 10.10.10.63 to 30
  servers, 180 sessions) = 2,580 sessions.
- `allowed_flow`: 0 (the one other allowed internal-source flow goes to 198.51.100.32, zone internet).
- Hosts: 1,387 internal IPs: desktop 231, dmz 1, iot 231, lan 462, mgmt 232, server 230.
- `reach/_stats.json`: `wall_secs 1.22, peak_rss_mb 314, access_secs 0.72, access_rebuilt true,
  access_sessions 2585, incidents 25, incidents_with_reach 11, incidents_empty 14, reachable 83,
  contract_errors 0`.

All numbers match the plan's planning queries.

### Contract check

Every one of the 25 `incidents/<n>.json` passes `contracts.validate_bundle` against `index.json` and
`alerts.json` (0 errors; checked in-process before writing, again by `data\tmp\p8_api_check.py` from disk,
and by `test_real_run_reach`). `/health`: `status ok`, `contract_errors 0`, counts 25 incidents, 57 alerts.

### Metrics (eval score)

| Metric | P7 | P8 |
|---|---|---|
| detection_recall | 100.0 % | 100.0 % |
| label_accuracy | 100.0 % | 100.0 % (exact 99.3 %, parent 99.3 %) |
| attack_path_rebuilt | 100.0 % (25/25) | 100.0 % (25/25) |
| multi_step_rebuilt | 4/4 | 4/4 |
| false_alarm_share | 0.0 % | 0.0 % |
| our incidents / spanning truth | 25 / [] | 25 / [] |
| processing_secs | 69 s | 69.91 s (sum of every `_stats.json` `wall_secs`; reach adds 1.22 s) |
| peak_rss_mb | 4,477 MB | 4,477 MB (reach 314 MB) |

No metric regressed. Timing stays in seconds: detect 13.0 s, correlate 0.27 s, chain 0.28 s, reach 1.22 s.

**Scorer hook:** `killchain/eval/score.py` has no reach-next or next-path metric, and the silver truth has
no reach data, so there is nothing to wire. The reach stage's `wall_secs` and `peak_rss_mb` are already
picked up by `processing_secs` / `peak_rss_mb`, because `load_run` reads every `_stats.json` under the run.

## Admin-account incidents ("done when")

| Incident | Account | Reach next |
|---|---|---|
| #3 (R05 + R15) | svc_backup30 | `svc_backup30 logged in to the firewall management interface firewall (10.10.99.1), which controls every zone.` 10.10.99.1, mgmt, hop 1, observed, via `controls` x1 |
| #6 (R07, alert user `admin`) | parul.sinha (from the evidence-line join) | `parul.sinha logged in to the firewall management interface firewall (10.10.99.1), which controls every zone.` |
| #11 (R05) | Deepika.Khan | `Deepika.Khan logged in to the firewall management interface firewall (10.10.99.1), which controls every zone.` via `controls` x3 |

The build plan's "done when" names incidents 5, 7 and 15; correlation numbering has changed since then,
and these are the same three admin-account incidents. Every incident has a reach list or a sentence starting
"No internal reach observed in the logs" (`docs/tasks/p8-reach.txt` lists all 25).

## Chain A and chain B

### Chain A: #1, 32.127.48.11 → portal 10.10.20.20

chain_text: `1. Initial Access → 2. Discovery → 3. Exfiltration → 4. Initial Access → 5. Persistence →
6. Command and Control → 7. Exfiltration` (rule steps R02 scan → R16 SQLi → R20 web shell → R12 data out).

Footholds: `10.10.20.20` (the SQLi, web-shell and transfer steps succeeded against it).
Sentence: `No internal connections from portal (10.10.20.20) were observed; 230 hosts in the same server
subnet (e.g. 10.10.20.31) are the likely next targets (inferred).`

Top reach next (all hop 1, inferred, via `10.10.20.20 zone_neighbour`, zone server):
`10.10.20.31, 10.10.20.13, 10.10.20.19, 10.10.20.12, 10.10.20.163, 10.10.20.10, 10.10.20.51, 10.10.20.25,
10.10.20.23, 10.10.20.43`. likely_tactics `["impact"]` (the chain reached exfiltration, stage 13).

Does it make sense? Yes, within what the logs show. `config/network.yaml` has no separate DB or AD zone: the
only server zone is 10.10.20.0/24 (230 server hosts, importance 0.75), which is where any DB or directory
server in this network sits, and the portal 10.10.20.20 is the DMZ host inside that /24. The logs show no
allowed session from the portal to any other internal host, so every entry is inferred (zone_neighbour,
strength 0.2) rather than observed. With equal importance and strength, the ranking falls back to each
host's event count, so the busiest servers come first. Management (10.10.99.0/24) is not listed because
neighbours are drawn only inside the foothold's own /24. The graph for #1 gains 10 reach nodes
(`reach: inferred`) and 10 dashed `reach_inferred` edges labelled `same server subnet (inferred)`.

### Chain B: #2, 10.10.10.118 → 7.154.5.35

chain_text: `1. Execution → 2. Command and Control → 3-4. Exfiltration → 5. Discovery → 6. Exfiltration →
7. Discovery → 8. Exfiltration` (R24 malware → R11 beaconing → A10/R12 exfiltration, then the A04/A08
hourly outliers).

Footholds: `10.10.10.118` (internal infected source). Reachable: none.
Sentence: `No internal reach observed in the logs: 10.10.10.118 opened no allowed sessions to other internal
hosts, and inferred neighbours are only drawn for server and DMZ subnets.` likely_tactics `["impact"]`.

Does it make sense? Yes. The infected desktop only talks to the outside C2/exfil address 7.154.5.35; the
access graph has no admin-port or allowed internal session from it, and it is in the desktop zone, where
inferred neighbours are not drawn by design (D10/D11). An empty list with its reason is the honest answer.

### Other reach results worth noting

- #8 (10.10.10.44 lateral movement) and #9 (10.10.10.63): both attackers have observed admin-port edges
  (60 and 30 servers), but every server they reached is already in the incident's evidence, so no observed
  host is reported. The sentence says so: `Every connection seen from ... goes to hosts already in this
  incident; 171 (201) hosts in the same server subnet ... are the likely next targets (inferred).`
- #4 (R14 logging disabled): the only foothold is the firewall itself (a successful A01 step to it), which
  has no outgoing internal sessions, so it gets the "opened no allowed sessions" reason.

## Deviations from the plan text (small, in track A code only)

- D11.6 "inferred only" sentence: when observed edges exist but all lead to hosts already in the incident,
  the sentence starts "Every connection seen from {footholds} goes to hosts already in this incident"
  instead of "No internal connections ... were observed", which would be false for #8 and #9.
- The `{zone}` in that sentence is the most common zone of the inferred hosts (ties go to the best-ranked
  host), so #5 (foothold 10.10.20.31, top inferred host the DMZ portal) reads "same server subnet".
- Singular/plural forms ("1 internal host was reached", "1 more is inferred").

## Contract vs API / UI (read-only check of `killchain/api/`, `web/`)

No mismatch found. What the UI reads, and what reach writes:
- `ReachNext.tsx` `EDGE_LABEL` keys `controls`, `admin_port`, `allowed_flow`, `zone_neighbour`:
  `via[].edge` uses exactly these. `via[].count` is the session/login count (0 for inferred, which the UI
  hides). `via[].lines` are evidence objects `{source, line, byte_offset, ts}` (up to 5, earliest first).
  The UI re-sorts by hop, then observed first (stable), so our rank order holds inside each group.
- `pathGraph.ts`: reach nodes carry `reach: observed|inferred`; reach edges have `kind
  reach_observed|reach_inferred` and `step null` and are drawn dashed.
- `api/entities.py`: node ids are raw values; a reach host (e.g. `/entities/10.10.20.31`) returns 200 with
  role `reachable next` for incident 1 (checked).
- `GET /incidents/1/path` returns `next` and `graph` identical to `incidents/1.json`.
- Contract C `next.reachable[].zone` must be one of the contract zones: reach uses the network.yaml zone
  through `path.node_for` (server, dmz, mgmt, ...), all valid.

## Files not committed

`data/` (run outputs, scratch scripts `data/tmp/p8_*.py`), `docs/tasks/p7-p8-plan.md`, `docs/tasks/plan.md`,
`docs/tasks/p4b-review.*`, `docs/tasks/p6-review.*`, `docs/tasks/p7-review.*`.

## Commit

Commit `5627bc04ea04a5480b28028b1ffc41ecd9f90c5d` ("Add the access graph and reach next"), parent
ae53594. `git fetch` brought in the teammate's threat-intel commit ae53594 (enrich step, /ti API, Threat
Intel page; it overlaps this commit only in `README.md`, different rows). `git rebase origin/main` applied
cleanly; `python -m pytest -q` after the rebase: **293 passed** (213 ours + the teammate's new tests);
`data\tmp\p8_api_check.py` and `p7_api_check.py` still pass on the rebased code. Pushed
`ae53594..5627bc0 main -> main`; `git rev-list --left-right --count main...origin/main` = `0 0`.
The commit also carries the P7 hash line in `docs/tasks/p7-verify.md`, which was a working-copy edit.
(This hash line was added after the commit, so it is a working-copy edit to this file.)
