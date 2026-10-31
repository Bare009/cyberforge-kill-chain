# P7 verification (numbered chain and path graph, plus the two P6-review fixes)

Run from the repo root (`killchain/`), PowerShell, miniconda `python`. Run folder
`c:\Users\hegde\Nishant\Projects\CyberForge_Hackathon\killchain\data\runs\firex-10G` (below: `data\runs\firex-10G`).

## What changed

- `killchain/graph/chain.py`: step ordering, `ongoing`, `gaps`, `chain_text`, contract-C step dicts.
- `killchain/graph/path.py`: path graph nodes and edges (NetworkX `MultiDiGraph`, exported as `{nodes, edges}`).
- `killchain/graph/incident_files.py`: provisional `incidents/<n>.json`, `index.json`, `alerts.json`;
  `validate_bundle` on every incident before anything is written; files written as `*.tmp` then renamed,
  the `incidents/` folder swapped as a whole.
- `killchain/graph/cli.py` + `killchain/__main__.py`: new stage `python -m killchain chain --run <run> [N]`.
- P6 fix 1, `killchain/correlate/cli.py`: the contract check now runs before `write_outputs`; on an error it
  prints the errors and returns 1 without writing anything.
- P6 fix 2: the ordering rule below, implemented in `chain.order_steps` and unit-tested.

## Ordering rule (P6 fix 2)

Sort key `(ts_start, stage_no, rule_id, alert_id)`, numbered 1..N:

1. Steps are sorted by when they start.
2. Steps that start at the same instant put the lower kill chain stage first, then the rule id
   (`alert_id` only makes the order total).
3. A long step (beaconing, exfiltration) gets one number at its start, keeps its own `ts_end`, and is
   `ongoing: true` when a later step starts strictly after it starts and before it ends. Equal-start ties
   do not count.
4. Tactics between the lowest and highest observed stage with no step go in `gaps`
   (`"No Credential Access evidence in the logs"`), never numbered; `resource-development` is never a gap.

Why overlaps are not reordered by stage: build-plan P7 says "ties and overlaps put the lower stage_no first",
but contract C (`validate_incident`) rejects any chain whose `ts_start` decreases. Moving a later-starting,
lower-stage step ahead of an earlier one would break the contract, so only exact start ties are reordered
by stage; an overlap is shown with `ongoing: true` on the long step. Contract wins.

How chain B reads under this rule: R24 malware (26 Oct 08:22 IST) → R11 beaconing (26 Oct 09:15 →
27 Oct ~18:30) → A10 and R12 exfiltration (27 Oct 23:24:40 → 28 Oct 01:37:40, both `ongoing`). The hourly
outliers A04/A08 start at 23:30 and 00:30, inside the exfiltration window and about five hours after
beaconing ended, so they overlap only the exfiltration and are numbered after its start. An outlier that
started during beaconing would be numbered before the exfiltration (unit test
`test_chain_b_outlier_during_beaconing_comes_before_exfil`).

## Commands and results

### 1. `python -m killchain detect --run c:\...\data\runs\firex-10G`

Exit 0. `57 alerts, 44,623 evidence lines from 35 rules in 13.5 s (peak 1005 MB)`;
`rule layer 32 alerts, anomaly layer 25 alerts from 11 detectors`. Same counts as P6.

### 2. `python -m killchain correlate --run c:\...\data\runs\firex-10G`

Exit 0. `25 incidents (0 anomaly-only) from 57 alerts; unexplained 1, below bar 0, largest incident 8 alerts; 0.23 s`.
`hubs: 10.10.20.20, 10.10.99.1, 203.0.113.5, admin, portal.corp.local`. Unchanged from P6.

### 3. `python -m killchain chain --run c:\...\data\runs\firex-10G`

Exit 0. `25 incidents, 56 steps (14 ongoing), 19 gaps, 44,622 evidence lines, 0 contract errors; 0.28 s`.
56 steps = 57 alerts minus the 1 unexplained alert; 44,622 = 44,623 evidence lines minus that alert's line.
`chain/_stats.json`: `{"stage": "chain", "wall_secs": 0.28, "peak_rss_mb": 92, "incidents": 25, "steps": 56,
"ongoing_steps": 14, "gaps": 19, "incident_lines": 44622, "graph_nodes": 65, "graph_edges": 72, "contract_errors": 0}`.
Written: `incidents/1.json` … `incidents/25.json`, `index.json`, `alerts.json` (56 of 57 alerts now carry an
`incident_number`; the unexplained one stays null), `chains.json`, `incident_lines.parquet`, `chain/_stats.json`.
One line per incident and the text form of incidents 1-5 (with their graphs) are in `docs/tasks/p7-chains.txt`.

### 4. `python -m killchain eval score --run c:\...\data\runs\firex-10G --parsed c:\...\data\parsed\firex-10G`

Exit 0. The scorer now reads `incidents/*.json` (it prefers them over the parquet files).

| Metric | P6 | P7 |
|---|---|---|
| detection_recall | 100.0 % | 100.0 % (32,200 / 32,200 lines; 25/25 incidents found) |
| label_accuracy | 100.0 % | 100.0 % (exact 99.3 %, parent 99.3 %, any accepted 100.0 %) |
| attack_path_rebuilt | 100.0 % (25/25) | 100.0 % (25/25) |
| multi-step rebuilt | 4/4 | 4/4 |
| false_alarm_share | 0.0 % | 0.0 % (25 incidents, 0 without truth) |
| incidents_spanning_truth | [] | [] |
| processing_secs | | 69 s (sum of every `_stats.json` `wall_secs`; chain adds 0.28 s) |
| peak_rss_mb | | 4,477 MB (max over stages; chain 92 MB) |

Timing stays in seconds: `chain/_stats.json` `wall_secs` is seconds (0.28), like the other stages, and the
scorer sums it as seconds.

### 5. Bundle and API check: `python data\tmp\p7_api_check.py` (scratch, not committed)

Reads every `incidents/<n>.json` from disk and runs `contracts.validate_bundle(incident, index, alerts)`:
`bundles 25 validate_bundle errors 0 steps 56 alerts with incident_number 56 of 57`.
Then `killchain.api.create_app(data/runs/firex-10G)` with `TestClient`: `/health` `status ok`,
`contract_errors 0`, counts `{incidents 25, alerts 57, events 44623}`; `/incidents?limit=500` total 25;
`/incidents/{n}/path` 200 for all 25 with `chain[].n == 1..N`; `/incidents/1/events?step=1` total 241;
`/entities/32.127.48.11` 200; `/mitre/matrix` 200. All assertions passed.

### 6. `python -m pytest -q`

Exit 0. `194 passed in 33.76s` (173 before + 21 new).
New in `tests/test_chain.py` (20): sort by start; exact tie → stage → rule → alert, same under shuffle; overlap
keeps start order with the long step ongoing; numbering 1..N with non-decreasing `ts_start`; ongoing true for a
long step passed by a later start, false for an equal-start tie, a start exactly at the end and the last step;
long step keeps one number and its own `ts_end`; chain B shape (R24, R11, A10, R12, A04, A08 with A10/R12
ongoing) and its variant (outlier during beaconing numbered before exfiltration); gaps interior only, unique,
no Resource Development, none for one stage; gaps never become steps; chain_text ranges (`1-4. Initial Access`,
`3-4. Exfiltration`); step fields = `contracts.STEP`, ≤ 20 sample lines, `line_total`, trigger rows first, UTC
and IST formats; node classification (external, portal, firewall mgmt/public, CIDR, 198.51.100.x, desktop,
account, domain); graph edges (main label `2. web sql injection x60`, login src → user → dst, hub domain gets no
node, other domain does, flood step gets `sources of step 5` / `6,005 sources`, every endpoint a node, contract
enums); assembled incident passes `validate_bundle` and risk_score = sum of points; write swaps out an old
`incidents/9.json` and leaves no `.tmp`; CLI builds, prints `N`, missing N → 1; missing inputs → 1; a failing
check writes nothing; real run (chain A rule order R02 < R16 < R20 < R12, chain B R24 < R11 < R12 with R12
ongoing and A04/A08 after it, all 25 bundles valid, every step has evidence and an edge, 56 steps).
New in `tests/test_correlate.py` (1): `test_cli_contract_error_writes_nothing` (P6 fix 1: exit 1, `boom` on
stderr, existing `incidents.parquet` byte-identical, a fresh folder gets no outputs).
`tests/test_db.py::test_cli_lists_stages` now expects `chain      ready` and uses `reach` (P8) as the planned stage.

## Chain A and chain B

Chain A, our #1 (truth #28, 32.127.48.11 → portal 10.10.20.20):

```
1. Initial Access → 2. Discovery → 3. Exfiltration → 4. Initial Access → 5. Persistence → 6. Command and Control → 7. Exfiltration
 1. 01:51:23 IST (ongoing until 10:09:09) A09 denied then allowed x241
 2. 01:51:23 IST R02 port scan x240
 3. 01:51:23 IST (ongoing until 12:38:54) A10 lopsided pair x840
 4. 02:07:10 IST R16 web SQL injection x60
 5. 02:41:36 IST R20 web shell x40
 6. 10:09:09 IST A11 too regular x600
 7. 10:09:09 IST R12 large lopsided transfer x600
```

It makes sense: the rule steps read scan (2) → SQL injection (4) → web shell (5) → data out (7), the order of
the attack. A09, R02 and A10 all start on the same first packet; the tie is broken by stage (3 < 9 < 13). A09
and A10 are anomaly summaries that span most of the incident, so they keep their start number and are marked
ongoing instead of being moved. Gaps: Execution, Privilege Escalation, Defense Evasion, Credential Access,
Lateral Movement, Collection.

Chain B, our #2 (truth #29, internal 10.10.10.118 → 7.154.5.35):

```
1. Execution → 2. Command and Control → 3-4. Exfiltration → 5. Discovery → 6. Exfiltration → 7. Discovery → 8. Exfiltration
 1. 10-26 08:22:00 IST R24 malware detected, not blocked x3
 2. 10-26 09:15:00 IST R11 beaconing x400
 3. 10-27 23:24:40 IST (ongoing until 10-28 01:37:40) A10 lopsided pair x400
 4. 10-27 23:24:40 IST (ongoing until 10-28 01:37:40) R12 large lopsided transfer x400
 5. 10-27 23:30:00 IST A04 outlier sessions x185
 6. 10-27 23:30:00 IST A08 outlier bytes out x180
 7. 10-28 00:30:00 IST A04 outlier sessions x182
 8. 10-28 00:30:00 IST A08 outlier bytes out x180
```

It makes sense: malware → beaconing → exfiltration in attack order. The hourly outliers are the per-hour view
of the exfiltration itself; they start inside the exfiltration window (beaconing had ended five hours
earlier), so they follow it and the exfiltration steps are marked ongoing. Gaps: Persistence, Privilege
Escalation, Defense Evasion, Credential Access, Lateral Movement, Collection.
Graph: 10.10.10.118 (internal_host, desktop) → 7.154.5.35 (external_ip) for every step, plus
10.10.10.118 → kjhsdf.duckdns.org (domain) for step 1.

## Contract / spec / API mismatches (contract wins)

1. Build-plan P7 "ties and overlaps put the lower stage_no first" vs contract C "`ts_start` must not
   decrease": only exact ties are reordered by stage; overlaps are shown with `ongoing` (see above).
2. Build-plan P11 says the track-B `bundle` step writes `incidents/<n>.json`, `index.json`, `alerts.json`.
   It does not exist yet, so `chain` writes provisional, contract-valid files (risk parts 0 points with the
   P10 weights, `risk_band low`, `enrichment {}`, a template report marked provisional, `next` placeholder).
   The teammate's `bundle` step can read `chains.json` or call `killchain.graph` and will overwrite them.
3. `alerts.json` `incident_number`: contract B says "incident it belongs to", detect writes null and the
   MITRE page relies on it; `chain` fills it (56 of 57).
4. Constraints the contract leaves open and the UI pins down, all followed: graph node ids are raw values
   (`10.10.20.20`, `Deepika.Khan`), gap strings are unique, every step has a `step` edge.
No mismatch was found between the contract and what `killchain/api/` or `web/` read.

## Observations (not changed in P7)

- R24's `action_text` contains an unfilled `{virus}` placeholder ("antivirus detected {virus} on
  10.10.10.118 ..."). It comes from the detect rule template, not from P7; worth fixing in the rule.
- `eval score` prefers `incidents/*.json`. Re-running `correlate` without re-running `chain` leaves the
  previous chain's files in place, so run `chain` after `correlate`.

## Commit

Commit `046d61f5f65111fcbc14fd94663109e40a2aed4e` ("Add numbered attack chains and path graphs; check
contracts before correlate writes"), parent 2d164e6. `git fetch` found nothing new on origin/main, so
`git rebase origin/main` was a no-op; `python -m pytest -q` after the rebase: 194 passed. Pushed
`2d164e6..046d61f main -> main`; `git rev-list --left-right --count main...origin/main` = `0 0`.
(This hash line was added after the commit, so it is a working-copy edit to this file.)
