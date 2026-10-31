# P10 verification: risk score and template report

Run `data\runs\firex-10G`, parsed `data\parsed\firex-10G`, branch `main`, PowerShell, miniconda `python`,
cwd = repo root. First iteration (no `p10-review.json`).

## What was built

- `killchain/score/risk.py`: the seven parts, `band`, `load_enrichment`, `incident_values`, `ti_matches`,
  `risk_parts`, `apply_risk`, `rank`. Weights from `incident_files.RISK_WEIGHTS` (0.25 / 0.20 / 0.10 / 0.15 /
  0.15 / 0.10 / 0.05), unchanged.
- `killchain/score/cli.py`: `python -m killchain score --run <run> [N]`. Scores, renumbers the bundle
  1..N by `(-risk_score, ts_start, incident_id)`, rewrites `incidents/<n>.json`, `index.json`,
  `alerts.json`, writes `score.json` and `score/_stats.json`. Refuses (exit 1, nothing written) when reach
  has not run or inputs are missing. With N: prints the parts table.
- `killchain/report/template.py` and `killchain/report/cli.py`: `python -m killchain report --run <run> [N]`.
  Writes `report = {source: template, markdown, triage: null}`, `report_source: template`, and
  `report/_stats.json`. Needs `score.json`. With N: prints the markdown.
- Contract: optional `detail` (string) on each risk part, checked in `validate_incident`; documented in
  `docs/contracts.md` (new "Risk score" subsection, report section order, run layout, stage order and
  renumbering note). `examples/sample-run/` untouched and still valid (no `detail` key there).
- `score` and `report` registered in `killchain/__main__.py`; `tests/test_db.py` now expects them `ready`.

Threat-intel source: the teammate's `enrichment.json` (commit ae53594), read only, matched by entity value.
Entities whose verdict is `unknown` (no outside provider answered) count as "no reputation score".
Without `enrichment.json` the part is 0 with the detail
`no threat-intel data for this run (enrichment.json not found)`.

## Commands and results

| Command | Exit | Result |
|---|---|---|
| `python -m killchain detect --run data\runs\firex-10G` | 0 | 57 alerts (32 rule, 25 anomaly), 44,623 evidence lines, 14.3 s |
| `python -m killchain correlate --run data\runs\firex-10G` | 0 | 25 incidents (0 anomaly-only), 1 unexplained, 0.18 s |
| `python -m killchain chain --run data\runs\firex-10G` | 0 | 32 numbered steps (2 ongoing), 24 supporting, 19 gaps, 44,622 lines, 0 contract errors |
| `python -m killchain reach --run data\runs\firex-10G` | 0 | 11 incidents with reach, 14 with a reason, 0 contract errors, 0.79 s |
| `python -m killchain score --run data\runs\firex-10G` (no `enrichment.json`) | 0 | 25 scored, critical 2 / high 17 / medium 6 / low 0, 24 renumbered; every TI part 0, detail "no threat-intel data for this run (enrichment.json not found)" |
| `python -m killchain.enrich --run data\runs\firex-10G --offline` | 0 | 58 indicators, 0 lookups, verdicts `unknown 58` (no OTX key, cache empty for these) |
| `python -m killchain score --run data\runs\firex-10G` (with `enrichment.json`) | 0 | same scores, 0 renumbered; TI 0 for all 25, detail "no entity of this incident has a reputation score (offline: cache and local context only)" |
| `python -m killchain report --run data\runs\firex-10G` | 0 | 25 template reports, 73,066 characters, 0 contract errors, 0.04 s |
| `python -m killchain.enrich --run data\runs\firex-10G --offline` | 0 | refreshed after score so its incident lists use the final numbers |
| `python -m killchain score --run data\runs\firex-10G 1` / `9` | 0 | parts tables below |
| `python -m killchain report --run data\runs\firex-10G 1` | 0 | report below |
| `python -m killchain eval score --run data\runs\firex-10G --parsed data\parsed\firex-10G` | 0 | metrics below |
| `python data\tmp\p10_report_dump.py ...` (scratch) | 0 | 25 incidents, `validate_bundle` errors 0, every `report_source == template`, markdown starts `## Summary` |
| `python data\tmp\p10_api_check.py` (scratch, teammate's API read-only) | 0 | `/health` contract_errors 0; `/incidents` 25 rows, numbers 1..25, scores non-increasing (86.5 .. 37.2); `/incidents/1` 7 parts with `detail`, template report; `/incidents/1/path` 200 |
| `python -m killchain.bundle --run data\runs\firex-10G --check` | 0 | 25 incidents, 0 warnings (no "not in risk order"), 0 contract errors; nothing written |
| `python -m pytest -q` | 0 | **350 passed** in 57 s (293 before Task 1; Task 1 and this task added tests) |

`score/_stats.json`: `{"stage": "score", "wall_secs": 0.05, "peak_rss_mb": 57, "incidents": 25,
"bands": {"critical": 2, "high": 17, "medium": 6, "low": 0}, "threat_intel_source": "enrichment.json",
"contract_errors": 0}`.
`report/_stats.json`: `{"stage": "report", "wall_secs": 0.04, "peak_rss_mb": 57, "incidents": 25,
"markdown_chars": 73066, "threat_intel_source": "enrichment.json", "contract_errors": 0}`.

## Eval metrics (unchanged)

| Metric | Before (P9 fix) | After P10 |
|---|---|---|
| detection_recall | 100.0 % | 100.0 % |
| label_accuracy | 100.0 % | 100.0 % (exact 99.3 %, any accepted 100 %) |
| attack_path_rebuilt | 25/25 | 25/25 (100 %) |
| multi-step rebuilt | 4/4 | 4/4 |
| false_alarm_share | 0.0 % | 0.0 % (25 incidents, 0 without truth) |
| processing_secs | ~70 s | 71 s (score and report add 0.09 s) |
| peak_rss_mb | 4,477 MB | 4,477 MB |

## Ranked incidents with their parts (points)

TI is 0 for every incident (offline enrich, all 58 indicators `unknown`).

| # | score | band | title | sev | stage | breadth | success | asset | reach | TI |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 86.5 | critical | Discovery to Exfiltration by 32.127.48.11 (**chain A**) | 25.00 | 18.57 | 6.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 2 | 81.5 | critical | Large one-way transfer between an internal and an outside host to 7.93.184.183 | 25.00 | 18.57 | 1.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 3 | 73.9 | high | Initial Access to Lateral Movement by 10.10.10.44 | 20.00 | 14.29 | 3.33 | 15.00 | 11.25 | 10.00 | 0.00 |
| 4 | 72.2 | high | One internal host opening admin services on many internal hosts from 10.10.10.63 | 20.00 | 14.29 | 1.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 5 | 71.4 | high | Successful admin login right after many failures from the same /24 from 8.42.69.134 (admin takeover) | 25.00 | 11.43 | 1.67 | 15.00 | 15.00 | 3.33 | 0.00 |
| 6 | 70.1 | high | Requests to server paths that no other source uses (web shell) from 202.36.226.247 | 25.00 | 7.14 | 1.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 7 | 68.8 | high | Persistence to Initial Access by 203.228.177.117 (rogue admin, admin takeover) | 25.00 | 7.14 | 3.33 | 15.00 | 15.00 | 3.33 | 0.00 |
| 8 | 67.9 | high | Connection flood of complete sessions to one server to 10.10.20.20 | 20.00 | 20.00 | 1.67 | 15.00 | 11.25 | 0.00 | 0.00 |
| 9 | 67.3 | high | Execution to Exfiltration by 7.154.5.35 (**chain B**, 10.10.10.118) | 25.00 | 18.57 | 5.00 | 15.00 | 3.75 | 0.00 | 0.00 |
| 10 | 66.7 | high | Logging switched off around a configuration change from 78.120.139.0 | 25.00 | 10.00 | 1.67 | 15.00 | 15.00 | 0.00 | 0.00 |
| 11 | 62.2 | high | SQL injection against a web server from 131.228.119.59 | 20.00 | 4.29 | 1.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 12 | 62.2 | high | Command injection against a web server from 72.7.116.239 | 20.00 | 4.29 | 1.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 13 | 62.2 | high | Path traversal against a web server from 72.90.113.105 | 20.00 | 4.29 | 1.67 | 15.00 | 11.25 | 10.00 | 0.00 |
| 14 | 59.3 | high | Successful admin login at night from abroad from 171.104.84.193 (admin takeover) | 20.00 | 4.29 | 1.67 | 15.00 | 15.00 | 3.33 | 0.00 |
| 15 | 57.6 | high | Regular small connections to one outside host (beaconing) to 198.79.124.52 | 20.00 | 17.14 | 1.67 | 15.00 | 3.75 | 0.00 | 0.00 |
| 16 | 57.6 | high | DNS tunnelling through long subdomain labels from 10.10.10.88 | 20.00 | 17.14 | 1.67 | 15.00 | 3.75 | 0.00 | 0.00 |
| 17 | 56.7 | high | Unsolicited DNS answers from many resolvers (amplification) to 203.0.113.5 | 20.00 | 20.00 | 1.67 | 0.00 | 15.00 | 0.00 | 0.00 |
| 18 | 56.0 | high | One VPN user connecting from two countries within 30 minutes from 102.8.77.227 | 20.00 | 4.29 | 1.67 | 15.00 | 15.00 | 0.00 | 0.00 |
| 19 | 52.9 | high | TCP flood from thousands of addresses to one host to 10.10.20.20 | 20.00 | 20.00 | 1.67 | 0.00 | 11.25 | 0.00 | 0.00 |
| 20 | 48.1 | medium | Slow credential stuffing spread across one /24 from 71.54.76.0/24 | 20.00 | 11.43 | 1.67 | 0.00 | 15.00 | 0.00 | 0.00 |
| 21 | 48.1 | medium | Brute force on the firewall admin login from 15.199.16.197 | 20.00 | 11.43 | 1.67 | 0.00 | 15.00 | 0.00 | 0.00 |
| 22 | 46.3 | medium | Many internal hosts reaching one outside address on telnet to 154.35.54.115 | 20.00 | 17.14 | 1.67 | 0.00 | 7.50 | 0.00 | 0.00 |
| 23 | 45.8 | medium | Port scan of one host from 194.102.163.167 (lone port scan) | 20.00 | 12.86 | 1.67 | 0.00 | 11.25 | 0.00 | 0.00 |
| 24 | 42.6 | medium | Executable disguised as a document to 111.253.167.34 | 20.00 | 17.14 | 1.67 | 0.00 | 3.75 | 0.00 | 0.00 |
| 25 | 37.2 | medium | Cross-site scripting against a web server from 178.50.251.250 | 20.00 | 4.29 | 1.67 | 0.00 | 11.25 | 0.00 | 0.00 |

Ties: #11-#13 (62.2) and #15-#16 (57.6), #20-#21 (48.1) are ordered by first time, then `incident_id`.

### Chain A (#1) parts

| Part | Value | Weight | Points | Detail |
|---|---|---|---|---|
| Severity | 1.0000 | 0.25 | 25.00 | highest alert severity 5 of 5 |
| Stage reached | 0.9286 | 0.20 | 18.57 | furthest stage Exfiltration (13 of 14) |
| Breadth | 0.6667 | 0.10 | 6.67 | 4 distinct tactics (full marks at 6) |
| Success | 1.0000 | 0.15 | 15.00 | step 2 got through |
| Asset importance | 0.7500 | 0.15 | 11.25 | portal (10.10.20.20) (dmz, importance 0.75) |
| Reach next | 1.0000 | 0.10 | 10.00 | 0 observed and 10 inferred important hosts reachable next (server, DMZ, management) |
| Threat intel | 0.0000 | 0.05 | 0.00 | no entity of this incident has a reputation score (offline: cache and local context only) |
| **Total** | | | **86.5** | critical (as predicted in the plan) |

### Chain B (#9) parts

| Part | Value | Weight | Points | Detail |
|---|---|---|---|---|
| Severity | 1.0000 | 0.25 | 25.00 | highest alert severity 5 of 5 |
| Stage reached | 0.9286 | 0.20 | 18.57 | furthest stage Exfiltration (13 of 14) |
| Breadth | 0.5000 | 0.10 | 5.00 | 3 distinct tactics (full marks at 6) |
| Success | 1.0000 | 0.15 | 15.00 | step 1 got through |
| Asset importance | 0.2500 | 0.15 | 3.75 | 10.10.10.118 (desktop, importance 0.25) |
| Reach next | 0.0000 | 0.10 | 0.00 | no important host reachable next |
| Threat intel | 0.0000 | 0.05 | 0.00 | no entity of this incident has a reputation score (offline: cache and local context only) |
| **Total** | | | **67.3** | high (as predicted in the plan) |

### Why the ranking looks like this

- **Chain A is #1** (86.5): the only incident with top marks on severity, a late stage (exfiltration), the
  widest chain (4 tactics), success, a DMZ asset and full reach (10 inferred servers next to the portal).
- **Admin takeovers rank high**: #5 (success after failures, 71.4), #7 (rogue admin, 68.8) and #14 (night
  login from abroad, 59.3) each touch the firewall management address 10.10.99.1 (asset 1.0 = 15 points),
  got through, and reach the firewall management interface (1 observed important host = 3.33). #3
  (Initial Access → Lateral Movement from 10.10.10.44, 73.9) is the other multi-step chain.
- **Lone port scan and floods are lower**: the port scan (#23, 45.8) was blocked (success 0) with no reach.
  The TCP flood (#19, 52.9) and DNS amplification (#17, 56.7) were blocked too; they keep 20 stage points
  because Impact is stage 14. Blocked brute force / credential stuffing (#20, #21) and XSS (#25) are the
  medium band.
- **Open item for the user (not changed; the weights and definitions are the agreed ones):** chain B ranks
  **#9**, below seven single-step incidents. Chain B's victim is a desktop (asset 0.25 = 3.75 points) and it
  has no reach (0 points), so it loses 7.5 asset points and 10 reach points against server-side incidents.
  What lifts the incidents above it:
  - #2 large transfer (81.5): a server source 10.10.20.31 (asset 11.25) and 10 inferred servers next (reach 10).
  - #3, #4 lateral movement (73.9, 72.2) and #6 web shell (70.1): server assets and full reach.
  - #5, #7 admin takeovers (71.4, 68.8): firewall asset 15 and reach 3.33.
  - #8 connection flood of complete sessions (67.9): Impact = stage 14 (20 points, more than chain B's
    18.57), success true (complete sessions got through), portal asset 11.25. It beats chain B by 0.6.
  The build plan hopes the two chains rank 1 and 2 "after tuning" (M10). Getting chain B to #2 needs a
  definition or weight change (for example rewarding breadth or multi-step chains more, or scoring Impact
  floods lower); that is the user's decision.

## Template report of incident #1 (full text)

````markdown
## Summary

32.127.48.11 went from Discovery to Exfiltration against portal (10.10.20.20) in 4 steps between 2026-10-29 01:51:23 and 2026-10-29 12:38:54 IST; risk 86.5 of 100 (critical).

## Risk

Risk score **86.5 / 100** (critical).

| Part | Value | Weight | Points | Why |
|---|---|---|---|---|
| Severity | 1.00 | 0.25 | 25.00 | highest alert severity 5 of 5 |
| Stage reached | 0.93 | 0.20 | 18.57 | furthest stage Exfiltration (13 of 14) |
| Breadth | 0.67 | 0.10 | 6.67 | 4 distinct tactics (full marks at 6) |
| Success | 1.00 | 0.15 | 15.00 | step 2 got through |
| Asset importance | 0.75 | 0.15 | 11.25 | portal (10.10.20.20) (dmz, importance 0.75) |
| Reach next | 1.00 | 0.10 | 10.00 | 0 observed and 10 inferred important hosts reachable next (server, DMZ, management) |
| Threat intel | 0.00 | 0.05 | 0.00 | no entity of this incident has a reputation score (offline: cache and local context only) |

## Attack chain

1. **2026-10-29 01:51:23 IST** to 2026-10-29 01:52:26 · Discovery · T1046 Network Service Discovery: 32.127.48.11 probed 240 ports on 10.10.20.20 in 1.1 minutes; 240 attempts were blocked (32.127.48.11 → 10.10.20.20, 240 events, blocked)
2. **2026-10-29 02:07:10 IST** to 2026-10-29 02:11:06 · Initial Access · T1190 Exploit Public-Facing Application: 32.127.48.11 sent 60 SQL injection attempts to 10.10.20.20 in 3.9 minutes; 6 were not blocked (32.127.48.11 → 10.10.20.20, 60 events, got through)
   - Supporting anomaly (during this step): 32.127.48.11 was denied 240 times by the firewall, then got through to 10.10.20.20 (A09-denied-then-allowed, T1190, 2026-10-29 01:51:23 to 2026-10-29 10:09:09 IST, 241 events)
3. **2026-10-29 02:41:36 IST** to 2026-10-29 03:01:06 · Persistence · T1505.003 Server Software Component: Web Shell: 32.127.48.11 made 40 requests to 10.10.20.20 for server paths that almost no other source requests (32.127.48.11 → 10.10.20.20, 40 events, got through)
4. **2026-10-29 10:09:09 IST** to 2026-10-29 12:38:54 · Exfiltration · T1048.002 Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol: 32.127.48.11 sent data to 10.10.20.20 in 600 sessions over 0.1 days, far more than it received (32.127.48.11 → 10.10.20.20, 600 events, got through)
   - Supporting anomaly (during this step): 32.127.48.11 sent at least 10 times more to 10.10.20.20 than it received, in 840 sessions over 0.4 days (A10-lopsided-pair, T1048, 2026-10-29 01:51:23 to 2026-10-29 12:38:54 IST, 840 events)
   - Supporting anomaly (during this step): 32.127.48.11 talked to 10.10.20.20 600 times at near-fixed intervals over 0.1 days (A11-too-regular, T1071, 2026-10-29 10:09:09 to 2026-10-29 12:38:54 IST, 600 events)

## Gaps

- No Execution evidence in the logs
- No Privilege Escalation evidence in the logs
- No Defense Evasion evidence in the logs
- No Credential Access evidence in the logs
- No Lateral Movement evidence in the logs
- No Collection evidence in the logs

## Reach next

No internal connections from portal (10.10.20.20) were observed; 230 hosts in the same server subnet (e.g. 10.10.20.31) are the likely next targets (inferred).

- 10.10.20.31 (server), hop 1, inferred, via 10.10.20.20 zone_neighbour
- 10.10.20.13 (server), hop 1, inferred, via 10.10.20.20 zone_neighbour
- 10.10.20.19 (server), hop 1, inferred, via 10.10.20.20 zone_neighbour
- 10.10.20.12 (server), hop 1, inferred, via 10.10.20.20 zone_neighbour
- 10.10.20.163 (server), hop 1, inferred, via 10.10.20.20 zone_neighbour

Likely next tactics (heuristic): Impact.

## Entities

- IPs: 32.127.48.11, 10.10.20.20
- Hosts: none
- Accounts: none
- Domains: portal.corp.local

## Threat intel

- 10.10.20.20: unknown, reputation 0.00
- 32.127.48.11: unknown, reputation 0.00
- portal.corp.local: unknown, reputation 0.00

Looked up offline: cached answers and local context only.

## Evidence

**Step 1** (240 lines):

- firex-10G.log line 3210437 (byte 1694226476), 2026-10-29 01:51:49 IST
- firex-10G.log line 3210439 (byte 1694227476), 2026-10-29 01:51:49 IST
- firex-10G.log line 3210440 (byte 1694227959), 2026-10-29 01:51:50 IST
- firex-10G.log line 3210442 (byte 1694229021), 2026-10-29 01:51:50 IST
- firex-10G.log line 3210443 (byte 1694229504), 2026-10-29 01:51:50 IST

**Step 2** (60 lines):

- firex-10G.log line 3212670 (byte 1695392653), 2026-10-29 02:07:10 IST
- firex-10G.log line 3212681 (byte 1695398474), 2026-10-29 02:07:14 IST
- firex-10G.log line 3212693 (byte 1695404854), 2026-10-29 02:07:18 IST
- firex-10G.log line 3212699 (byte 1695407957), 2026-10-29 02:07:22 IST
- firex-10G.log line 3212712 (byte 1695415187), 2026-10-29 02:07:26 IST

**Step 3** (40 lines):

- firex-10G.log line 3217029 (byte 1697701360), 2026-10-29 02:41:36 IST
- firex-10G.log line 3217086 (byte 1697731458), 2026-10-29 02:42:06 IST
- firex-10G.log line 3217149 (byte 1697763119), 2026-10-29 02:42:36 IST
- firex-10G.log line 3217213 (byte 1697797368), 2026-10-29 02:43:06 IST
- firex-10G.log line 3217276 (byte 1697830849), 2026-10-29 02:43:36 IST

**Step 4** (600 lines):

- firex-10G.log line 3344208 (byte 1764806229), 2026-10-29 10:09:09 IST
- firex-10G.log line 3344247 (byte 1764826995), 2026-10-29 10:09:24 IST
- firex-10G.log line 3344285 (byte 1764847275), 2026-10-29 10:09:39 IST
- firex-10G.log line 3344321 (byte 1764866717), 2026-10-29 10:09:54 IST
- firex-10G.log line 3344350 (byte 1764881789), 2026-10-29 10:10:09 IST

## Recommended actions

- **Discovery** (step 1): Block 32.127.48.11 and check whether any probed service on 10.10.20.20 answered.
- **Initial Access** (step 2): Patch or take offline the exposed service on 10.10.20.20, reset any account used from 32.127.48.11, and review 10.10.20.20's logs from this step on.
- **Persistence** (step 3): Remove the planted file or account on 10.10.20.20 and audit it for other changes since the first step.
- **Exfiltration** (step 4): Block traffic between 32.127.48.11 and 10.10.20.20, estimate how much data left from the evidence, and start the data-breach process.

_Template report: built only from this incident's facts, without AI._
````

Chain B's report (#9) has the same sections. Its summary reads: "10.10.10.118 went from Execution to
Exfiltration against 7.154.5.35 in 3 steps between 2026-10-26 08:22:00 and 2026-10-28 01:37:40 IST; risk
67.3 of 100 (high)." Its step 3 lists the 5 supporting anomalies (A10, A04, A08, A04, A08), and its threat
intel lists `kjhsdf.duckdns.org: unknown, reputation 0.00; dynamic-DNS domain` (a local-context flag).

## Unit tests added

- `tests/test_score.py` (21 tests, band cases parametrized): every part's value and detail on a hand-made chain-A incident (69.8,
  high); `points == round(value*weight*100, 2)`, score = rounded sum, `validate_incident` clean; bands at
  75.0 / 74.9 / 50.0 / 49.9 / 25.0 / 24.9 / 0; breadth capped with 8 tactics; reach (2 observed + 2
  inferred servers + 5 desktops → 1.0; one observed 10.10.99.1 → 0.3333; desktops only → 0); asset ignores
  reach nodes, external IPs, accounts and domains and is 1.0 for 10.10.99.1; no internal host → 0;
  supporting anomalies do not change stage, breadth or success; anomaly-only incident uses its numbered
  anomaly steps; TI (no file → 0 and "not found"; reputation 0.6 matched by value even with a stale
  incident number; unrelated entity ignored; `unknown` verdict ignored; offline note); `rank` order, ties,
  1..N, idempotent. CLI: renumbers (stronger incident 2 → 1, alerts follow, null stays null), `score.json`,
  `score/_stats.json`, `validate_bundle` clean, second run byte-identical, `score N` prints the table,
  reads `enrichment.json`, refuses a placeholder reach (nothing written), missing `index.json` → exit 1.
- `tests/test_report.py` (11 tests): `ACTIONS` covers all 14 tactics; headings once each in order; summary
  sentence (multi-tactic and single-tactic wording, actor, targets, steps, IST span, score, band); one line
  per step with its IST start and the ongoing clause only when ongoing; supporting bullets; gaps / `None:`
  line; reach sentence, at most 5 hosts, likely tactics; entity bullets; TI section without and with
  enrichment; ≤ 5 evidence rows per step with line and byte; one action per tactic in chain order with no
  unfilled `{}`; deterministic; every IPv4 in the markdown is an incident value, graph node or reach host.
  CLI: writes template reports, `validate_bundle` clean, `report/_stats.json`, second run byte-identical,
  `report N` prints markdown, refuses without `score.json` (nothing written).
- `tests/test_contracts.py`: risk part `detail: "x"` valid, `detail: 3` an error.

## Notes for the teammate (track B) and follow-ups

- The UI already shows `risk_parts` (`RiskBreakdown`; it ignores `detail`, which could become a tooltip)
  and `report.markdown` (`MarkdownReport`). No API or UI change was needed; `/health` reports 0 contract
  errors.
- The bundle step binds `enrichment.json` by value, so it is correct after `score` renumbers. A run served
  without the bundle step uses `apply_enrichment` (by incident number), so `enrich` must be re-run after
  `score` there; documented in `docs/contracts.md`.
- Outside this task: rule R24's `action_text` has an unfilled `{virus}` placeholder ("antivirus detected
  {virus} on 10.10.10.118 ..."); it comes from `alerts.json` and shows in the chain and the report. Worth a
  fix in the rule's action template.
- `docs/build-plan.md` says threat intel is "0 offline"; offline enrich still has cached answers, so the
  score uses them when present and says "offline" in the detail. On this run nothing was cached, so every
  TI part is 0 either way.
