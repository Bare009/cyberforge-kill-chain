# P6 verification (correlation)

Run from the repo root (`killchain/`), PowerShell, miniconda `python`. Run folder `data\runs\firex-10G`.

## Commands and results

### 1. `python -m killchain detect --run data\runs\firex-10G`

Exit 0. `57 alerts, 44,623 evidence lines from 35 rules in 6.9 s (peak 978 MB)`;
`rule layer 32 alerts, anomaly layer 25 alerts from 11 detectors`.
R02 now has severity 4 (plan item 11), so the lone port scan (truth #2) passes the promotion bar.
Alert ids are unchanged (severity is not part of the id).

### 2. `python -m killchain correlate --run data\runs\firex-10G`

Exit 0, no contract errors.
`25 incidents (0 anomaly-only) from 57 alerts; unexplained 1, below bar 0, largest incident 8 alerts; 0.12 s`.
`hubs: 10.10.20.20, 10.10.99.1, 203.0.113.5, admin, portal.corp.local` (the fixed list; no dynamic hub
fires, because 32.127.48.11 and 10.10.10.118 are each in > 10 % of alerts but with 0 other sources).

`correlate/_stats.json`: 57 alerts (32 rule, 25 anomaly), 35 links, 25 rule components, 0 below bar,
25 incidents, 24 anomaly alerts joined as extra steps, 1 unexplained, largest incident 8 alerts.

Targets:

| Target | Result |
|---|---|
| Chain A (truth #28, 32.127.48.11) one incident with all firewall steps | our #1: A09 > R02 > A10 > R16 > R20 > A11 > R12 (R12 starts 7 h after R20 ends; joined via the 72 h widened gap) |
| Chain B (truth #29, 10.10.10.118 -> 7.154.5.35) one incident | our #2: R24 > R11 > A10 > R12 > A04 > A08 > A04 > A08 (R12 starts 4.9 h after R11 ends) |
| #15 R15 + R05 (svc_backup30, 203.228.177.117) together | our #3 |
| #13 R13 + second R09 (10.10.10.44) together | our #8 |
| The 23 single-type incidents stay separate | yes, one incident each (#4-#7, #9-#25) |
| Total incidents 25-35 | 25 |
| No giant component (largest <= 15 alerts) | largest 8 (chain B) |
| Wall time < 10 s | 0.12 s |

### 3. `python -m killchain eval score --run data\runs\firex-10G --parsed data\parsed\firex-10G`

Exit 0. The scorer now reads `incidents.parquet` + `incident_alerts.parquet` (no `incidents/` folder yet).

| Metric | Value |
|---|---|
| detection_recall | 100.0 % (32,200 / 32,200 truth lines; 25/25 incidents found) |
| label_accuracy | 100.0 % (exact 99.3 %, parent 99.3 %, any accepted 100.0 %) |
| attack_path_rebuilt | 100.0 % (25/25) |
| false_alarm_share | 0.0 % (0 of 25 incidents without truth) |
| our incidents | 25 |
| multi-step rebuilt | 4/4 (#7, #9, #28, #29) |
| incidents_spanning_truth | [] (no wrong merges) |
| rule layer alone | recall 100.0 %, labels 100.0 % |
| anomaly layer | 25 alerts, 0 background |

### 4. `python -m pytest -q`

Exit 0. `153 passed`. New: 22 tests in `tests/test_correlate.py` (classify_ip, entity rows, fixed hubs,
dynamic hub needs both conditions, union-find, time rule incl. widened gap and stage order, chain A shape,
long gap to a lower stage splits, fixed hub does not link, internal target alone does not link but
user + target (1.3) does, internal source of both links, promotion bar (each reason, and confidence 0.69
fails), anomaly cannot promote a weak rule component, anomaly joins only the stronger component and never
bridges two, anomaly-only two detectors -> incident, single / same detector / > 1 h -> unexplained,
stable id under shuffle, contract fields, CLI writes outputs, CLI missing inputs, real-run chains), and
3 in `tests/test_eval.py` (parquet-only incidents score, dominant-alert step order, incident spanning
two truth incidents). `tests/test_db.py::test_cli_lists_stages` now expects `correlate  ready` and checks
`chain` as the planned stage.

## Incident list

`docs/tasks/p6-incidents.txt` has one line per incident (id, rules in chain order, entities, IST span,
truth match) and the unexplained alerts.

## Merges and splits seen

- No wrong merges: every incident maps to exactly one truth incident (`incidents_spanning_truth` empty).
- One split: anomaly alert `fa51332436bc5a41` (A01 rare event, `parul.sinha` from 8.42.69.77, 10-24 19:59 IST)
  is left unexplained. It belongs with our #6 (R07, 8.42.69.154 -> 10.10.99.1 as `admin`, truth #7), but the
  two share only the hub 10.10.99.1: different IPs in the same /24 and different users. Truth #7 is still
  rebuilt because R07 covers both of its steps. Joining it would need a /24 subnet entity, which the plan
  does not include; left as is.
- Chain B's step order puts the hourly A04/A08 outlier alerts after R12 because they start a few minutes
  after it; the path check uses each truth step's dominant alert, so the order check still passes.

## Contract

`incidents.parquet` uses contract C names and types for the fields P6 owns (`incident_number`,
`incident_id`, `title`, `severity`, `ts_start`, `ts_end`, `merged {alerts, events}`,
`entities {ips, hosts, users, domains}`, `tactics`, `techniques`, `layers`). `engine.contract_errors`
checks them (and that every chain alert is a known alert) on every run; the CLI exits 1 on an error.
The remaining contract C fields (risk, chain steps, graph, next, report) arrive in P7-P11, so the full
`validate_incident` / `validate_bundle` runs in the bundle step.
