# Requirements

Source: *PRD: Kill Chain and Attack Path Analysis* (30 October 2026), the only
problem statement we have. Each requirement names the module that owns it and
how we check it. Design details are in `docs/architecture.md`.

## Functional requirements (must have)

| ID | Requirement | Owner | Done when |
|---|---|---|---|
| FR-1 | Read the full data set without loading it into memory | `killchain/parser` | Full tier parses with peak RSS under 16 GB (target 8 GB). **Built.** |
| FR-2 | Detect suspicious events (e.g. 50 failed logins on one account, then a success) | `killchain/detect`, `rules/` | Rules cover the 25 firewall incidents in `docs/build-plan.md` section 2.3 (and the Windows types if a Windows log arrives), and every alert carries all the raw events behind it |
| FR-3 | Map each detection to an ATT&CK technique and a kill chain stage | `killchain/detect`, `killchain/attack`, `rules/` | Every alert and evidence line has a technique valid in the bundled catalogue, a tactic and a stage number |
| FR-4 | Link related events into one incident by host, user, IP and time | `killchain/correlate` | Failed logins + new admin account + upload to an outside IP end up in one incident; chains crossing both logs end up in one incident |
| FR-5 | Show the attack path as a timeline and as a graph of hosts and users | `killchain/graph`, `killchain/api`, `web/` | Each incident has ordered steps and host/user nodes with directed edges |
| FR-6 | Show what the attacker could reach next | `killchain/graph` | Each incident lists reachable hosts and accounts, with the evidence for each edge |
| FR-7 | Simple API or page, with a short README | `killchain/api`, `web/`, `README.md` | `GET /incidents/12/path` works with numeric IDs; the README gets a judge from clone to results |

## Bonus

| ID | Requirement | Owner | Done when |
|---|---|---|---|
| B-1 | Risk score per incident, worst on top | `killchain/score` | Incidents numbered and listed by score, with the score's parts shown |
| B-2 | Auto-written incident report in plain English | `killchain/agents`, `killchain/report` | Every incident has a report; a template report is produced when no LLM is reachable |
| B-3 | Number of raw alerts merged into each incident | `killchain/correlate` | Incidents show merged alert and raw event counts |
| B-4 | New detection rule by editing a config file (e.g. Sigma), not code | `rules/`, `killchain/detect` | Rules are Sigma-style YAML; adding a file adds a rule |
| B-5 | Live mode: new log lines update the attack path within seconds | `killchain/live` | Appending lines to a tailed log changes the affected incident within seconds |

## Additions beyond the PRD

The PRD does not score these. They are built after the required items and must
never lower a score.

| Item | Tier | Owner | Constraint |
|---|---|---|---|
| Anomaly layer (generic detectors for attacks no rule covers) | T1 | `killchain/anomaly`, `rules/anomaly` | Lower confidence; alone it becomes an incident only when two detectors agree, otherwise "unexplained activity" |
| Local context (zone, role, host importance, first seen, rarity) | T1 | `killchain/enrich` | No network needed |
| Threat intel: OTX, AbuseIPDB, Shodan InternetDB (GreyNoise, VirusTotal T2) | T1 | `killchain/enrich` | Per incident entity only, cached, skipped without keys, small weight in the risk score |
| Q&A agent on one incident | T2 | `killchain/agents`, `killchain/api` | Answers only from the incident's data, citing checked line numbers |
| Rule writer agent | T2 | `killchain/agents`, `killchain/api` | Drafts are validated and test-run before saving |

Priority tiers (T0 must ship, T1 should ship, T2 stretch) and the cut order are
in `docs/build-plan.md` section 1.

## Targets (measured against the planted attacks)

| Metric | Good | Great | Measured by |
|---|---|---|---|
| Detection: share of planted steps found | > 70% | > 90% | `killchain/eval`, on the silver truth (25 incidents found in the data), or on an organisers' manifest when one matches the file |
| Correct labels: share of found steps with the right technique | > 60% | > 85% | `killchain/eval` |
| Attack path: planted attacks rebuilt in the right order | half | all | `killchain/eval` |
| False alarms: share of incidents that are not real attacks | < 30% | < 10% | `killchain/eval`, counted per incident |
| Processing time, full tier | < 3 h | < 1 h | `_stats.json` of each stage |
| Peak memory | < 16 GB | < 8 GB | `_stats.json` of each stage |
| Time to open one incident's path | < 2 s | < 500 ms | `killchain/eval` against the API |

Tier: Core 15 GB (1.0x), Advanced 30 GB (1.3x), Extreme 50 GB (1.6x). A bigger
tier only pays if accuracy stays above the bar, and every tier holds the same
planted attacks. We aim for Advanced (30 GB), since the only manifest we have is
for that tier, and get accuracy right before scaling.

## What the targets imply for the design

- **Complete evidence.** Recall is counted on planted steps, which the manifest
  lists event by event, so an alert must carry every raw event behind it.
- **Few, well-formed incidents.** False alarms are counted per incident and
  background noise is heavy, so only alert groups that pass a promotion bar
  become incidents. Other alerts stay visible as alerts.
- **Thresholds measured, not guessed.** The harness reports how often each rule
  fires on normal traffic.
- **No tuning to one file's quirks.** The real scoring tier may arrive later; the
  pipeline must take any file plus its manifest.

## Non-requirements

Polished UI, login, user management, cloud deployment, blocking or stopping the
attack.

## Constraints we set ourselves

- Runs from the README with `pip install -r requirements.txt` on a normal
  laptop. No database server or message queue. LLM and threat-intel keys are
  optional; without them the run still finishes, using cached or template
  output. Docker Compose is added at the end as a convenience.
- LLMs run on hosted APIs (Groq first, NeevCloud as fallback); no local GPU is
  assumed.
- Rules run as DuckDB SQL over the parser's Parquet files; no database server.
- Rules use event time from the logs, never processing time. Rows the parser
  flags with a bad `ts_quality` stay out of time-window rules.
- Detection, ATT&CK labels and incident membership are deterministic. LLMs and
  threat intel only add context and explanation.
- Every alert keeps the `source`, `line` and `byte_offset` of the raw lines
  behind it.

## Open questions for the organisers

1. A manifest that matches `firex-10G.log` (the one we have describes the 30 GB tier).
2. The Windows log for our tier: it holds 4 of the 29 attack types, 12 of the
   20 chain stages, host names (FR-5) and admin rights (FR-6).
3. Whether a "step" for detection is one event or one stage.
4. Whether either of two listed techniques (e.g. `T1110.001, T1078`) counts as a
   correct label.
5. Whether the stuck-clock region and the random-byte tail are intended, and
   whether planted events can fall inside them.
