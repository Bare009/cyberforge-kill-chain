# Requirements

Source: *PRD: Kill Chain and Attack Path Analysis* (30 October 2026). Each
requirement below names the module that owns it and how we check it.

## Functional requirements (must have)

| ID | Requirement | Owner | Done when |
|---|---|---|---|
| FR-1 | Read the full data set without loading it into memory | `killchain/parser` | Full tier parses with peak RSS under 16 GB (target 8 GB). **Built.** |
| FR-2 | Detect suspicious events (e.g. 50 failed logins on one account, then a success) | `killchain/detect`, `rules/` | Detections cover the 29 planted incident types listed in `docs/data-notes.md` |
| FR-3 | Map each detection to an ATT&CK technique and a kill chain stage | `killchain/attack`, `rules/` | Every detection carries a technique ID valid in the bundled catalogue, a tactic and a stage number |
| FR-4 | Link related events into one incident by host, user, IP and time | `killchain/correlate` | Failed logins + new admin + upload to an outside IP end up in one incident |
| FR-5 | Show the attack path as a timeline and as a graph of hosts and users | `killchain/graph`, `killchain/api`, `web/` | Each incident has ordered steps and host/user nodes with directed edges |
| FR-6 | Show what the attacker could reach next | `killchain/graph` | Each incident lists reachable hosts/accounts with the evidence for each edge |
| FR-7 | Simple API or page, with a short README | `killchain/api`, `web/`, `README.md` | `GET /incidents/{id}/path` works; README gets a judge from clone to results |

## Bonus

| ID | Requirement | Owner |
|---|---|---|
| B-1 | Risk score per incident, worst first | `killchain/score` |
| B-2 | Auto-written incident report in plain English | `killchain/report` |
| B-3 | Number of raw alerts merged into each incident | `killchain/correlate` |
| B-4 | New detection rule by editing a config file, not code | `rules/*.yaml`, `killchain/detect` |
| B-5 | Live mode: new log lines update the path within seconds | `killchain/live` |

## Targets (measured against the planted attacks)

| Metric | Good | Great | Measured by |
|---|---|---|---|
| Detection: share of planted steps found | > 70% | > 90% | `killchain/eval` |
| Correct labels: share of found steps with the right technique | > 60% | > 85% | `killchain/eval` |
| Attack path: planted attacks rebuilt in the right order | half | all | `killchain/eval` |
| False alarms: share of incidents that are not real attacks | < 30% | < 10% | `killchain/eval` |
| Processing time, full tier | < 3 h | < 1 h | `_stats.json` of each stage |
| Peak memory | < 16 GB | < 8 GB | `_stats.json` of each stage |
| Time to open one incident's path | < 2 s | < 500 ms | `killchain/eval` against the API |

Tier: Core 15 GB (1.0x), Advanced 30 GB (1.3x), Extreme 50 GB (1.6x). A
bigger tier only pays if accuracy stays above the bar.

## Non-requirements

Polished UI, login, user management, cloud deployment, blocking attacks.

## Constraints we set ourselves

- Runs from the README with `pip install -r requirements.txt` on a normal
  laptop. No database server, message queue or LLM is required. Docker Compose
  is added at the end as a convenience.
- Rules use event time from the logs, never processing time. Rows the parser
  flags with a bad `ts_quality` stay out of time-window rules.
- Every detection keeps the `source`, `line` and `byte_offset` of the raw lines
  behind it, so results can be scored against the manifest and shown as
  evidence.
