# Detection rules

One YAML file per rule; the file name is the rule's `id`. `firewall/` holds
rules over the FortiGate table, `anomaly/` the generic detectors (lower trust),
`windows/` rules for a Windows log if one arrives. Adding a rule means adding a
file here; no code changes (PRD bonus B-4).

```powershell
python -m killchain detect --validate --run data\runs\firex-10G     # check every file and its SQL
python -m killchain detect --run data\runs\firex-10G --only R01-admin-bruteforce   # one rule, output to detect-only/
python -m killchain detect --run data\runs\firex-10G               # all rules
python -m killchain eval score --run data\runs\firex-10G           # how the rules score
```

## Example

```yaml
id: R01-admin-bruteforce
title: Brute force on the firewall admin login
status: stable
tuning: "planted 2,000 failed logins in 10 min; busiest other source 25 per 10 min"
attack:
  technique: T1110.001
  alt_techniques: [T1110]
  tactic: credential-access
severity: 4
confidence: 0.9
kind: count
where: "log_desc = 'Admin login failed' AND NOT src_internal"
group_by: [src_ip]
window: 10m
having: {gte: 100}
entities: {src_ip: src_ip, dst_ip: dst_ip, user: user}
action_text: "{src_ip} tried {event_count} admin passwords against the firewall in {minutes} minutes"
```

## Fields

| Field | Meaning |
|---|---|
| `id`, `title`, `status` | `status`: experimental, test or stable |
| `tuning` | required note: planted count and background maximum the threshold was set from |
| `attack.technique` | ATT&CK id, checked against the catalogue; `unknown` for anomaly detectors |
| `attack.tactic` | required when the technique has several tactics; must be one of them |
| `attack.alt_techniques` | other acceptable ids |
| `attack.technique_by` | per-line labels, e.g. `dst_port: {3389: T1021.001}` |
| `attack.technique_by_file` | more per-line labels from a YAML file relative to the repo root (e.g. `config/rare_events.yaml`): column → value → `{technique, tactic}` or a plain id; inline `technique_by` wins. A `technique: unknown` rule takes each alert's label from its most common evidence label |
| `severity` 1-5, `confidence` 0-1, `promote` | `promote: true` makes one hit enough for an incident |
| `logsource` | `firewall` (default) or `windows` |
| `kind` | `match`, `count`, `distinct`, `sequence` or `sql` (below) |
| `where` | SQL condition over the `events` columns (README, "Query a parsed run") |
| `group_by` | columns, or `expression AS name`, e.g. `src_net24` or `lower(user) AS u` |
| `entities` | contract fields `src_ip`, `dst_ip`, `host`, `user`, `domain`, `url` → SQL; the alert takes the most common value |
| `success` | which evidence lines count as "got through" (default: not denied, dropped or blocked, and not failed) |
| `time_quality` | `valid` (default: only `ts_valid` rows) or `any` |
| `action_text` | sentence; placeholders: entity names, group_by names, `{event_count}`, `{minutes}`, `{hours}`, `{days}`, `{distinct_count}`, `{passed}`, `{blocked}`, `{src_count}`, `{dst_count}` |

## Kinds

| Kind | Extra fields | Alert when | Evidence |
|---|---|---|---|
| `match` | `split_gap` (default 1h), optional `having` on the line count | lines match; a gap longer than `split_gap` starts a new alert for the same key | the matching lines |
| `count` | `window`, `having` | a sliding window per key reaches the count | every line inside a qualifying window; overlapping windows merge |
| `distinct` | `window`, `field`, `having` | a sliding window per key reaches that many distinct values of `field` | as `count` |
| `sequence` | `steps: [{name, where, min}]`, `within` | step 1 … step N happen in order for the same key within `within`, each at least `min` times | all step lines in the window and the final line |
| `sql` | `sql` | your query returns rows `alert_key, source, line`; one alert per `alert_key` | the returned lines. `{events}` is the table with the time filter, `{all_events}` without |

## Anomaly detectors

Generic detectors in `anomaly/`, run by the same engine. Every file is `kind: sql`, `layer: anomaly`,
`promote: false`, confidence 0.3-0.5 and severity 2-3, so an anomaly alert never makes an incident on its
own; correlation (P6) joins it to incidents the rules start. Detectors use `{events}` only (skips `stuck` rows).
Outliers compare a source's hour to its own hours: each hour's value is divided by g(hour), the hour's
total traffic over the median hour, then tested against median + 6 MAD with a MAD floor and an absolute
floor; sources need 24 active hours for a baseline.

| Id | Flags | Label | firex-10G alerts |
|---|---|---|---|
| `A01-rare-event` | `log_id`, `log_desc` or `action` value seen < 20 times in the run | from `config/rare_events.yaml`, else `unknown` | 6 |
| `A02-first-seen-admin-pair` | internal source with ≥ 10 new (src, dst) pairs on admin ports after the first 2 days | T1021 | 1 |
| `A03-first-seen-user-country` | successful login / tunnel-up from a (user, country) first seen after the first 2 days | T1078 | 4 |
| `A04-outlier-sessions` | sessions per hour (MAD floor 10, ≥ 100) | `unknown` | 3 |
| `A05-outlier-destinations` | distinct destinations per hour (MAD floor 3, ≥ 25) | T1021 | 3 |
| `A06-outlier-ports` | distinct destination ports per hour (MAD floor 2, ≥ 50) | T1046 | 0 |
| `A07-outlier-failed-logins` | failed admin logins per hour (MAD floor 2, ≥ 50) | T1110 | 0 |
| `A08-outlier-bytes-out` | bytes sent to outside hosts per hour (MAD floor 100 kB, ≥ 1 MB) | T1048 | 2 |
| `A09-denied-then-allowed` | ≥ 50 denies, then an accept, same pair; evidence is the denies and the first accept | T1190 | 1 |
| `A10-lopsided-pair` | pair with sent ≥ 1 MB and ≥ 10 × received over the run; evidence is the sent > received lines | T1048 | 3 |
| `A11-too-regular` | ≥ 30 accepted sessions, mean gap ≥ 10 s, gap CV ≤ 0.1 | T1071 | 2 |

On firex-10G all 25 alerts overlap planted lines (0 background), and the 32 rule alerts are unchanged.
