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
