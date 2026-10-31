# Detection rules

One YAML file per rule: `firewall/` for rules over the FortiGate table,
`windows/` for rules over the Windows table. Adding a rule means adding a file
here; no code changes (PRD bonus B-4).

Each rule will carry its ATT&CK technique and tactic, a filter, and one of the
rule kinds `match`, `threshold`, `distinct`, `sequence`, `periodic` or
`volume`. The exact format is defined with the rule engine in
`killchain/detect`.
