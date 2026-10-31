# Notes on the organisers' data

Based on slices of `firex-10G.log` (about 10% of its real-traffic region) and
`firex-30G.log.manifest.json`, both from `logs.zip` (31 October 2026).

## firex-10G.log (6.54 GB)

FortiGate (FortiOS) `key=value` lines from one device, `FGT60FTK00000000`,
time zone +0530.

| Bytes | Lines | Content |
|---|---|---|
| 0 to 2.03 GB | 3.85 M | Real traffic, 2026-10-23 08:48:26 to 2026-10-30 08:48:25 +0530, in time order |
| 2.03 to 4.82 GB | 5.28 M | Same event mix, every line stamped 2026-10-30 08:48:25.999999; 8.7% exact duplicates; no attack lines seen |
| 4.82 to 6.54 GB | about 6.8 M | Random bytes |

Event mix in the real region: traffic/forward 64%, failed admin logins 14%,
webfilter 4.4%, IPS 3.0%, app-ctrl 3.0%, DNS 3.0%, antivirus 1.5%, VPN 1.5%,
device health 5.5%.

Things rules must respect:

- Alert-looking noise is common: scanner logins, random IPS signatures,
  antivirus blocks of `/download/setup.exe`. One alert is not an incident.
- `service` does not match the port (`service="RDP"` on 443). Use `dst_port`.
- `eventtime` is the local wall clock written as if it were UTC.
- Rows in the stuck-clock region must stay out of time-window rules.

## The manifest

It describes the **30 GB** tier (seed 2): a firewall log of 19.6 GB and a
Windows JSON-lines log of 10.4 GB. Its offsets, times and IPs do not match
`firex-10G.log`, but the attack types and their event counts do (for example
80 path-traversal events in both). Each incident lists `at: [line, byte,
stream]` for every planted event; lines are 1-based, bytes 0-based, stream 0 is
the firewall log and 1 the Windows log.

## The 29 planted incident types

| # | Name | Stream | ATT&CK |
|---|---|---|---|
| 1 | brute-force-burst | firewall | T1110.001 |
| 2 | port-scan | firewall | T1046 |
| 3 | known-bad-destination | firewall | T1071.001 |
| 4 | malware-download | firewall | T1105 |
| 5 | admin-login-odd-hour | firewall | T1078.001 |
| 6 | slow-credential-stuffing | firewall | T1110.004 |
| 7 | successful-login-after-failures | firewall | T1110.001, T1078 |
| 8 | impossible-travel | firewall | T1078.004 |
| 9 | lateral-movement | firewall | T1021.002, T1021.001 |
| 10 | dns-tunnel | firewall | T1071.004, T1048.003 |
| 11 | c2-beaconing | firewall | T1071.001, T1573 |
| 12 | staged-exfiltration | firewall | T1048.002, T1030 |
| 13 | insider-drift | firewall | T1078.002, T1083 |
| 14 | logging-disabled-around-a-change | firewall | T1562.002, T1070 |
| 15 | rogue-admin-account | firewall | T1136.001, T1098 |
| 16 | sql-injection | firewall | T1190, T1595.002 |
| 17 | cross-site-scripting | firewall | T1189, T1059.007 |
| 18 | path-traversal | firewall | T1190, T1083 |
| 19 | command-injection | firewall | T1190, T1059.004 |
| 20 | web-shell-in-use | firewall | T1505.003, T1071.001 |
| 21 | syn-flood | firewall | T1498.001 |
| 22 | http-flood | firewall | T1498.001, T1499.002 |
| 23 | dns-amplification | firewall | T1498.002 |
| 24 | dcerpc-enumeration | windows | T1135, T1087.002, T1018 |
| 25 | smb-password-spray | windows | T1110.003, T1021.002 |
| 26 | kerberoasting | windows | T1558.003 |
| 27 | remote-service-execution | windows | T1569.002, T1021.002 |
| 28 | chain-web-to-domain-admin | both, 11 stages | T1595.002 → T1190 → T1505.003 → T1059.003 → T1135 → T1558.003 → T1021.002 → T1136.002 → T1560.001 → T1048.002 → T1070.001 |
| 29 | chain-ransomware-precursor | both, 9 stages | T1566.001 → T1204.002 → T1071.001 → T1003.001 → T1087.002 → T1021.001 → T1562.001 → T1490 → T1048.002 |

## Open questions for the organisers

1. Manifest for `firex-10G.log`.
2. The Windows stream for the 10 GB tier.
3. Whether the stuck-clock region and the random tail are intended, and
   whether planted events can fall inside them.
4. Whether a "step" for recall is one event in `at` or one stage.
