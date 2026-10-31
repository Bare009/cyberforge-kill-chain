# P4b verification (anomaly layer)

All commands run from the repo root (`killchain/`), Windows PowerShell, miniconda `python`.
Baseline before P4b saved with `Copy-Item data\runs\firex-10G\metrics.json data\tmp\metrics-before-p4b.json`
(and `alerts.parquet` → `data\tmp\alerts-before-p4b.parquet`).

## 1. Validate

```
python -m killchain detect --validate --run data\runs\firex-10G
35 rules loaded, 0 errors
```

## 2. Detect

```
python -m killchain detect --run data\runs\firex-10G
```

| Detector | Alerts | Evidence lines | Secs |
|---|---|---|---|
| A01-rare-event | 6 | 14 | 0.31 |
| A02-first-seen-admin-pair | 1 | 2,400 | 0.11 |
| A03-first-seen-user-country | 4 | 8 | 0.05 |
| A04-outlier-sessions | 3 | 548 | 0.23 |
| A05-outlier-destinations | 3 | 1,266 | 0.56 |
| A06-outlier-ports | 0 | 0 | 0.28 |
| A07-outlier-failed-logins | 0 | 0 | 0.16 |
| A08-outlier-bytes-out | 2 | 360 | 0.25 |
| A09-denied-then-allowed | 1 | 241 | 0.12 |
| A10-lopsided-pair | 3 | 3,240 | 0.29 |
| A11-too-regular | 2 | 2,212 | 0.88 |
| **anomaly layer** | **25** | **10,289** | |
| rule layer (R01-R24, unchanged) | 32 | 34,334 | |

Final lines printed:

```
57 alerts, 44,623 evidence lines from 35 rules in 6.1 s (peak 985 MB) -> data\runs\firex-10G
rule layer 32 alerts, anomaly layer 25 alerts from 11 detectors
```

Runtime: 6.1 s for all 35 rules (rules alone were about 2 s; the 11 detectors add about 3.2 s).
All alerts pass `contracts.validate_alert` (detect exits 0; it exits 1 on any contract error).
Anomaly alerts are written to the same `data/runs/firex-10G/alerts.parquet` with `layer='anomaly'`;
rule alerts keep `layer='rule'`.

Rule alerts unchanged, checked with `data\tmp\p4b_check.py` (compares against the saved baseline):

```
rule alert ids same: True
R rows changed: []          # alerts, truth_lines, background_alerts of every R* row equal the baseline
```

The 25 anomaly alerts, by entity: rare events for Tejas.Roy (T1562 defense-evasion), parul.sinha, keerat.ghughal,
Deepika.Khan, svc_backup30 (T1078 initial-access) and Rakes (T1098 persistence); first-seen admin pairs 10.10.10.44;
new countries keerat.ghughal ×2, Deepika.Khan, svc_backup30; outliers 10.10.10.63, 10.10.10.118 ×2 (sessions),
10.10.10.63, 10.10.10.44 ×2 (destinations), 10.10.10.118 ×2 (bytes out); denied-then-allowed and lopsided and
too-regular for 32.127.48.11 → 10.10.20.20; lopsided 10.10.20.31 → 7.93.184.183 and 10.10.10.118 → 7.154.5.35;
too regular 10.10.10.112 → 198.79.124.52. A06 and A07 raise 0: the planted scanners and brute-force source have
1-5 active hours (no 24-hour baseline), and the busiest background hours passing the MAD test have 9 ports and
33 failures, under the absolute floors of 50.

## 3. Score

```
python -m killchain eval score --run data\runs\firex-10G --parsed data\parsed\firex-10G
```

```
detection_recall       100.0%       great
label_accuracy         100.0%       great
attack_path_rebuilt    0.0%         below   (P6 not built: no incidents yet)
false_alarm_share      0.0%         great
processing_secs        61 s         great
peak_rss_mb            4,477 MB     great
truth lines 32,200, covered 32,200 (anomaly-only 0); truth incidents 25, found 25
labels: exact 99.3%, parent 99.3%, any accepted 100.0%
our incidents 0, without truth 0 (confirmed false 0, unreviewed 0); multi-step rebuilt 0/4
anomaly layer: 25 alerts (0 background), anomaly-only truth lines 0, anomaly-only incidents 0 (0 false); rule layer alone: recall 100.0%, labels 100.0%
```

Per-rule table now has a `layer` column; anomaly rows:

```
rule                             layer    alerts  truth_lines  background
A01-rare-event                   anomaly      6           14           0
A02-first-seen-admin-pair        anomaly      1         2400           0
A03-first-seen-user-country      anomaly      4            8           0
A04-outlier-sessions             anomaly      3          537           0
A05-outlier-destinations         anomaly      3         1153           0
A08-outlier-bytes-out            anomaly      2          360           0
A09-denied-then-allowed          anomaly      1          241           0
A10-lopsided-pair                anomaly      3         3240           0
A11-too-regular                  anomaly      2         2212           0
```

Every R* row equals the baseline. Truth lines found only by the anomaly layer: 0 (the rules already cover all
32,200). Anomaly-only incidents and false ones: 0 and 0, because P6 (correlation) has not run; the counts are
wired and tested (`tests/test_eval.py::test_anomaly_only_false_incident`).

## 4. Tests

```
python -m pytest -q
102 passed in 8.66s
```

80 existing tests plus 22 new: `tests/test_anomaly.py` (20: anomaly rule loading and flags, `technique_by_file`
labels and errors, inline-wins, alert relabelling from evidence, one planted case per detector on a synthetic
4-day log, A09 evidence has exactly one accept, background sources raise nothing, A06/A07 quiet) and
`tests/test_eval.py` (2: anomaly-only false incident; anomaly labels do not lower rule metrics).
