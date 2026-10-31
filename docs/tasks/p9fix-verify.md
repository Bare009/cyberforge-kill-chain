# p9fix verification: number only rule steps; anomalies become supporting evidence

Branch `main`, run `data\runs\firex-10G`, parsed `data\parsed\firex-10G`, PowerShell, miniconda `python`.
Plan: `docs/tasks/p9fix-p10-plan.md` section 3 (decisions D1-D8). First iteration (no `p9fix-review.json`).

## What changed

- `killchain/graph/chain.py`: when an incident has a rule alert, only rule alerts are numbered; every
  anomaly alert is attached to one rule step as `supporting` (D2 key: shared entity, gap seconds, same
  tactic, nearest start, lower n; relation `during`/`before`/`after`). Anomaly-only incidents number their
  anomaly alerts with `supporting: []`. `gaps(stage_nos, also_seen)` lets supporting stages fill gaps
  without widening the range. `tactics`/`techniques`: numbered first, then supporting-only.
  `incident_lines.parquet` keeps supporting alerts' lines under the parent step.
- `killchain/graph/path.py`: each supporting alert is drawn with the parent step number, its own
  technique/tactic, `supporting: true` and a ` (anomaly)` label suffix. Rule-step edges have no new key.
- `killchain/graph/reach.py`: `evidence_steps(chain)` (steps plus supporting, P7 order) feeds footholds,
  touched and likely tactics, so `next` does not change.
- `killchain/eval/score.py`: membership and the false-alarm check include supporting alert ids
  (supporting rows take the parent step number).
- `killchain/contracts.py` + `docs/contracts.md`: optional `step.supporting` (new `SUPPORT` spec,
  `RELATIONS`), optional bool `edge.supporting`, duplicate alert id check, supporting ids must be in
  `alerts.json`. All optional; `examples/sample-run/` untouched and still valid.
- `killchain/graph/cli.py`: text form prints supporting entries; `chain/_stats.json` gains `supporting`.
- Docs: `README.md` rows 3a/3b, `docs/build-plan.md` P4b/P7 bullets, `docs/contracts.md`.

## Chain A (incident #1) and chain B (incident #2)

BEFORE (snapshot `data\tmp\p9fix_before_inc1.txt` / `inc2.txt`, taken before any edit):

```
#1 1. Initial Access → 2. Discovery → 3. Exfiltration → 4. Initial Access → 5. Persistence → 6. Command and Control → 7. Exfiltration
   (A09, R02, A10, R16, R20, A11, R12; 7 numbered steps)
#2 1. Execution → 2. Command and Control → 3-4. Exfiltration → 5. Discovery → 6. Exfiltration → 7. Discovery → 8. Exfiltration
   (R24, R11, A10, R12, A04, A08, A04, A08; 8 numbered steps)
```

AFTER (`python -m killchain chain --run data\runs\firex-10G 1` and `... 2`, full text in
`docs/tasks/p9fix-chains.txt`):

```
#1 1. Discovery → 2. Initial Access → 3. Persistence → 4. Exfiltration
 1. R02-port-scan x240
 2. R16-web-sql-injection x60
      + during: A09-denied-then-allowed T1190 x241
 3. R20-web-shell x40
 4. R12-large-lopsided-transfer x600
      + during: A10-lopsided-pair T1048 x840
      + during: A11-too-regular T1071 x600
#2 1. Execution → 2. Command and Control → 3. Exfiltration
 1. R24-malware-detected-not-blocked x3
 2. R11-beaconing x400
 3. R12-large-lopsided-transfer x400
      + during: A10-lopsided-pair, A04-outlier-sessions, A08-outlier-bytes-out, A04, A08
```

Gaps, `next` and reach sentences of both incidents are unchanged.

Attachment per incident (all relations `during`; matches the plan's D2 prediction):
#1 A09→2, A10→4, A11→4; #2 all five →3; #3 A01→1, A01→2, A03→2; #4 A01→1; #5 A10→1; #8 A02, A05, A05→2;
#9 A04, A05→1; #10 A01, A03, A03→1; #11 A01, A03→1; #12 A11→1. Others have no anomaly alerts.

## Commands run and results

| Command | Exit | Result |
|---|---|---|
| `python data\tmp\p9fix_snapshot.py` | 0 | before copies of chains.json, reach.json, metrics.json, incident 1/2 text |
| `python -m killchain detect --run data\runs\firex-10G` | 0 | 57 alerts (32 rule, 25 anomaly), 44,623 evidence lines, 12.6 s |
| `python -m killchain correlate --run data\runs\firex-10G` | 0 | 25 incidents (0 anomaly-only), 1 unexplained, largest 8 alerts |
| `python -m killchain chain --run data\runs\firex-10G` | 0 | 25 incidents, **32 numbered steps (2 ongoing), 24 supporting**, 19 gaps, 44,622 evidence lines, 0 contract errors, 0.28 s |
| `python -m killchain reach --run data\runs\firex-10G` | 0 | 11 incidents with reach, 14 with a stated reason, 0 contract errors, 0.95 s |
| `python -m killchain eval score --run data\runs\firex-10G --parsed data\parsed\firex-10G` | 0 | metrics below |
| `python data\tmp\p9fix_compare.py` | 0 | `next` identical 25/25, footholds identical 25/25, gaps identical 25/25 |
| `python data\tmp\p9fix_api_check.py` | 0 | see API check |
| `python -m pytest -q` | 0 | **304 passed** in 50.7 s (baseline 293) |

Ongoing steps: before 14 (anomaly steps overlapping), after 2 (R15 on #3, R13 on #8).

## Eval metrics (before → after)

| Metric | Before | After |
|---|---|---|
| detection_recall | 100.0 % | 100.0 % |
| label_accuracy | 100.0 % (exact 99.3 %) | 100.0 % (exact 99.3 %) |
| attack_path_rebuilt | 100.0 % (25/25) | 100.0 % (25/25) |
| multi_step_rebuilt | 4/4 | 4/4 |
| false_alarm_share | 0.0 % | 0.0 % |
| our incidents / spanning truth | 25 / [] | 25 / [] |
| processing_secs | 69.9 s | 69.2 s |
| peak_rss_mb | 4,477 | 4,477 |

`score.py` needed only the membership change: the dominant-alert rule already prefers rule alerts, and a
supporting alert takes its parent's step number, so the order check stays consistent.

## Bundle and API check (`data\tmp\p9fix_api_check.py`)

- `validate_bundle` on all 25 incidents: 0 errors.
- `/health`: `ok`, `contract_errors 0`, counts 25 incidents / 57 alerts / 44,623 events.
- `/incidents/1/path`: 200, steps [1, 2, 3, 4], supporting per step [0, 1, 0, 2], 3 supporting edges.
- `/incidents/2/path`: 200, steps [1, 2, 3], supporting per step [0, 0, 5], 5 supporting edges.
- `/incidents/1/events?step=1`: 200, total 240. `/incidents/1/events`: total 940 (rule-step lines only,
  see change c below). `/entities/32.127.48.11`: 200.

## Tests added or changed

- `tests/test_contracts.py::test_supporting_optional_and_checked` (sample valid; valid supporting entry;
  missing key, bad relation, bad tactic, bad time, non-list, duplicate id, id not in alerts.json, non-bool
  edge flag all rejected).
- `tests/test_chain.py`: `test_chain_b_rule_steps_and_supporting`, `test_outlier_during_beaconing_attaches_to_beaconing`
  (replace the two old chain B tests), `test_chain_a_supporting`, `test_attach_prefers_shared_entity`,
  `test_attach_before_and_after`, `test_attach_tie_breaks`, `test_anomaly_only_incident_is_numbered`,
  `test_supporting_fields`, `test_graph_draws_supporting_edges`, `test_incident_lines_and_tactics_include_supporting`;
  `test_step_fields_and_evidence` allows `supporting`; `test_graph_edges` asserts rule edges have no
  `supporting` key; `test_real_run_chains` rewritten (exact rule order and chain_text for A and B,
  supporting placement, every anomaly member once as supporting, 32 numbered + 24 supporting, 44,622 lines).
- `tests/test_reach.py::test_footholds_include_supporting`.
- `tests/test_eval.py::test_supporting_alerts_count_for_paths`.

## Teammate UI and API (read-only check)

Renders without their code changing:
- `killchain/api/bundle.py` validates with `validate_incident` (accepts the optional keys) and `path_view`
  passes `chain` and `graph` through, so `supporting` reaches `GET /incidents/{id}/path`.
- `web/src/components/incident/AttackTimeline.tsx` renders only the fields it knows; the numbered timeline
  now shows rule steps only. Extra keys are ignored at runtime.
- `web/src/lib/pathGraph.ts` lays out every `kind == 'step'` edge by `step`; supporting edges carry the
  parent's step number, so they are placed, coloured (by the anomaly's tactic) and played with their
  parent step, and fanned out when parallel. The graph keeps showing anomaly evidence.
- `killchain/api/entities.py` matches graph node ids and `chain[].src/dst`; still works (anomaly entities
  are the same values in these runs).

Changes they need to make to show supporting evidence fully (none blocks rendering today):
- (a) `web/src/types/incident.ts`: add a `SupportingAlert` type (fields in `docs/contracts.md`), plus
  `supporting?: SupportingAlert[]` on `Step` and `supporting?: boolean` on `GraphEdge`.
- (b) `AttackTimeline.tsx` `StepItem`: list `step.supporting` under the step (action, rule_id, technique,
  relation, times, event_count) with the existing anomaly badge.
- (c) `killchain/api/evidence.py` `lines()` and `counts_by_step()`: build `step_of` from `chain[].alert_id`
  **and** `chain[].supporting[].alert_id` (both → `s["n"]`). Today the Evidence tab omits supporting lines
  (incident #1 shows 940 lines, rule steps only).
- (d) optional: `pathGraph.ts` draw `supporting` edges thinner or dashed; the tooltip `action` currently
  shows the parent step's action for them.
- (e) `killchain/enrich/indicators.py::collect` `step_of`: include supporting alert ids so their
  domains/URLs are looked up per step.
- (f) re-run `python -m killchain.enrich` after `chain`: step numbers changed, and step flags in
  `enrichment.json` are keyed by step number.
- (g) `killchain/bundle/build.py` (P11, arrived in 43dcd99 during this task's rebase): the membership
  fallback used when `incident_alerts.parquet` is missing (`member_of` from `chain[].alert_id`, about line
  247) should also take `chain[].supporting[].alert_id`, or those anomaly alerts get `incident_number: null`.
  The normal path reads `incident_alerts.parquet` and is unaffected. Its `steps` count is numbered steps.

After the rebase onto 43dcd99, `python -m pytest -q`: **317 passed** in 69.9 s (their 13 bundle tests included).
