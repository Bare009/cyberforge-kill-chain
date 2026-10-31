# killchain

Kill chain and attack path analysis over large security log sets (CyberForge PRD
"Kill Chain and Attack Path Analysis"). Built in stages; this README grows with
each one.

| Stage | Status |
|---|---|
| 1. Streaming log parser (FR-1) | done: `killchain.parser` |
| 2. Detection rules with ATT&CK labels (FR-2, FR-3, B-4) | next |
| 3. Incidents, attack paths, reach-next (FR-4 to FR-6) | planned |
| 4. API and UI (FR-7) | planned |
| 5. Scoring harness against the ground-truth manifest | planned |

Requirements and targets: `docs/requirements.md`. Pipeline and stage
contracts: `docs/architecture.md`. What the organisers' data looks like:
`docs/data-notes.md`.

## Layout

```
killchain/          Python package, one sub-package per pipeline stage
  parser/           raw logs -> Parquet (built)
  attack/           ATT&CK catalogue and kill chain stage order
  detect/           YAML rule engine
  correlate/        incident builder
  graph/            attack paths and reach-next
  score/            risk score
  report/           plain-English reports
  api/              FastAPI app
  eval/             scoring against the ground-truth manifest
  live/             live mode
rules/              detection rules, firewall/ and windows/
web/                React UI
tools/              developer checks
docs/               requirements, architecture, data notes
data/               local inputs and outputs, never committed
```

## Setup

Python 3.11 or newer.

```powershell
pip install -r requirements.txt
```

Put the organisers' files under `data/raw/` (for example
`data/raw/firex-10G.log`). `data/` is ignored by git.
