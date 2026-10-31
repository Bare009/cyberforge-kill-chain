# Test fixtures

Real responses of `killchain/api` over `examples/sample-run`, so the UI tests
use exactly what the API returns. Regenerate after an API shape change (from
the repo root):

```powershell
python -c "import json; from fastapi.testclient import TestClient; from killchain.api import create_app; c = TestClient(create_app('examples/sample-run')); [open(f'web/src/test/fixtures/{n}.json', 'w', encoding='utf-8', newline='\n').write(json.dumps(c.get(p).json(), indent=1) + '\n') for n, p in [('mitre-matrix', '/mitre/matrix'), ('mitre-technique-T1190', '/mitre/techniques/T1190')]]"
```

| File | Endpoint |
|---|---|
| `mitre-matrix.json` | `GET /mitre/matrix` |
| `mitre-technique-T1190.json` | `GET /mitre/techniques/T1190` |
| `events-all.json` | `GET /incidents/1/events` (raw text read from `data/raw/firex-10G.log`) |
| `events-step2.json` | `GET /incidents/1/events?step=2` |
| `entity-attacker.json` | `GET /entities/32.127.48.11` |
| `entity-reach.json` | `GET /entities/10.10.20.31` |

The day-3 fixtures were made the same way with the raw log in `data/raw/`;
add their names and paths to the list in the command above to regenerate.
