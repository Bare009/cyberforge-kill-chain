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
