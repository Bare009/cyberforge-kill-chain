"""Load a run bundle (contract C) into memory for the API.

A run folder holds `index.json`, `incidents/<n>.json`, `alerts.json` and
`run_summary.json` (docs/contracts.md, "Run layout"). Everything is read once
at start-up; each incident is also serialised once, so a request only looks up
bytes in a dict.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import orjson

from killchain.bundle.merge import apply_enrichment
from killchain.contracts import validate_alert, validate_incident

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]


class BundleError(Exception):
    """The run folder is missing or unreadable."""


@dataclass
class RunBundle:
    run_dir: Path
    run: str
    sample: bool
    index_rows: List[Dict[str, Any]]
    incidents: Dict[int, Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    run_summary: Dict[str, Any]
    # incident_id (stable hash) -> incident_number
    by_hash: Dict[str, int] = field(default_factory=dict)
    # incident_number -> serialised JSON of the full incident and of its path view
    incident_bytes: Dict[int, bytes] = field(default_factory=dict)
    path_bytes: Dict[int, bytes] = field(default_factory=dict)
    # contract problems found while loading; the API still serves the run
    errors: List[str] = field(default_factory=list)
    # threat intel merged into the incidents (ti.json from the bundle step, else enrichment.json); None when absent
    enrichment: Optional[Dict[str, Any]] = None
    enrichment_source: Optional[str] = None

    def resolve(self, ident: str) -> Optional[int]:
        """An incident's number from its number ("12") or its stable hash."""
        if ident.isdigit():
            n = int(ident)
            return n if n in self.incidents else None
        return self.by_hash.get(ident)


def default_data_dir() -> Path:
    """KILLCHAIN_DATA_DIR (relative paths are taken from the repo root), else <repo>/data."""
    data_dir = Path(os.environ.get("KILLCHAIN_DATA_DIR") or REPO_ROOT / "data")
    return data_dir if data_dir.is_absolute() else REPO_ROOT / data_dir


def default_raw_dir() -> Path:
    """Where the raw logs named in evidence rows are: KILLCHAIN_RAW_DIR, else <data dir>/raw."""
    raw = os.environ.get("KILLCHAIN_RAW_DIR")
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else REPO_ROOT / p
    return default_data_dir() / "raw"


def resolve_run_dir(run: Optional[str] = None) -> Path:
    """Find a run folder from a path or a run name.

    Order: the argument, else KILLCHAIN_RUN, else "sample-run". A name is looked
    up in `<KILLCHAIN_DATA_DIR>/runs/<name>` (default data/runs) and then in
    `examples/<name>`, so the sample works on a fresh clone.
    """
    name = run or os.environ.get("KILLCHAIN_RUN") or "sample-run"
    direct = Path(name)
    if direct.is_dir():
        return direct.resolve()
    data_dir = default_data_dir()
    for cand in (data_dir / "runs" / name, REPO_ROOT / "examples" / name):
        if cand.is_dir():
            return cand.resolve()
    raise BundleError(
        f"run '{name}' not found: looked for {direct}, {data_dir / 'runs' / name} and {REPO_ROOT / 'examples' / name}"
    )


def _read_json(path: Path) -> Any:
    try:
        return orjson.loads(path.read_bytes())
    except FileNotFoundError as exc:
        raise BundleError(f"missing {path}") from exc
    except orjson.JSONDecodeError as exc:
        raise BundleError(f"{path} is not valid JSON: {exc}") from exc


def path_view(inc: Dict[str, Any]) -> Dict[str, Any]:
    """What GET /incidents/{id}/path returns: the story and the graph (FR-5) and reach next (FR-6)."""
    return {
        "incident_number": inc["incident_number"],
        "incident_id": inc["incident_id"],
        "title": inc["title"],
        "risk_score": inc["risk_score"],
        "risk_band": inc["risk_band"],
        "chain_text": inc["chain_text"],
        "chain": inc["chain"],
        "gaps": inc["gaps"],
        "graph": inc["graph"],
        "next": inc["next"],
    }


def load_threat_intel(run_dir: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(document, file name) of the run's threat intel, or (None, None).

    ti.json (written by the bundle step, bound to the current incident numbers)
    wins while it was made from the current enrichment.json; when enrich ran
    again after the last bundle, enrichment.json is used and a rebundle is due.
    """
    docs = {}
    for name in ("ti.json", "enrichment.json"):
        p = run_dir / name
        if p.exists():
            doc = _read_json(p)
            if isinstance(doc, dict) and isinstance(doc.get("entities"), dict):
                docs[name] = doc
            else:
                log.warning("%s has no 'entities' object; ignored", p)
    ti, raw = docs.get("ti.json"), docs.get("enrichment.json")
    if ti and (raw is None or ti.get("generated_at") == raw.get("generated_at")):
        return ti, "ti.json"
    if raw:
        if ti:
            log.warning("enrichment.json is newer than ti.json; run python -m killchain.bundle --run %s", run_dir)
        return raw, "enrichment.json"
    return None, None


def load_bundle(run_dir: Path) -> RunBundle:
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise BundleError(f"run folder not found: {run_dir}")

    index = _read_json(run_dir / "index.json")
    alerts = _read_json(run_dir / "alerts.json")
    summary_path = run_dir / "run_summary.json"
    summary = _read_json(summary_path) if summary_path.exists() else {}

    if not isinstance(index, dict) or not isinstance(index.get("incidents"), list):
        raise BundleError(f"{run_dir / 'index.json'}: needs an object with a list 'incidents'")
    if not isinstance(alerts, list):
        raise BundleError(f"{run_dir / 'alerts.json'}: needs a list")

    enrichment, enrichment_source = load_threat_intel(run_dir)

    errors: List[str] = []
    incidents: Dict[int, Dict[str, Any]] = {}
    for row in index["incidents"]:
        n = row.get("incident_number")
        if not isinstance(n, int):
            errors.append(f"index.json: row without an integer incident_number: {row.get('incident_id')!r}")
            continue
        inc = _read_json(run_dir / "incidents" / f"{n}.json")
        if enrichment is not None:
            row["ti_verdict"] = apply_enrichment(inc, n, enrichment)
        errors += validate_incident(inc, f"incidents/{n}.json")
        incidents[n] = inc
    for i, a in enumerate(alerts):
        errors += validate_alert(a, f"alerts.json[{i}]")

    bundle = RunBundle(
        run_dir=run_dir,
        run=str(index.get("run") or summary.get("run") or run_dir.name),
        sample=bool(summary.get("sample") or index.get("sample")),
        index_rows=sorted(index["incidents"], key=lambda r: r.get("incident_number", 0)),
        incidents=incidents,
        alerts=alerts,
        run_summary=summary,
        errors=errors,
        enrichment=enrichment,
        enrichment_source=enrichment_source,
    )
    for n, inc in incidents.items():
        if isinstance(inc.get("incident_id"), str):
            bundle.by_hash[inc["incident_id"]] = n
        bundle.incident_bytes[n] = orjson.dumps(inc)
        try:
            bundle.path_bytes[n] = orjson.dumps(path_view(inc))
        except KeyError as exc:
            errors.append(f"incidents/{n}.json: cannot build the path view, missing {exc}")

    if errors:
        log.warning("run %s loaded with %d contract problem(s); first: %s", bundle.run, len(errors), errors[0])
    log.info("run %s: %d incidents, %d alerts from %s", bundle.run, len(incidents), len(alerts), run_dir)
    return bundle
