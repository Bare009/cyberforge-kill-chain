"""Merge the track B results (threat intel, narrator reports) into contract-C incidents.

Kept free of heavy imports: the API uses `apply_enrichment` at start-up for runs
that have not been bundled yet.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

VERDICT_RANK = {"known-malicious": 3, "suspicious": 2, "no-reports": 1, "unknown": 0}
CONTRACT_ENRICHMENT_KEYS = ("kind", "zone", "verdict", "reputation", "providers", "tags", "flags", "sendable")
REPORT_SOURCES = ("ai", "template")


def worst_verdict(verdicts: Iterable[str]) -> Optional[str]:
    vs = list(verdicts)
    return max(vs, key=lambda v: VERDICT_RANK.get(v, 0)) if vs else None


def apply_enrichment(inc: Dict[str, Any], n: int, doc: Dict[str, Any]) -> Optional[str]:
    """Merge threat-intel results into one incident (in place); returns the incident's worst verdict.

    The incident's `enrichment` becomes the result for every entity listed
    under incident `n`, and each step gets the flags in `doc["steps"][n]`.
    Detection fields (chain, risk score, ...) are not touched.
    """
    ents = {v: e for v, e in doc["entities"].items() if n in (e.get("incidents") or [])}
    if not ents:
        return None
    inc["enrichment"] = {v: {k: e[k] for k in CONTRACT_ENRICHMENT_KEYS if k in e} for v, e in ents.items()}
    flags = (doc.get("steps") or {}).get(str(n)) or {}
    for s in inc.get("chain") or []:
        extra = flags.get(str(s.get("n"))) or []
        if extra:
            s["enrichment_flags"] = list(dict.fromkeys([*(s.get("enrichment_flags") or []), *extra]))
    return worst_verdict(e["verdict"] for e in ents.values())


def bind_enrichment(doc: Dict[str, Any], incidents: Dict[int, Dict[str, Any]],
                    alerts: Iterable[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """enrichment.json re-bound to these incidents: (ti document, values not enriched, values dropped).

    Entities are matched by value, so the result is right even when the risk
    score renumbered the incidents after enrich ran. Each entity's `incidents`
    and the per-step flags are recomputed from the current incident files.
    """
    from killchain.enrich.indicators import collect

    known = collect(incidents, alerts)
    source = doc.get("entities") or {}
    entities: Dict[str, Dict[str, Any]] = {}
    missing: List[str] = []
    for value, ind in sorted(known.items()):
        e = source.get(value)
        if e is None:
            missing.append(value)
            continue
        entities[value] = {**e, "incidents": sorted(ind.incidents)}
    dropped = sorted(set(source) - set(entities))

    steps: Dict[str, Dict[str, List[str]]] = {}
    for n, inc in sorted(incidents.items()):
        per: Dict[str, List[str]] = {}
        for s in inc.get("chain") or []:
            flags: List[str] = []
            for v in (s.get("src"), s.get("dst")):
                for f in (entities.get(v) or {}).get("flags") or []:
                    if f not in flags:
                        flags.append(f)
            if flags:
                per[str(s["n"])] = flags
        if per:
            steps[str(n)] = per

    verdicts: Dict[str, int] = {}
    for e in entities.values():
        verdicts[e["verdict"]] = verdicts.get(e["verdict"], 0) + 1
    out = {**doc, "entities": entities, "steps": steps,
           "summary": {**(doc.get("summary") or {}), "verdicts": verdicts},
           "bound": {"indicators": len(entities), "not_enriched": missing, "dropped": dropped}}
    return out, missing, dropped


def apply_report(inc: Dict[str, Any], entry: Dict[str, Any]) -> Optional[str]:
    """Put one report.json entry into an incident (in place); returns the triage verdict or None.

    An entry is `{source: ai|template, markdown, triage}`; `triage` is
    `{verdict, confidence, reasons}` or null.
    """
    src = entry.get("source")
    md = entry.get("markdown")
    if src not in REPORT_SOURCES or not isinstance(md, str) or not md.strip():
        raise ValueError(f"report for {inc.get('incident_id')}: needs source ai|template and non-empty markdown")
    triage = entry.get("triage")
    inc["report"] = {"source": src, "markdown": md, "triage": triage}
    inc["report_source"] = src
    return triage.get("verdict") if isinstance(triage, dict) else None
