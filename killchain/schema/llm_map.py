"""LLM suggestions for the fields the synonym table does not know (one call, a second only for values).

The model sees killchain's column list with meanings, the columns already mapped, and every unmatched
field with 3-5 sample values. It answers JSON:

    {"field_map": {"<source field>": "<column>"}, "value_maps": {"action": {"<raw>": "<canonical>"}},
     "category": "network | endpoint | auth | vendor_alert | other", "ts_field": "<field or null>",
     "ts_format": "epoch | iso | <strptime format> | null"}

The answer is cached in data/cache/schema_llm/<hash>.json, keyed on a hash of the sorted field set, so
a file with the same fields never calls the model again. Everything the model proposes is checked
before use: unknown fields or columns are ignored, value maps must target a known canonical value,
and mapped fields go through the same validation as synonym matches (a field that fails is dropped).
Uses killchain.agents.llm.LLMClient (fallback chain, temperature 0); keys are never printed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import canonical as C

ROOT = Path(__file__).resolve().parents[2]
CACHE_DIR = ROOT / "data" / "cache" / "schema_llm"
PROMPT_VERSION = 1
MAX_FIELDS = 80
MAX_TOKENS = 1500

SYSTEM = ("You map fields of a security product's log export to a fixed set of columns. Answer only with JSON. "
          "Map a field only when its meaning clearly matches the column's meaning and its sample values fit. "
          "Leave a field out when unsure. Never invent field names; use them exactly as given.")


def fields_hash(fields: Sequence[str]) -> str:
    blob = json.dumps({"v": PROMPT_VERSION, "fields": sorted(set(fields))}, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def client_or_reason(no_llm: bool) -> Tuple[Any, Optional[str]]:
    """(LLMClient, None) or (None, why the LLM step is skipped)."""
    if no_llm:
        return None, "--no-llm"
    try:
        from ..agents import settings
        from ..agents.llm import LLMClient
    except Exception as e:  # pragma: no cover - agents package missing or broken
        return None, f"LLM client unavailable ({type(e).__name__})"
    if not settings.llm_enabled():
        return None, "LLM off (LLM_ENABLED is not true in .env)"
    eps = settings.endpoints("large")
    if not eps:
        return None, "no LLM key in .env (LLM_PRIMARY_API_KEY / LLM_FALLBACK_API_KEY)"
    return LLMClient(eps), None


def build_prompt(unmatched: Dict[str, List[str]], mapped: Dict[str, List[str]],
                 literal_values: Dict[str, List[str]], vocab: Dict[str, set]) -> List[Dict[str, str]]:
    cols = {c: C.MEANINGS.get(c, "") for c in C.MAPPABLE if c not in ("category",)}
    body = {
        "columns": cols,
        "already_mapped": {c: fs for c, fs in mapped.items()},
        "unmatched_fields": {f: vals for f, vals in list(unmatched.items())[:MAX_FIELDS]},
        "values_to_map": literal_values,
        "canonical_values": {c: sorted(v) for c, v in vocab.items() if c in literal_values},
        "answer_format": {
            "field_map": {"<unmatched field>": "<column>"},
            "value_maps": {"<column>": {"<raw value>": "<one of canonical_values>"}},
            "category": "network | endpoint | auth | vendor_alert | other",
            "ts_field": "<field holding the event time, if no column 'ts' is mapped yet, else null>",
            "ts_format": "epoch | iso | <python strptime format> | null",
        },
    }
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": json.dumps(body, ensure_ascii=False, indent=0)}]


def _parse(content: str) -> Dict[str, Any]:
    try:
        doc = json.loads(content)
    except ValueError:
        s, e = content.find("{"), content.rfind("}")
        doc = json.loads(content[s:e + 1]) if s >= 0 and e > s else {}
    return doc if isinstance(doc, dict) else {}


def suggest(client: Any, all_fields: Sequence[str], unmatched: Dict[str, List[str]], mapped: Dict[str, List[str]],
            literal_values: Dict[str, List[str]], vocab: Dict[str, set],
            cache_dir: Path = CACHE_DIR) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(checked answer, info {calls, cached, endpoint, notes, rejected}). Raises nothing: an error is in info."""
    info: Dict[str, Any] = {"calls": 0, "cached": False, "endpoint": None, "notes": [], "rejected": []}
    key = fields_hash(all_fields)
    cache = Path(cache_dir) / f"{key}.json"
    raw: Optional[Dict[str, Any]] = None
    if cache.exists():
        try:
            raw = json.loads(cache.read_text(encoding="utf-8"))
            info["cached"] = True
        except ValueError:
            raw = None
    if raw is None:
        if not unmatched and not literal_values:
            return {"field_map": {}, "value_maps": {}}, info
        try:
            res = client.chat(build_prompt(unmatched, mapped, literal_values, vocab), max_tokens=MAX_TOKENS, json_mode=True)
            info["calls"] += 1
            info["endpoint"] = getattr(res, "endpoint", None)
            raw = _parse(res.content)
            # A second call only for literal values the first answer left unmapped.
            left = {c: [v for v in vs if v not in ((raw.get("value_maps") or {}).get(c) or {})]
                    for c, vs in literal_values.items()}
            left = {c: vs for c, vs in left.items() if vs}
            if left:
                res2 = client.chat(build_prompt({}, mapped, left, vocab), max_tokens=MAX_TOKENS, json_mode=True)
                info["calls"] += 1
                more = _parse(res2.content).get("value_maps") or {}
                vm = raw.setdefault("value_maps", {})
                for c, m in more.items():
                    if isinstance(m, dict):
                        vm.setdefault(c, {}).update(m)
        except Exception as e:      # LLMError, network, bad JSON: the schema goes on without it
            info["notes"].append(f"LLM call failed: {type(e).__name__}: {str(e)[:200]}")
            return {"field_map": {}, "value_maps": {}}, info
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(raw, indent=1, ensure_ascii=False), encoding="utf-8")
    return check_answer(raw, unmatched, all_fields, mapped, vocab, info), info


def check_answer(raw: Dict[str, Any], unmatched: Dict[str, List[str]], all_fields: Sequence[str],
                 mapped: Dict[str, List[str]], vocab: Dict[str, set], info: Dict[str, Any]) -> Dict[str, Any]:
    fields = set(all_fields)
    out: Dict[str, Any] = {"field_map": {}, "value_maps": {}, "category": None, "ts_field": None, "ts_format": None}
    for f, col in (raw.get("field_map") or {}).items():
        if f not in fields or f not in unmatched:
            info["rejected"].append(f"field_map {f!r}: not an unmatched field")
        elif col not in C.MAPPABLE or col == "category":
            info["rejected"].append(f"field_map {f!r} -> {col!r}: not a column")
        else:
            out["field_map"][f] = col
    for col, m in (raw.get("value_maps") or {}).items():
        if col not in C.LITERAL_COLS or not isinstance(m, dict):
            info["rejected"].append(f"value_maps {col!r}: not a literal column")
            continue
        ok = {}
        for k, v in m.items():
            if str(v) in vocab.get(col, set()):
                ok[str(k).strip().lower()] = str(v)
            else:
                info["rejected"].append(f"value_maps {col}: {k!r} -> {v!r} is not a known value")
        if ok:
            out["value_maps"][col] = ok
    cat = raw.get("category")
    if cat in ("network", "endpoint", "auth", "vendor_alert", "other"):
        out["category"] = cat
    tf = raw.get("ts_field")
    if tf and "ts" not in mapped:
        if tf in fields:
            out["ts_field"] = tf
            out["ts_format"] = raw.get("ts_format") if isinstance(raw.get("ts_format"), str) else None
        else:
            info["rejected"].append(f"ts_field {tf!r}: not a field")
    return out
