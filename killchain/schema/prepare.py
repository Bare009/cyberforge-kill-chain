"""`schema` stage: detect the format, sample, map fields to canonical columns, validate, and report.

    fmt, mapping, report = prepare("export.csv", "data/runs/x", no_llm=True)

Writes <run_dir>/schema.yaml (the mapping, readable and editable), <run_dir>/schema_report.json, and
config/schemas/<fingerprint>.yaml. The fingerprint is a hash of the format and the sorted field set of
the sample; a mapping found under config/schemas is reused as-is (pass force=True to build a new one).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import pyarrow as pa
import pyarrow.compute as pc
import yaml

from ..parser.fortigate import FIELDS
from . import canonical as C
from . import formats as F
from .convert import CATEGORIES, Mapper, records_getter, row_categories
from .coverage import RULE_DIRS, available_columns, rule_report, rule_requirements
from .llm_map import CACHE_DIR, client_or_reason, suggest
from .mapping import (SYNONYMS_YAML, Synonyms, canonical_vocab, detect_time_format, load_synonyms, map_value, match_fields,
                      norm, product_hint, severity_scale, to_text)
from .validate import MIN_SHARE, check, validate_columns

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = ROOT / "config" / "schemas"
DECOMPRESSED = ROOT / "data" / "tmp" / "decompressed"
SAMPLE_N = 2000
VERSION = 1
MAX_GROUPS = 50
GROUP_MAJORITY = 0.8
TIME_KEYS = ("ts", "tz", "date", "time_of_day")


class SchemaError(Exception):
    pass


# ── input ───────────────────────────────────────────────────────────────────

def plain_input(path: Union[str, Path], tmp_root: Optional[Path] = None) -> Tuple[Path, Optional[str]]:
    """A seekable plain file for `path`: itself, or a cached decompressed copy of a .gz / .zip
    (under data/tmp/decompressed/<hash of path, size, mtime>/; offsets and lines refer to that copy)."""
    path = Path(path)
    tmp_root = Path(tmp_root or DECOMPRESSED)
    _, comp = F.read_head(path, 4)
    if comp is None:
        return path, None
    st = path.stat()
    key = hashlib.sha1(f"{path.resolve()}|{st.st_size}|{st.st_mtime_ns}".encode()).hexdigest()[:12]
    out_dir = tmp_root / key
    done = out_dir / ".done"
    if done.exists():
        name = done.read_text(encoding="utf-8").strip()
        if (out_dir / name).exists():
            return out_dir / name, comp
    dst = F.decompress(path, out_dir)
    done.write_text(dst.name, encoding="utf-8")
    return dst, comp


def fingerprint(det: F.Detected, fields: Sequence[str]) -> str:
    blob = json.dumps({"format": det.format, "delimiter": det.delimiter, "payload": det.payload,
                       "fields": sorted(set(fields))}, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# ── FortiGate (existing parser) ──────────────────────────────────────────────

def fortigate_mapping(detected: str = "fortigate") -> Dict[str, Any]:
    m: Dict[str, Any] = {
        "version": VERSION, "format": "fortigate", "parser": "killchain.parser (FortiGate key=value, unchanged)",
        "time": {"date_field": "date", "time_field": "time", "tz_field": "tz", "field": "eventtime", "format": "fortigate"},
        "columns": {name: {"fields": [key], "method": "fortigate"} for key, name, _ in FIELDS},
    }
    if detected != "fortigate":
        m["detected"] = detected
        m["note"] = "no supported format recognised; the FortiGate parser reads the file and rejects what it cannot parse"
    return m


def _fortigate_sample(path: Path, n: int) -> pa.Table:
    from ..parser.lines import LineParser

    lines = []
    size = path.stat().st_size
    starts = [(0, 1)]
    if size > 4 * F.HEAD_BYTES:
        # the sample's line numbers are not used, so the middle part is not counted (that would read
        # half the file: 3 GB on firex-10G)
        starts.append((F.mid_offset(path), 1))
    for s, first in starts:
        got = 0
        for raw, ln, off in F.iter_lines(path, s, None, first):
            lines.append((raw, ln, off))
            got += 1
            if got >= n:
                break
    tables = LineParser(path.name).parse(lines)
    return tables.get("firewall") or pa.table({f.name: pa.array([], f.type) for f in C.SCHEMA})


# ── sample helpers ───────────────────────────────────────────────────────────

def _field_order(records: Sequence[Dict[str, Any]]) -> List[str]:
    seen: Dict[str, None] = {}
    for r in records:
        for k in r:
            seen.setdefault(k, None)
    return list(seen)


def _detect_expand(records: Sequence[Dict[str, Any]], fields: Sequence[str]) -> List[str]:
    """Text fields that carry a key=value or CEF/LEEF payload in most records (e.g. a JSON 'message')."""
    out = []
    for f in fields:
        vals = [r.get(f) for r in records[:500] if isinstance(r.get(f), str) and r.get(f)]
        if len(vals) < 5:
            continue
        hits = sum(F.looks_kv(v) or bool(F._CEF_RE.search(v.encode("utf-8", "replace")))
                   or bool(F._LEEF_RE.search(v.encode("utf-8", "replace"))) for v in vals)
        if hits / len(vals) >= 0.5:
            out.append(f)
    return out


def _multiline_csv(path: Path, n: int = 5000) -> bool:
    for i, (raw, _, _) in enumerate(F.iter_lines(path)):
        if raw.count(b'"') % 2:
            return True
        if i >= n:
            break
    return False


def _distinct(records: Sequence[Dict[str, Any]], f: str, k: int = 5) -> List[str]:
    out: List[str] = []
    for r in records:
        t = to_text(r.get(f))
        if t is not None:
            t = t[:80]
            if t not in out:
                out.append(t)
                if len(out) >= k:
                    break
    return out


def _time_spec(cols: Dict[str, List[str]], records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    tz_field = (cols.get("tz") or [None])[0]
    if cols.get("date") and cols.get("time_of_day"):
        d, t = cols["date"][0], cols["time_of_day"][0]
        vals = []
        for r in records:
            a, b = to_text(r.get(d)), to_text(r.get(t))
            vals.append(f"{a} {b}" if a and b else None)
        fmt, share, zoned = detect_time_format(vals, MIN_SHARE)
        if fmt and share >= MIN_SHARE:
            return {"date_field": d, "time_field": t, "format": fmt, "tz_field": tz_field, "zoned": zoned,
                    "parsed_share": share}
    for f in cols.get("ts") or []:
        if cols.get("date") and cols.get("time_of_day") and (f in cols["time_of_day"] or f in cols["date"]):
            continue          # the time part of a date + time pair is not an event time on its own
        fmt, share, zoned = detect_time_format([to_text(r.get(f)) for r in records], MIN_SHARE)
        if fmt and share >= MIN_SHARE:
            return {"field": f, "format": fmt, "tz_field": tz_field, "zoned": zoned, "parsed_share": share}
    return {}


def _group_field(fields: Sequence[str], records: Sequence[Dict[str, Any]], syn: Synonyms) -> Optional[str]:
    by_norm: Dict[str, str] = {}
    for f in fields:
        by_norm.setdefault(norm(f), f)
    for name in syn.event_type_fields:
        f = by_norm.get(norm(name))
        if f is None:
            continue
        filled = sum(to_text(r.get(f)) is not None for r in records)
        if records and filled / len(records) >= 0.5:
            return f
    return None


def _coverage(table: pa.Table) -> Dict[str, float]:
    n = table.num_rows or 1
    cov = {c: round(1 - table[c].null_count / n, 4) for c in C.OUTPUT_COLUMNS if c in table.column_names}
    cov["ts"] = round(pc.sum(pc.is_in(table["ts_quality"], value_set=pa.array(["ok", "tz_assumed"]))).as_py() / n, 4) \
        if table.num_rows else 0.0
    return cov


# ── the mapping ──────────────────────────────────────────────────────────────

def build_mapping(det: F.Detected, records: Sequence[Dict[str, Any]], fields: Sequence[str], syn: Synonyms, *,
                  fp: str, assume_tz: str, expand: List[str], multiline: bool, llm_client: Any, llm_reason: Optional[str],
                  llm_cache: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(mapping, build info {checks, dropped, llm})."""
    cols = match_fields(fields, det.format, syn)
    methods: Dict[Tuple[str, str], str] = {(c, f): ("pattern" if f.startswith("parsed.") else "synonym")
                                           for c, fs in cols.items() for f in fs}
    kept, dropped, checks = validate_columns(cols, records, syn.value_maps, to_text)

    # LLM for the leftovers
    vocab = canonical_vocab(syn)
    llm: Dict[str, Any] = {"used": False, "reason": llm_reason, "added": []}
    used = {f for fs in kept.values() for f in fs}
    unmatched = {f: _distinct(records, f) for f in fields if f not in used}
    unmatched = {f: v for f, v in unmatched.items() if v}
    literal_values: Dict[str, List[str]] = {}
    for c in C.LITERAL_COLS:
        if c not in kept:
            continue
        cnt: Counter = Counter()
        for r in records:
            for f in kept[c]:
                t = to_text(r.get(f))
                if t is not None:
                    cnt[t.strip().lower()] += 1
                    break
        left = [v for v, _ in cnt.most_common(40) if v not in (syn.value_maps.get(c) or {})
                and not (c in ("log_type", "log_subtype") and map_value(c, v, syn.value_maps) != v)]
        if left:
            literal_values[c] = left
    llm_value_maps: Dict[str, Dict[str, str]] = {}
    llm_category = None
    if llm_client is not None:
        answer, info = suggest(llm_client, fields, unmatched, kept, literal_values, vocab, llm_cache)
        llm.update(used=True, reason=None, **{k: info[k] for k in ("calls", "cached", "endpoint", "notes", "rejected")})
        for f, c in answer["field_map"].items():
            cur = kept.get(c, [])
            if len(cur) >= 3:
                continue
            r = check(c, [to_text(rec.get(f)) for rec in records], syn.value_maps)
            checks.setdefault(c, {})[f] = r
            if r["ok"]:
                kept[c] = cur + [f]
                methods[(c, f)] = "llm"
                llm["added"].append({"field": f, "column": c})
            else:
                dropped.append({"column": c, "field": f, "method": "llm", "share": r["share"],
                                "reason": f"{r['rule']}: {r['share']:.0%} of {r['n']} values pass",
                                "bad_examples": r["bad_examples"]})
        if answer.get("ts_field") and "ts" not in kept:
            kept["ts"] = [answer["ts_field"]]
            methods[("ts", answer["ts_field"])] = "llm"
        llm_value_maps = answer.get("value_maps") or {}
        llm_category = answer.get("category")

    time_spec = _time_spec(kept, records)
    if not time_spec.get("date_field"):
        for c in ("date", "time_of_day"):      # only used as a date + time pair
            kept.pop(c, None)
    if not time_spec and kept.get("ts"):
        for f in kept["ts"]:
            dropped.append({"column": "ts", "field": f, "reason": "no time format parses 90% of the values",
                            "share": 0.0, "bad_examples": _distinct(records, f, 3)})

    # value maps actually seen (readable in schema.yaml; the parse also applies the defaults)
    value_maps: Dict[str, Dict[str, str]] = {}
    maps = {c: dict(m) for c, m in syn.value_maps.items()}
    for c, m in llm_value_maps.items():
        maps.setdefault(c, {}).update(m)
    unknown_values: Dict[str, List[str]] = {}
    for c in list(C.LITERAL_COLS) + ["proto"]:
        if c not in kept:
            continue
        cnt = Counter()
        for r in records:
            for f in kept[c]:
                t = to_text(r.get(f))
                if t is not None:
                    cnt[t.strip().lower()] += 1
                    break
        vm = {}
        for v, _ in cnt.most_common(60):
            vm[v] = map_value(c, v, maps)
            known = v in (maps.get(c) or {}) or (c in ("log_type", "log_subtype") and vm[v] != v)
            if not known and c in C.LITERAL_COLS:
                unknown_values.setdefault(c, []).append(v)
        if vm:
            value_maps[c] = {k: (int(v) if c == "proto" and str(v).isdigit() else v) for k, v in vm.items()}
    for c, m in llm_value_maps.items():
        value_maps.setdefault(c, {}).update(m)

    sev_scale = severity_scale(to_text(r.get(kept["severity"][0])) for r in records) if kept.get("severity") else None
    vsev_scale = None
    if kept.get("vendor_severity"):
        vsev_scale = (checks.get("vendor_severity", {}).get(kept["vendor_severity"][0]) or {}).get("scale")

    columns: Dict[str, Any] = {}
    for c in C.MAPPABLE:
        if c == "category" or c not in kept:
            continue
        fs = kept[c]
        if c == "ts" and time_spec.get("field"):
            fs = [time_spec["field"]] + [f for f in fs if f != time_spec["field"]]
        ms = [methods.get((c, f), "synonym") for f in fs]
        entry: Dict[str, Any] = {"fields": fs, "method": ms[0]}
        if len(set(ms)) > 1:
            entry["methods"] = ms
        columns[c] = entry
    mapping: Dict[str, Any] = {
        "version": VERSION, "fingerprint": fp, "format": det.format, "delimiter": det.delimiter,
        "payload": det.payload, "compressed": det.compressed, "multiline": multiline,
        "wrappers": list(syn.wrappers), "expand": expand, "assume_tz": assume_tz,
        "time": {k: v for k, v in time_spec.items() if k != "parsed_share"},
        "columns": columns, "value_maps": value_maps,
        "value_maps_by": syn.value_maps_by, "derive": syn.derive,
        "severity_scale": sev_scale, "vendor_severity_scale": vsev_scale,
    }
    if "product" not in columns:            # a product without a product field (SentinelOne, Wazuh exports)
        hint = product_hint(fields, syn)
        if hint:
            mapping["product_name"] = hint
    # categories per record group
    gf = _group_field(fields, records, syn)
    cat: Dict[str, Any] = {"field": gf, "map": {}, "default": "per_record"}
    if records:
        m0 = Mapper({**mapping, "category": {}}, syn)
        get = records_getter(records, m0.needed_fields() + ([gf] if gf else []))
        tcols = m0.text_columns(get, len(records))
        per_row = row_categories(tcols, len(records)).to_pylist()
        if gf:
            groups: Dict[str, Counter] = {}
            for r, c in zip(records, per_row):
                groups.setdefault(to_text(r.get(gf)) or "", Counter())[c] += 1
            if len(groups) <= MAX_GROUPS:
                for g, cnt in groups.items():
                    top, k = cnt.most_common(1)[0]
                    if g and k / sum(cnt.values()) >= GROUP_MAJORITY:
                        cat["map"][g] = top
                    elif g:
                        cat["map"][g] = "per_record"
        if llm_category in CATEGORIES and not gf:
            cat["llm_suggestion"] = llm_category
    mapping["category"] = cat
    return mapping, {"checks": checks, "dropped": dropped, "llm": llm, "unknown_values": unknown_values}


# ── report ───────────────────────────────────────────────────────────────────

def _report_columns(mapping: Dict[str, Any], cov: Dict[str, float], records: Sequence[Dict[str, Any]],
                    fortigate: bool) -> List[Dict[str, Any]]:
    out = []
    cols = mapping.get("columns") or {}
    for c in C.MAPPABLE:
        if c == "category":
            continue
        e = cols.get(c)
        if c in ("tz", "date", "time_of_day", "dns_query", "alert_entities"):
            if not e:
                continue
            n = len(records) or 1
            share = sum(any(to_text(r.get(f)) is not None for f in e["fields"]) for r in records) / n
            out.append({"column": c, "fields": e["fields"], "method": e["method"], "coverage": round(share, 4)})
            continue
        v = cov.get(c, 0.0)
        if e:
            method = e["method"]
            fields = e["fields"]
            if c == "ts" and mapping.get("time", {}).get("date_field"):
                t = mapping["time"]
                fields = [t["date_field"], t["time_field"]] + ([t["tz_field"]] if t.get("tz_field") else [])
        elif c == "ts" and fortigate:
            method, fields = "fortigate", ["date", "time", "tz", "eventtime"]
        elif v > 0:
            method, fields = "derived", []
        else:
            method, fields = "unmapped", []
        out.append({"column": c, "fields": fields, "method": method, "coverage": v})
    return out


def build_report(path: Path, plain: Path, det: F.Detected, mapping: Dict[str, Any], table: pa.Table,
                 records: Sequence[Dict[str, Any]], fields: Sequence[str], sample_info: Dict[str, Any],
                 build: Dict[str, Any], source: str, rule_dirs: Sequence[Path]) -> Dict[str, Any]:
    fortigate = mapping["format"] == "fortigate"
    cov = _coverage(table)
    cats = Counter(table["category"].to_pylist()) if "category" in table.column_names else \
        Counter(row_categories({c: table[c].combine_chunks().cast(pa.string()) for c in table.column_names
                                if c in C.OUTPUT_COLUMNS}, table.num_rows).to_pylist())
    mapped = [c for c, e in (mapping.get("columns") or {}).items() if e.get("fields")]
    if mapping.get("time") or fortigate:
        mapped.append("ts")
    avail = available_columns(mapped, mapping.get("derive") or [], cov)
    rules = rule_report(rule_requirements(rule_dirs), avail)
    used = set()
    for e in (mapping.get("columns") or {}).values():
        used.update(e.get("fields") or [])
    for k in ("field", "tz_field", "date_field", "time_field"):
        if (mapping.get("time") or {}).get(k):
            used.add(mapping["time"][k])
    groups = []
    gf = (mapping.get("category") or {}).get("field")
    if gf and records:
        cnt = Counter(to_text(r.get(gf)) for r in records)
        for g, k in cnt.most_common(MAX_GROUPS):
            groups.append({"value": g, "records": k, "category": (mapping["category"].get("map") or {}).get(g, "per_record")})
    elif fortigate and table.num_rows:
        cnt = Counter(zip(table["log_type"].to_pylist(), table["log_subtype"].to_pylist()))
        for (a, b), k in cnt.most_common(MAX_GROUPS):
            groups.append({"value": f"{a}/{b}", "records": k})
        gf = "type/subtype"
    checks = []
    for c, per in (build.get("checks") or {}).items():
        for f, r in per.items():
            if r.get("rule"):
                checks.append({"column": c, "field": f, "rule": r["rule"], "ok": r["ok"], "share": r["share"],
                               "n": r["n"], **({"format": r["format"]} if r.get("format") else {}),
                               **({"scale": r["scale"]} if r.get("scale") else {})})
    t = mapping.get("time") or {}
    return {
        "input": str(path.resolve()), "plain_input": str(plain.resolve()) if plain != path else None,
        "bytes": path.stat().st_size, "format": det.label if not fortigate or det.format == "fortigate" else det.label,
        "format_detail": {"format": det.format, "delimiter": det.delimiter, "payload": det.payload,
                          "compressed": det.compressed, "multiline": mapping.get("multiline"),
                          "expand": mapping.get("expand")},
        "parser": "fortigate" if fortigate else "generic",
        "fingerprint": mapping.get("fingerprint"), "schema_source": source,
        "sample": sample_info,
        "time": {**t, "coverage": cov.get("ts", 0.0)},
        "categories": dict(cats.most_common()), "group_field": gf, "groups": groups,
        "columns": _report_columns(mapping, cov, records, fortigate),
        "validation": {"checks": checks, "dropped": build.get("dropped") or [],
                       "unknown_values": build.get("unknown_values") or {}},
        "llm": build.get("llm") or {"used": False, "reason": "reused mapping" if source == "reused" else None},
        "rules": rules,
        "unmapped_fields": [f for f in fields if f not in used][:200],
    }


# ── entry point ──────────────────────────────────────────────────────────────

def _dump_yaml(path: Path, doc: Dict[str, Any], header: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120, default_flow_style=None)
    path.write_text(header + body, encoding="utf-8")


HEADER = ("# killchain schema mapping (python -m killchain schema). Edit freely: the generic parser applies it as-is.\n"
          "# columns: canonical column -> source fields (first non-empty value wins); value_maps: raw -> canonical\n"
          "# (the defaults in config/schema_synonyms.yaml apply too); docs/schema.md explains every key.\n")


def prepare(input: Union[str, Path], run_dir: Union[str, Path], no_llm: bool = False, force: bool = False, *,
            schemas_dir: Union[str, Path] = SCHEMAS_DIR, synonyms_path: Union[str, Path] = SYNONYMS_YAML,
            rule_dirs: Sequence[Path] = RULE_DIRS, llm_client: Any = None, llm_cache: Union[str, Path] = CACHE_DIR,
            sample_n: int = SAMPLE_N, assume_tz: str = "+00:00", write: bool = True
            ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """Detect, sample and map one input file. Returns (format label, mapping, report).

    llm_client: an object with .chat(messages, max_tokens=, json_mode=) -> obj with .content (for tests);
    when None, the LLMClient from .env is used unless no_llm is set or no key is configured.
    """
    t0 = time.perf_counter()
    path = Path(input)
    if not path.is_file():
        raise SchemaError(f"not a file: {path}")
    run = Path(run_dir)
    plain, comp = plain_input(path)
    det = F.detect_file(plain)
    det.compressed = comp
    syn = load_synonyms(Path(synonyms_path))

    if det.format in ("fortigate", "unknown"):
        mapping = fortigate_mapping(det.format)
        table = _fortigate_sample(plain, sample_n)
        info = {"records": table.num_rows, "rejected": {}}
        report = build_report(path, plain, det, mapping, table, [], [], info, {"llm": {"used": False,
                              "reason": "FortiGate input: the existing parser maps every field"}}, "fortigate", rule_dirs)
    else:
        line_fmt = det.format in F.LINE_FORMATS
        dec = F.Decoder(det.format if line_fmt else "ndjson", syn.wrappers, syn.message_patterns)
        sample, rejected = F.sample_records(plain, det, sample_n, dec if line_fmt else None)
        if not line_fmt:
            sample = [(dec.finish(r), ln, off) for r, ln, off in sample]
        records = [r for r, _, _ in sample]
        if not records:
            raise SchemaError(f"{path}: detected {det.label} but could not read any record ({rejected or 'empty'})")
        fields = _field_order(records)
        expand = _detect_expand(records, fields)
        if expand:
            dx = F.Decoder("ndjson", (), syn.message_patterns, tuple(expand))
            records = [dx.finish(dict(r)) for r in records]
            fields = _field_order(records)
        multiline = det.format == "csv" and _multiline_csv(plain)
        fp = fingerprint(det, fields)
        stored = Path(schemas_dir) / f"{fp}.yaml"
        size = plain.stat().st_size
        mid = F.mid_offset(plain) if size > 4 * F.HEAD_BYTES else None
        info = {"records": len(records), "from_start": sum(1 for _, _, off in sample if mid is None or off < mid),
                "from_middle": sum(1 for _, _, off in sample if mid is not None and off >= mid),
                "rejected": rejected}
        if stored.exists() and not force:
            mapping = yaml.safe_load(stored.read_text(encoding="utf-8"))
            source = f"reused {stored.relative_to(ROOT) if stored.is_relative_to(ROOT) else stored}"
            build = {"llm": {"used": False, "reason": "mapping reused from " + str(stored.name)}}
        else:
            client, reason = (llm_client, None) if llm_client is not None else client_or_reason(no_llm)
            if no_llm:
                client, reason = None, "--no-llm"
            mapping, build = build_mapping(det, records, fields, syn, fp=fp, assume_tz=assume_tz, expand=expand,
                                           multiline=multiline, llm_client=client, llm_reason=reason,
                                           llm_cache=Path(llm_cache))
            source = "new"
        mapper = Mapper(mapping, syn)
        get = records_getter(records, mapper.needed_fields())
        n = len(records)
        table, _ = mapper.table(get, n, plain.name, [ln for _, ln, _ in sample], [off for _, _, off in sample],
                                [0] * n, None, None, None)
        report = build_report(path, plain, det, mapping, table, records, fields, info, build, source, rule_dirs)
        if write and source == "new":
            _dump_yaml(stored, mapping, HEADER)
    report["secs"] = round(time.perf_counter() - t0, 2)
    if write:
        run.mkdir(parents=True, exist_ok=True)
        _dump_yaml(run / "schema.yaml", mapping, HEADER)
        (run / "schema_report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False, default=str),
                                               encoding="utf-8")
    return report["format"], mapping, report


def load_mapping(path: Union[str, Path]) -> Dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
