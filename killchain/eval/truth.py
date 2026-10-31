"""Ground truth as one table: a row per planted log line.

Two sources produce the same columns:
  - `build_silver()`  from eval/silver_truth.yaml, run over a parsed run;
  - `load_manifest()` from an organisers' manifest (`at: [line, byte, stream]`).

Columns: incident_id, incident_name, class, ordered, step_n, step_name,
technique, alt (list), tactic, stream, source, line, byte_offset.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import polars as pl
import yaml

TRUTH_SCHEMA = {
    "incident_id": pl.Int64, "incident_name": pl.Utf8, "class": pl.Utf8, "ordered": pl.Boolean,
    "step_n": pl.Int64, "step_name": pl.Utf8, "technique": pl.Utf8, "alt": pl.List(pl.Utf8),
    "tactic": pl.Utf8, "stream": pl.Utf8, "source": pl.Utf8, "line": pl.Int64, "byte_offset": pl.Int64,
}


class TruthError(Exception):
    pass


def empty_truth() -> pl.DataFrame:
    return pl.DataFrame(schema=TRUTH_SCHEMA)


# ── silver truth ─────────────────────────────────────────────────────────────

def load_silver_spec(path: Union[str, Path]) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    for inc in spec["incidents"]:
        for i, s in enumerate(inc["steps"], start=1):
            s["n"] = i
            s.setdefault("alt", [])
            s.setdefault("tolerance", 0.0)
        inc.setdefault("ordered", len(inc["steps"]) > 1)
    return spec


def build_silver(con, spec: Dict[str, Any]) -> Tuple[pl.DataFrame, List[Dict[str, Any]]]:
    """Run every step's condition in one scan of `events`. Returns (truth, checks)."""
    steps = [(inc, s) for inc in spec["incidents"] for s in inc["steps"]]
    if not steps:
        return empty_truth(), []
    flags = ", ".join(f"COALESCE(({s['where']}), false) AS s{k}" for k, (_, s) in enumerate(steps))
    any_cond = " OR ".join(f"COALESCE(({s['where']}), false)" for _, s in steps)
    sql = (f"SELECT source, line, byte_offset, {flags} FROM events "
           f"WHERE ts_valid AND ({any_cond})")
    hits = con.sql(sql).pl()
    frames, checks = [], []
    for k, (inc, s) in enumerate(steps):
        part = hits.filter(pl.col(f"s{k}")).select("source", "line", "byte_offset")
        got, want = part.height, int(s["expect"])
        ok = abs(got - want) <= max(1, round(want * float(s["tolerance"]))) if s["tolerance"] else got == want
        checks.append({"incident_id": inc["id"], "incident_name": inc["name"], "step_n": s["n"],
                       "step_name": s["name"], "expect": want, "got": got, "ok": ok})
        frames.append(part.with_columns(
            pl.lit(inc["id"], pl.Int64).alias("incident_id"), pl.lit(inc["name"]).alias("incident_name"),
            pl.lit(inc.get("class", "")).alias("class"), pl.lit(bool(inc["ordered"])).alias("ordered"),
            pl.lit(s["n"], pl.Int64).alias("step_n"), pl.lit(s["name"]).alias("step_name"),
            pl.lit(s["technique"]).alias("technique"),
            pl.lit(list(s["alt"]), pl.List(pl.Utf8)).alias("alt"),
            pl.lit(s["tactic"]).alias("tactic"), pl.lit("firewall").alias("stream")))
    truth = pl.concat(frames, how="diagonal_relaxed").select(list(TRUTH_SCHEMA)).cast(TRUTH_SCHEMA)
    return truth, checks


# ── organisers' manifest ─────────────────────────────────────────────────────

def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _techniques(attack: str) -> List[str]:
    out = []
    for part in str(attack).replace("->", ",").split(","):
        p = part.strip()
        if p.startswith("T"):
            out.append(p)
    return out


def _row(inc: Dict[str, Any], stream: str, ln: int, off: Optional[int], sources: Dict[str, Union[str, Path]]
         ) -> Dict[str, Any]:
    """One truth row; a multi-stage incident gives the line the stage it falls in."""
    stages = inc.get("stages") or []
    techs = _techniques(inc.get("attack", ""))
    step_n, tech, tactic, step_name = 1, (techs[0] if techs else "unknown"), inc.get("tactic", ""), inc.get("name")
    alt = techs[1:]
    if stages:
        cand = [s for s in stages if s.get("log") == stream and _int(s.get("first_line")) is not None
                and _int(s["first_line"]) <= int(ln)]
        st_ = max(cand, key=lambda s: _int(s["first_line"])) if cand else stages[0]
        step_n, tech, tactic, step_name = int(st_["n"]), st_["attack"], st_.get("tactic", ""), st_.get("stage")
        alt = []
    return {"incident_id": _int(inc.get("id")), "incident_name": inc.get("name"), "class": inc.get("class", ""),
            "ordered": bool(stages), "step_n": step_n, "step_name": step_name, "technique": tech,
            "alt": alt, "tactic": str(tactic).lower().replace(" ", "-"), "stream": stream,
            "source": Path(sources[stream]).name if stream in sources else stream,
            "line": int(ln), "byte_offset": int(off) if off is not None else None}


def _addr_sql(col: str, value: str) -> str:
    """An address match: 115.180.0.0 means the /16, 8.42.69.0 the /24, anything else the exact address."""
    v = str(value).strip().split("/")[0]
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        if parts[2:] == ["0", "0"]:
            return f"{col} LIKE '{parts[0]}.{parts[1]}.%'"
        if parts[3] == "0":
            return f"{col} LIKE '{parts[0]}.{parts[1]}.{parts[2]}.%'"
    return f"{col} = '{v.replace(chr(39), '')}'"


SIGNATURE = ("log_type", "log_subtype", "action", "dst_port", "service", "app", "policy_id")


def resolve_range(con: Any, inc: Dict[str, Any], source: str, rng: Dict[str, Any]) -> Tuple[Optional[pl.DataFrame], str]:
    """The planted lines of an incident the manifest lists only as a line range plus addresses.

    Candidates: lines of `source` inside [first_line, last_line] between the incident's `src`
    and `peer` (either direction). When there are more candidates than the manifest's event
    count, keep the largest group sharing one traffic signature (log type and subtype, action,
    port, service, app, policy). Accepted only when the count is exactly the manifest's.
    Returns (frame of line, byte_offset; or None, and a note saying what happened).
    """
    want, lo, hi = _int(rng.get("events")), _int(rng.get("first_line")), _int(rng.get("last_line"))
    if want is None or lo is None or hi is None:
        return None, "no event count or line range"
    conds = [f"source = '{source.replace(chr(39), '')}'", f"line BETWEEN {lo} AND {hi}"]
    peer, src = inc.get("peer"), inc.get("src")
    if peer:
        conds.append(f"({_addr_sql('dst_ip', peer)} OR {_addr_sql('src_ip', peer)})")
    if src:
        conds.append(f"({_addr_sql('src_ip', src)} OR {_addr_sql('dst_ip', src)})")
    if not (peer or src):
        return None, "no src or peer to pick its lines from the range"
    where = " AND ".join(conds)
    got = con.sql(f"SELECT line, byte_offset, {', '.join(SIGNATURE)} FROM events WHERE {where}").pl()
    how = f"{got.height:,} lines in the range between {src or '*'} and {peer or '*'}"
    if got.height > want:
        top = (got.group_by(list(SIGNATURE)).agg(pl.len().alias("n")).sort("n", descending=True).head(1))
        if top.height:
            sig = top.drop("n").row(0, named=True)
            narrowed = got.join(top.drop("n"), on=list(SIGNATURE), how="semi", nulls_equal=True)
            how += f", {narrowed.height:,} with the common signature {', '.join(f'{k}={v}' for k, v in sig.items() if v is not None)}"
            got = narrowed
    if got.height != want:
        return None, f"{how}; the manifest says {want:,}, so it was not used"
    return got.select("line", "byte_offset"), how


def load_manifest(path: Union[str, Path], sources: Dict[str, Union[str, Path]],
                  check_offsets: int = 200, con: Any = None,
                  notes: Optional[List[str]] = None) -> pl.DataFrame:
    """Read a manifest. `sources` maps stream name ('firewall', 'windows') to the raw file.

    An incident without its per-line list (`at`), e.g. a large flood, is resolved from its
    line range and addresses with `con` (DuckDB over the run's events; see resolve_range).
    Without `con`, or when the count does not match exactly, it has no truth lines and a
    note says so. `notes` (optional list) collects such remarks, including truth lines in a
    stream whose raw log was not given.

    Raises TruthError when the manifest's byte offsets do not point at line
    starts of the given files, so a manifest for another tier is never scored
    against this one.
    """
    m = json.loads(Path(path).read_text(encoding="utf-8"))
    streams = {str(k): v for k, v in (m.get("streams") or {"0": "firewall", "1": "windows"}).items()}
    notes = notes if notes is not None else []
    rows: List[Dict[str, Any]] = []
    for inc in m.get("incidents", []):
        at = inc.get("at") or []
        for ln, off, st in at:
            rows.append(_row(inc, streams.get(str(st), str(st)), int(ln), int(off), sources))
        if at:
            continue
        label = f"#{inc.get('id')} {inc.get('name')}"
        for stream, rng in (inc.get("ranges") or {}).items():
            if stream not in sources:
                notes.append(f"{label}: no per-line list and no {stream} log given; not scored")
                continue
            if con is None:
                notes.append(f"{label}: no per-line list; give --run with events.duckdb to resolve its "
                             f"{stream} line range")
                continue
            got, how = resolve_range(con, inc, Path(sources[stream]).name, rng)
            if got is None:
                notes.append(f"{label}: {how}")
                continue
            notes.append(f"{label}: resolved from its line range ({how})")
            rows += [_row(inc, stream, ln, off, sources) for ln, off in got.iter_rows()]
    truth = pl.DataFrame(rows, schema=TRUTH_SCHEMA) if rows else empty_truth()
    for stream in sorted(set(truth["stream"].to_list()) - set(sources)):
        part = truth.filter(pl.col("stream") == stream)
        notes.append(f"{part.height:,} planted lines in {part['incident_id'].n_unique()} incident(s) are in the "
                     f"{stream} log, which was not given (--raw {stream}=<file>); they count as not found")
    _check_offsets(truth.filter(pl.col("byte_offset").is_not_null()), sources, check_offsets)
    return truth


def _check_offsets(truth: pl.DataFrame, sources: Dict[str, Union[str, Path]], n: int) -> None:
    for stream, path in sources.items():
        part = truth.filter(pl.col("stream") == stream)
        if part.height == 0:
            continue
        size = Path(path).stat().st_size
        sample = part.sample(min(n, part.height), seed=1)
        bad = 0
        with open(path, "rb") as f:
            for off in sample["byte_offset"]:
                if off >= size:
                    bad += 1
                    continue
                if off > 0:
                    f.seek(off - 1)
                    if f.read(1) != b"\n":
                        bad += 1
        if bad > sample.height * 0.02:
            raise TruthError(f"manifest does not belong to {Path(path).name}: {bad} of {sample.height} sampled "
                             f"byte offsets are not line starts")
