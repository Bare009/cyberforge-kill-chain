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


def load_manifest(path: Union[str, Path], sources: Dict[str, Union[str, Path]],
                  check_offsets: int = 200) -> pl.DataFrame:
    """Read a manifest. `sources` maps stream name ('firewall', 'windows') to the raw file.

    Raises TruthError when the manifest's byte offsets do not point at line
    starts of the given files, so a manifest for another tier is never scored
    against this one.
    """
    m = json.loads(Path(path).read_text(encoding="utf-8"))
    streams = {str(k): v for k, v in (m.get("streams") or {"0": "firewall", "1": "windows"}).items()}
    rows: List[Dict[str, Any]] = []
    for inc in m.get("incidents", []):
        iid = _int(inc.get("id"))
        stages = inc.get("stages") or []
        techs = _techniques(inc.get("attack", ""))
        for ln, off, st in inc.get("at") or []:
            stream = streams.get(str(st), str(st))
            step_n, tech, tactic, step_name = 1, (techs[0] if techs else "unknown"), inc.get("tactic", ""), inc.get("name")
            alt = techs[1:]
            if stages:
                cand = [s for s in stages if s.get("log") == stream and _int(s.get("first_line")) is not None
                        and _int(s["first_line"]) <= int(ln)]
                st_ = max(cand, key=lambda s: _int(s["first_line"])) if cand else stages[0]
                step_n, tech, tactic, step_name = int(st_["n"]), st_["attack"], st_.get("tactic", ""), st_.get("stage")
                alt = []
            rows.append({"incident_id": iid, "incident_name": inc.get("name"), "class": inc.get("class", ""),
                         "ordered": bool(stages), "step_n": step_n, "step_name": step_name, "technique": tech,
                         "alt": alt, "tactic": str(tactic).lower().replace(" ", "-"), "stream": stream,
                         "source": Path(sources[stream]).name if stream in sources else stream,
                         "line": int(ln), "byte_offset": int(off)})
    truth = pl.DataFrame(rows, schema=TRUTH_SCHEMA) if rows else empty_truth()
    _check_offsets(truth, sources, check_offsets)
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
