"""One in-process rebuild of the bundle from the live window, into a staging folder.

detect (on the live table) -> correlate -> chain -> reach (on the live table) -> score -> report -> bundle,
the same stage code as the batch run, called in-process: a subprocess per stage costs about 2 s each,
in-process the whole rebuild costs about 1 s on a demo-sized window. Enrich and the narrator are not run
(network, LLM); score's threat-intel part is 0 and every report is the template one.

Detect and reach each run on their own cursor: detect leaves a result open on its connection, and
reach's con.sql() would refuse it.
"""

from __future__ import annotations

import contextlib
import io
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

import polars as pl

from .table import LiveTable

STAGES = ("detect", "correlate", "chain", "reach", "score", "report", "bundle")


@dataclass
class RebuildResult:
    ok: bool
    alerts: Optional[pl.DataFrame] = None
    timings_ms: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None
    stage: Optional[str] = None
    log_tail: List[str] = field(default_factory=list)
    stopped_after_detect: bool = False


class StageError(Exception):
    pass


def alert_signatures(alerts: Optional[pl.DataFrame]) -> FrozenSet[Tuple[Any, ...]]:
    """(alert_id, event_count, ts_end, success) per alert: when the set is unchanged, nothing downstream runs."""
    if alerts is None or not alerts.height:
        return frozenset()
    return frozenset(alerts.select("alert_id", "event_count", pl.col("ts_end").cast(pl.Utf8), "success").iter_rows())


class StagePipeline:
    def __init__(self, work: Path, rules: List[Any]) -> None:
        self.work = Path(work)
        self.rules = rules
        self.logs = self.work.parent / "logs"

    def rebuild(self, table: LiveTable, proceed: Optional[Callable[[pl.DataFrame], bool]] = None) -> RebuildResult:
        """Run the stages into the work folder. proceed(alerts) is asked after detect; False stops there
        (res.ok, res.stopped_after_detect) because nothing downstream would change."""
        import psutil

        from ..bundle.build import run_bundle
        from ..correlate.cli import main as correlate_main
        from ..detect import engine
        from ..graph.cli import main as chain_main, run_reach
        from ..report.cli import main as report_main
        from ..score.cli import main as score_main

        self.work.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        W = str(self.work)
        res = RebuildResult(ok=False)
        out: Dict[str, Any] = {}

        def detect() -> int:
            t0 = time.perf_counter()
            cur = table.con.cursor()
            try:
                alerts, evidence, per_rule = engine.run_rules(cur, self.rules)
            finally:
                cur.close()
            layers = {"rule": 0, "anomaly": 0}
            if alerts.height:
                for lay, n in alerts.group_by("layer").len().iter_rows():
                    layers[lay] = n
            stats = {"stage": "detect", "wall_secs": round(time.perf_counter() - t0, 2),
                     "peak_rss_mb": round(psutil.Process().memory_info().rss / 2**20), "rules": len(self.rules),
                     "alerts": alerts.height, "evidence_lines": evidence.height, "layers": layers,
                     "per_rule": per_rule}
            bad = engine.write_outputs(self.work, alerts, evidence, stats)
            if bad:
                print("contract errors:\n  " + "\n  ".join(bad[:20]))
                return 1
            out["alerts"] = alerts
            print(f"{alerts.height} alerts from {len(self.rules)} rules")
            return 0

        def reach() -> int:
            cur = table.con.cursor()
            try:
                code, _, errors, _ = run_reach(self.work, cur, True)
            finally:
                cur.close()
            if errors:
                print("contract errors:\n  " + "\n  ".join(errors[:20]))
            return code

        def bundle() -> int:
            r = run_bundle(self.work, None)
            for w in r.warnings:
                print("warning:", w)
            if r.errors:
                print("contract errors:\n  " + "\n  ".join(r.errors[:20]))
                return 1
            return 0

        steps = {"detect": detect, "correlate": lambda: correlate_main(["--run", W]),
                 "chain": lambda: chain_main(["--run", W]), "reach": reach,
                 "score": lambda: score_main(["--run", W]), "report": lambda: report_main(["--run", W]),
                 "bundle": bundle}
        for name in STAGES:
            buf = io.StringIO()
            t0 = time.perf_counter()
            code: Any = None
            err: Optional[str] = None
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    code = steps[name]()
            except SystemExit as e:          # argparse inside a stage
                err = f"exit {e.code}"
            except Exception as e:  # noqa: BLE001 - reported in the status, retried next tick
                err = f"{type(e).__name__}: {e}"
            res.timings_ms[name] = round((time.perf_counter() - t0) * 1000)
            text = buf.getvalue()
            (self.logs / f"{name}.log").write_text(text + (f"\n{err}\n" if err else ""), encoding="utf-8")
            if err is None and code not in (0, None):
                err = f"returned {code}"
            if err is not None:
                res.stage, res.error = name, f"{name}: {err}"
                res.log_tail = (text.strip().splitlines() + [err])[-20:]
                return res
            if name == "detect":
                res.alerts = out.get("alerts")
                if proceed is not None and not proceed(res.alerts):
                    res.ok, res.stopped_after_detect = True, True
                    return res
        res.ok = True
        return res
