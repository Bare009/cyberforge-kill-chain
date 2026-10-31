"""The template report and the report CLI (docs/build-plan.md P10, B-2)."""

from __future__ import annotations

import json
import re

from killchain import contracts as C
from killchain.graph import chain as ch
from killchain.report import template as T
from killchain.report.cli import main as report_main
from killchain.score.cli import main as score_main
from test_chain import al
from test_score import ATTACKER, NEXT, PORTAL, bundle_bytes, chain_a, make_inc, rd, reach_row, scored, weak, \
    write_bundle

HEADINGS = ["## Summary", "## Risk", "## Attack chain", "## Gaps", "## Reach next", "## Entities",
            "## Threat intel", "## Evidence", "## Recommended actions"]


def rich():
    """Chain A plus a long ongoing beacon, a supporting anomaly, a gap and a reach list of 7 hosts."""
    xs = chain_a() + [al("b1", "R11-beaconing", 20, minutes=600, tactic="command-and-control", src_ip=ATTACKER,
                         dst_ip=PORTAL),
                      al("x1", "A09-first-seen", 17, tactic="initial-access", layer="anomaly", src_ip=ATTACKER,
                         dst_ip=PORTAL)]
    rows = [reach_row(f"10.10.20.{30 + i}", "inferred") for i in range(7)]
    nxt = {**NEXT, "reachable": rows, "sentence": "Seven servers are the likely next targets (inferred).",
           "likely_tactics": ["impact"]}
    return scored(make_inc(xs, nxt=nxt))


def test_actions_cover_every_tactic():
    assert set(T.ACTIONS) == set(C.TACTICS)


def test_sections_in_order_once():
    md = T.render(rich())
    pos = [md.index(h + "\n") for h in HEADINGS]
    assert pos == sorted(pos)
    assert all(md.count(h + "\n") == 1 for h in HEADINGS)
    assert md.rstrip().endswith(T.FOOTER)


def test_summary_sentence():
    inc = rich()
    s = T.summary(inc)
    assert "\n" not in s and s.endswith(".")
    assert s.startswith(f"{ATTACKER} went from Discovery to Exfiltration against portal ({PORTAL}) in 4 steps")
    assert f"between {inc['ts_start_ist']} and {inc['ts_end_ist']} IST" in s
    assert f"risk {inc['risk_score']:.1f} of 100 ({inc['risk_band']})" in s
    one = scored(make_inc(weak()))
    assert T.summary(one).startswith("45.74.28.9 showed Discovery activity against 10.10.10.50 in 1 step between")


def test_chain_lines_and_supporting():
    inc = rich()
    md = T.render(inc)
    for s in inc["chain"]:
        line = next(x for x in md.splitlines() if x.startswith(f"{s['n']}. **"))
        assert s["ts_start_ist"] in line and f"{s['event_count']:,} events" in line
        assert ("Still running when later steps began." in line) == s["ongoing"]
    assert any(s["ongoing"] for s in inc["chain"])
    n_sup = sum(len(s["supporting"]) for s in inc["chain"])
    assert n_sup == 1 and md.count("   - Supporting anomaly (during this step): ") == n_sup


def test_gaps_reach_entities():
    inc = rich()
    md = T.render(inc)
    assert inc["gaps"] and all(f"- {g}\n" in md for g in inc["gaps"])
    assert "None: every tactic" not in md
    assert T.render(scored(make_inc(weak()))).count("None: every tactic between the first and the last step") == 1
    reach = md.split("## Reach next\n")[1].split("## Entities")[0]
    assert inc["next"]["sentence"] in reach
    assert sum(ln.startswith("- 10.10.20.") for ln in reach.splitlines()) == 5
    assert "Likely next tactics (heuristic): Impact." in reach
    ents = md.split("## Entities\n")[1].split("## Threat intel")[0]
    for label in ("- IPs: ", "- Hosts: none", "- Accounts: none", "- Domains: none"):
        assert label in ents
    assert f"{ATTACKER}" in ents and PORTAL in ents


def test_threat_intel_section():
    inc = rich()
    assert T.NO_TI_FILE in T.render(inc)
    doc = {"offline": True, "entities": {ATTACKER: {"verdict": "suspicious", "reputation": 0.4,
                                                    "flags": ["OTX: 2 pulses"], "incidents": [9]},
                                         "8.8.8.8": {"verdict": "known-malicious", "reputation": 0.9}}}
    md = T.render(inc, doc)
    assert f"- {ATTACKER}: suspicious, reputation 0.40; OTX: 2 pulses" in md
    assert "8.8.8.8" not in md
    assert "No entity of this incident was looked up." in T.render(inc, {"entities": {}})


def test_evidence_and_actions():
    inc = rich()
    md = T.render(inc)
    ev = md.split("## Evidence\n")[1].split("## Recommended actions")[0]
    for s in inc["chain"]:
        assert f"**Step {s['n']}** ({s['line_total']:,} lines):" in ev
    rows = [ln for ln in ev.splitlines() if ln.startswith("- ")]
    assert len(rows) == sum(min(len(s["line_sample"]), T.EVIDENCE_LINES) for s in inc["chain"])
    assert all(re.search(r" line \d+ \(byte \d+\), \d{4}-\d\d-\d\d \d\d:\d\d:\d\d IST$", r) for r in rows)
    acts = [ln for ln in md.split("## Recommended actions\n")[1].splitlines() if ln.startswith("- **")]
    order = list(dict.fromkeys(s["tactic"] for s in inc["chain"]))
    assert [a.split("**")[1] for a in acts] == [ch.tactic_name(t) for t in order]
    assert f"Block {ATTACKER} and check whether any probed service on {PORTAL} answered." in acts[0]
    assert "{" not in "\n".join(acts)


def test_deterministic_and_only_known_ips():
    inc = rich()
    md = T.render(inc)
    assert md == T.render(inc)
    known = {v for v in (inc["entities"]["ips"] + [n["id"] for n in inc["graph"]["nodes"]]
                         + [r["host"] for r in inc["next"]["reachable"]] + [v["from"] for r in inc["next"]["reachable"]
                                                                           for v in r["via"]])}
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", md):
        assert ip in known, ip


def test_report_for():
    r = T.report_for(rich())
    assert r["source"] == "template" and r["triage"] is None and r["markdown"].startswith("## Summary")


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_cli_writes_reports(tmp_path, capsys):
    run = write_bundle(tmp_path / "r")
    assert score_main(["--run", str(run)]) == 0
    assert report_main(["--run", str(run)]) == 0
    index, alerts = rd(run / "index.json"), rd(run / "alerts.json")
    for n in (1, 2):
        inc = rd(run / "incidents" / f"{n}.json")
        assert inc["report"]["source"] == "template" and inc["report_source"] == "template"
        assert inc["report"]["triage"] is None and inc["report"]["markdown"].startswith("## Summary")
        assert C.validate_bundle(inc, index, alerts) == []
    st = rd(run / "report" / "_stats.json")
    assert st["stage"] == "report" and st["incidents"] == 2 and st["markdown_chars"] > 0
    before = bundle_bytes(run)
    assert report_main(["--run", str(run)]) == 0
    assert bundle_bytes(run) == before
    capsys.readouterr()
    assert report_main(["--run", str(run), "1"]) == 0
    assert capsys.readouterr().out.startswith("## Summary")


def test_cli_needs_score(tmp_path, capsys):
    run = write_bundle(tmp_path / "r")
    before = bundle_bytes(run)
    assert report_main(["--run", str(run)]) == 1
    assert "score" in capsys.readouterr().err
    assert bundle_bytes(run) == before and not (run / "report").exists()
