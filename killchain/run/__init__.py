"""python -m killchain run: the whole pipeline on one log file in one command (docs/build-plan.md P13).

Stage order: parse -> prepare -> detect -> correlate -> chain -> reach -> score -> report -> enrich ->
narrate -> bundle. Each stage runs as its own process; the run records per-stage wall time, peak memory,
counts and status under the `pipeline` key of <run>/run_summary.json and in <run>/pipeline.json.
"""
