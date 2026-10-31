"""Live mode (P15): tail a growing log and update attack paths within seconds.

  tailer.py    FileTailer adapted from AI-SOC agent/soar_agent.py: appends, rotation, truncation, checkpoint
  table.py     LiveTable: the in-memory DuckDB window (last 72 h of event time) with the derived columns
  settings.py  config/live.yaml and which rules fit the window
  pipeline.py  one in-process rebuild: detect, correlate, chain, reach, score, report, bundle, into a staging folder
  publish.py   copy the staged bundle into the run folder (watched files last), diff incidents, live/ records
  engine.py    LiveEngine: the tick loop tying the above together
  cli.py       python -m killchain live
  feed.py      read live/status.json and live/events.jsonl (for the API; stdlib only)
  replay.py    cut a log slice around one attacker and append it to a file at a chosen speed
  latency.py   measure the time from a line written to its incident being visible
"""
