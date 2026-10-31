"""SIEM connections (Settings -> SIEM Integrations), ported from AI-SOC.

Connectors are stored in <KILLCHAIN_DATA_DIR>/connectors/connectors.json.
Records arrive by webhook (webhook.py) or API pull (poller.py), or by syslog
(syslog_server.py, KILLCHAIN_SYSLOG=1), and land in <data>/ingest/: one
records.ndjson per connector, plus the raw log lines in the shared live.log
that `python -m killchain live --input data/ingest/live.log` tails.

routes.router (/settings/...) and webhook.router (/ingest/...) are mounted by
killchain/api/app.py; poller.connectors_lifespan is its lifespan.
"""
