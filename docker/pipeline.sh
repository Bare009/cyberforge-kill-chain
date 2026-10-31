#!/bin/sh
# Every pipeline stage in order, for one log file (used by `docker compose run pipeline-all`).
#   docker/pipeline.sh <log file name in /app/logs> [run name]
# Writes data/parsed/<run> and data/runs/<run>; the api service picks the new bundle up on its own
# when it serves that run. Replace with `python -m killchain run` once P13 adds it.
set -eu

LOG="${1:?usage: pipeline.sh <log file in /app/logs> [run name]}"
RUN="${2:-$(basename "$LOG" .log)}"
IN="/app/logs/$(basename "$LOG")"
PARSED="data/parsed/$RUN"
OUT="data/runs/$RUN"
WORKERS="${PARSE_WORKERS:-4}"

[ -f "$IN" ] || { echo "pipeline: $IN not found (put the log in ./logs, or set LOGS_DIR)" >&2; exit 2; }
echo "pipeline: $IN -> $OUT (parse workers: $WORKERS)"

step() { echo; echo "== $*"; "$@"; }
step python -m killchain parse "$IN" --out "$PARSED" --workers "$WORKERS" --overwrite
step python -m killchain db --parsed "$PARSED" --run "$OUT" --prepare
step python -m killchain detect --run "$OUT" --parsed "$PARSED"
step python -m killchain correlate --run "$OUT"
step python -m killchain chain --run "$OUT"
step python -m killchain reach --run "$OUT"
if [ "${TI_OFFLINE:-}" = "1" ]; then
  step python -m killchain.enrich --run "$OUT" --offline
else
  step python -m killchain.enrich --run "$OUT"
fi
step python -m killchain score --run "$OUT"
step python -m killchain report --run "$OUT"
if [ "${LLM_ENABLED:-false}" = "true" ]; then
  step python -m killchain.agents narrate --run "$OUT"
fi
step python -m killchain.bundle --run "$OUT" --parsed "$PARSED"
echo; echo "pipeline: done. Serve it with KILLCHAIN_RUN=$RUN docker compose up"
