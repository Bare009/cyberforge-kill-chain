# KillChain Python image: one Dockerfile, two targets (docs/build-plan.md P14).
#   target pipeline: runs the stages (python -m killchain ...); used by the pipeline and live services
#   target api:      serves a run bundle with FastAPI on port 8000
# Build from the repo root:  docker compose build   (or docker build -f docker/Dockerfile --target api .)

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
# Code, rules and config; data/ (logs, runs, caches) is mounted at run time.
COPY killchain ./killchain
COPY config ./config
COPY rules ./rules
COPY eval ./eval
COPY examples ./examples
COPY tools ./tools
COPY docker/pipeline.sh ./docker/pipeline.sh
RUN sed -i 's/\r$//' docker/pipeline.sh && chmod +x docker/pipeline.sh \
    && useradd --create-home --uid 1000 killchain \
    && mkdir -p data/runs data/parsed data/cache data/raw logs \
    && chown -R killchain:killchain /app
USER killchain
ENV KILLCHAIN_DATA_DIR=/app/data \
    KILLCHAIN_RAW_DIR=/app/logs

FROM base AS pipeline
ENTRYPOINT ["python", "-m", "killchain"]
CMD ["--help"]

FROM base AS api
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4); sys.exit(0)"
ENTRYPOINT ["python", "-m", "killchain.api", "--host", "0.0.0.0", "--port", "8000"]
CMD []
