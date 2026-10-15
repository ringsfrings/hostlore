#!/bin/sh
set -eu

# Allow passthrough for debugging:
#   docker compose run --rm app python -c "from app import create_app; create_app()"
#   docker compose run --rm app sh
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

mkdir -p /app/logs

echo "[entrypoint] Hostlore starting…"
echo "[entrypoint] Waiting for Postgres at ${DB_HOST:-db}:${DB_PORT:-5432}…"

if ! python /app/_probe.py --wait-db --host "${DB_HOST:-db}" --port "${DB_PORT:-5432}" --timeout 60; then
    echo "[entrypoint] Postgres never became reachable — aborting." >&2
    exit 1
fi

# Shared Prometheus samples for all Gunicorn workers (see app/metrics.py).
export PROMETHEUS_MULTIPROC_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus}"
rm -rf "$PROMETHEUS_MULTIPROC_DIR" && mkdir -p "$PROMETHEUS_MULTIPROC_DIR"

WORKERS="${GUNICORN_WORKERS:-3}"
LOG_LEVEL="${GUNICORN_LOG_LEVEL:-info}"

echo "[entrypoint] Starting Gunicorn: workers=${WORKERS} log-level=${LOG_LEVEL}"
exec gunicorn \
    --config /app/gunicorn.conf.py \
    --workers "${WORKERS}" \
    --bind 0.0.0.0:8000 \
    --log-level "${LOG_LEVEL}" \
    --access-logfile - \
    --error-logfile - \
    --capture-output \
    run:app
