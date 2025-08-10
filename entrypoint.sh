#!/bin/sh
set -e

mkdir -p /app/logs
echo "[entrypoint] NetScanner starting…"
echo "[entrypoint] Waiting for Postgres at ${DB_HOST:-db}:5432…"

# Wait for DB (optional but helpful)
until python - <<'PY'
import os, socket
host=os.environ.get("DB_HOST","db")
s=socket.socket(); s.settimeout(1.5)
try:
    s.connect((host,5432))
    print("db:ready")
except Exception:
    raise SystemExit(1)
finally:
    s.close()
PY
do
  sleep 1
done

echo "[entrypoint] Starting Gunicorn…"
exec gunicorn -w 3 -b 0.0.0.0:8000 --log-level debug run:app
