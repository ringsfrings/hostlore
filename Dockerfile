FROM python:3.10-slim

# Runtime-only apt packages — no build tooling required because all our Python
# deps ship prebuilt wheels (psycopg2-binary, cryptography, bcrypt, etc).
#   nmap                  — the actual scanner
#   samba-common-bin      — nmblookup for Windows NetBIOS names
#   curl + ca-certificates — HEALTHCHECK + Telegram HTTPS
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap samba-common-bin \
    curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code. NOTE: secrets/ is NOT copied — mounted at runtime via Docker secrets.
COPY app ./app
COPY db ./db
COPY run.py entrypoint.sh gunicorn.conf.py _probe.py README.md ./

RUN mkdir -p /app/config /app/logs && chmod +x /app/entrypoint.sh

# Default envs — override in compose. FLASK_SECRET_KEY is intentionally NOT set here;
# the compose file enforces it via ${FLASK_SECRET_KEY:?set in .env}.
ENV DB_HOST=db \
    DB_PORT=5432 \
    DB_USER=netadmin \
    DB_NAME=network_inventory \
    GUNICORN_WORKERS=3 \
    GUNICORN_LOG_LEVEL=info \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
