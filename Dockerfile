# Dockerfile
FROM python:3.10-slim

# System packages for runtime:
# - nmap, samba-common-bin (nmblookup)
# - netcat-openbsd + iputils-ping (nice to have for network checks)
# - curl, ca-certificates (Telegram HTTPS)
# - build-essential, libpq-dev (if psycopg2 is from source)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap samba-common-bin netcat-openbsd iputils-ping \
    curl ca-certificates \
    build-essential libpq-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY app ./app
COPY db ./db
COPY secrets ./secrets
COPY run.py  entrypoint.sh _probe.py README.md ./

# Ensure runtime folders exist (and keep permissions friendly)
RUN mkdir -p /app/config /app/logs && chmod +x /app/entrypoint.sh

# Default envs (override in compose)
ENV DB_HOST=db \
    DB_PORT=5432 \
    DB_USER=netadmin \
    DB_NAME=network_inventory \
    PYTHONUNBUFFERED=1 \
    FLASK_SECRET_KEY=change-me-in-prod

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
