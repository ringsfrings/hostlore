# 🛰 Hostlore — the story of every host on your network

[![CI](https://github.com/ringsfrings/hostlore/actions/workflows/ci.yml/badge.svg)](https://github.com/ringsfrings/hostlore/actions/workflows/ci.yml)

Hostlore is an **agentless LAN inventory tool**: it discovers hosts, open services and websites with **Nmap / SNMP / NetBIOS / HTTP**, stores the inventory in **PostgreSQL**, **tells you what changed** since the last scan (new device, device offline, port opened/closed, website down) in one Telegram digest, and exposes **Prometheus metrics** with a ready-made **Grafana dashboard**.

```
             ┌──────────────── docker compose ────────────────┐
 browser ──► │  app (Flask + Gunicorn, nmap)  ──►  PostgreSQL │
             │      │  ▲                                       │
             │      │  └── Redis (scan state, scheduler lock,  │
             │      │            shared rate limits)           │
             │      └──► /metrics ◄── Prometheus ──► Grafana   │  (observability overlay)
             └──────┼─────────────────────────────────────────┘
                    └──► Telegram Bot API (one change digest per scan)
```

---

## 📦 Features
- Agentless scanning — no SSH, no agents on the targets
- OS & hostname detection (SNMP, NetBIOS, UPnP, HTTP banners, SMB fallback)
- **Change detection**: 🆕 new device · 🔻 went offline · 🔁 back online · 🔓 port opened · 🔒 port closed · 🌐 website up/down · 🏷️ title changed
- **One digest per scan**, not one message per host; the first scan is a silent **baseline** (one summary)
- **No false alarms from timeouts**: a host whose port scan times out keeps its previous state instead of being reported as "all ports closed"
- Background scans with live status and cancel; optional **scheduled scans**
- **Exactly-one scheduler** across Gunicorn workers (Redis `SET NX` lock with TTL — if the worker dies, another takes over)
- Encrypted secret storage (Fernet), DB password via **Docker secret**
- Optional **HTTP basic auth** (bcrypt) and **rate-limited** reset page
- `/health` (app, DB, setup state) and `/metrics` (Prometheus)
- Prometheus metrics aggregated across all Gunicorn workers (multiprocess mode)
- CI: lint (ruff) → unit tests → Docker smoke test → **e2e lab scan** → Trivy image scan

---

## 🚀 Quick start

```bash
git clone https://github.com/ringsfrings/hostlore.git
cd hostlore

# 1. config + DB password (both are git-ignored)
cp .env.example .env
sed -i.bak "s/^FLASK_SECRET_KEY=.*/FLASK_SECRET_KEY=$(openssl rand -hex 32)/" .env && rm .env.bak
mkdir -p secrets && openssl rand -hex 24 > secrets/db_password.txt && chmod 600 secrets/db_password.txt

# 2. start
docker compose up -d --build
```

Open **http://localhost:8000**. On first run the **Setup page** asks for:
- **IP range** to scan (e.g. `192.168.1.0/24`)
- **Telegram bot token + chat ID** (optional — create a bot with [@BotFather](https://t.me/BotFather))

The DB password comes from the Docker secret, so it is not asked for. Settings are encrypted into `config/secrets.enc`; change them later at `/reset` (rate-limited).

### With Prometheus + Grafana
```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d
```
- Grafana: http://localhost:3000 (user/password from `GF_ADMIN_*` in `.env`) — dashboard **Hostlore** is provisioned automatically
- Prometheus: http://localhost:9090

---

## ⚙ Configuration (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | — (**required**) | Flask session/CSRF key |
| `POSTGRES_USER` / `POSTGRES_DB` | `netadmin` / `network_inventory` | DB created by the `db` container, reused by the app |
| `GUNICORN_WORKERS` | `3` | Web workers |
| `GUNICORN_LOG_LEVEL` | `info` | |
| `HOSTLORE_AUTH_USER` / `HOSTLORE_AUTH_PASSWORD_HASH` | empty (auth **off**) | Enable HTTP basic auth. Hash: `python -c 'import bcrypt; print(bcrypt.hashpw(b"pass", bcrypt.gensalt()).decode())'` |
| `SCAN_SCHEDULE_INTERVAL` | empty (off) | Automatic scans, e.g. `15m`, `1h` |
| `GF_ADMIN_USER` / `GF_ADMIN_PASSWORD` | `admin` / `admin` | Grafana (overlay only) |

The DB password is **only** read from `secrets/db_password.txt` (mounted at `/run/secrets/db_password`).
`/health` and `/metrics` stay open when auth is on, so health checks and Prometheus keep working.

---

## 📈 Metrics

| Metric | Type | Meaning |
|---|---|---|
| `hostlore_scans_total{profile,result}` | counter | Finished scans by outcome |
| `hostlore_scan_duration_seconds{profile}` | histogram | Full scan duration |
| `hostlore_scan_in_progress` | gauge | 1 while a scan runs |
| `hostlore_hosts_discovered` / `hostlore_hosts_scanned` | gauge | Inventory size (last scan) |
| `hostlore_services_open` | gauge | Open services (last scan) |
| `hostlore_websites_up` / `hostlore_websites_down` | gauge | Website status |
| `hostlore_nmap_duration_seconds{op}` | histogram | Time per nmap operation |
| `hostlore_nmap_timeouts_total{op}` | counter | nmap timeouts |
| `hostlore_telegram_sends_total{result}` | counter | Telegram alert deliveries |

Check exact names with `curl -s localhost:8000/metrics | grep hostlore_`.

---

## 🧪 Testing

### Unit tests

```bash
python3.10 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest --cov=app --cov=db
```
Tests need no Postgres or Redis: the DB init is stubbed and Redis falls back to an in-memory store.

### End-to-end lab (real scans, no real network needed)
`docker-compose.lab.yml` builds a small isolated "office LAN" (`172.30.99.0/24`) with a web server, an SSH server, an SNMP agent and a **mock Telegram API**. `lab/e2e.sh` drives the whole product through it:

```bash
./lab/e2e.sh          # ~2 minutes; KEEP=0 ./lab/e2e.sh tears the lab down afterwards
```

| Step | Action | Expected |
|---|---|---|
| 1–2 | start stack, first-run setup | app healthy, settings saved |
| 3 | baseline scan | web1 site + title, ssh1 port 22, snmp1 data over SNMP; **one** baseline message; metrics counted |
| 4 | scan again, nothing changed | **no** alert |
| 5 | open port 8080 on ssh1 | digest: `opened tcp/8080` |
| 6 | stop web1 | digest: `went offline` |
| 7 | start web1 | digest: `back online` |

The lab uses its own config volume, so it never touches your real `config/`. The same script runs in CI on every push.

---

## 📂 Project structure
```
├── app/
│   ├── routes.py          # dashboard, setup/reset, results, /health, /metrics
│   ├── scanner.py         # nmap / SNMP / NetBIOS / HTTP discovery
│   ├── scan_worker.py     # background scan state (Redis or in-memory)
│   ├── scheduler.py       # interval scans, single leader via Redis lock
│   ├── auth.py            # optional HTTP basic auth
│   ├── metrics.py         # Prometheus metrics
│   ├── telegram.py        # alerts
│   └── secrets_manager.py # Fernet-encrypted settings
├── db/                    # SQLAlchemy models, init.sql
├── observability/         # Prometheus config, Grafana provisioning + dashboard
├── tests/                 # pytest suite
├── .github/workflows/ci.yml
├── docker-compose.yml               # app + Postgres + Redis
└── docker-compose.observability.yml # + Prometheus + Grafana
```

---

## 🔒 Security notes
- Turn on basic auth (or put the app behind a reverse proxy with auth/TLS) before exposing it beyond localhost.
- `.env`, `secrets/`, `config/secret.key` and `config/secrets.enc` are git-ignored — never commit them.
- Only scan networks you own or are authorised to scan.
- From the default Docker bridge network, discovery works over IP (ping/TCP); for ARP-level discovery of the host's LAN, run the app with `network_mode: host`.
