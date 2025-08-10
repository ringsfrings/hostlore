# 🛰 NetScanner - Network Inventory Tool (Dockerized)

NetScanner is a **Flask-based LAN scanning and inventory tool** that detects network hosts, services, and websites, stores results in **PostgreSQL**, and sends **Telegram alerts** for website status changes.

It uses:
- **Nmap** (host discovery & service detection)
- **SNMP** (CPU, RAM, system info when available)
- **HTTP parsing** (web titles & banners)
- **Telegram Bot API** (alerts)
- **PostgreSQL** (data storage)
- **Docker Compose** (deployment)

---

## 📦 Features
- Passive LAN scanning without SSH or agents
- OS & hostname detection (multi-method: SNMP, NetBIOS, UPnP, HTTP)
- Website UP/DOWN alerts via Telegram
- Encrypted secret storage (Fernet)
- Web dashboard for viewing scan results
- Fully Dockerized (no manual dependency installation)

---

## 🚀 Quick Start (Local Deployment)

### 1️⃣ Clone this repository
```bash
git clone https://github.com/yourname/network-inventory-tool-docker.git
cd network-inventory-tool-docker
```

### 2️⃣ Prepare secrets
Before running the containers, **you must create your own database password** (this is required).  
Create the secrets folder and the password file:
```bash
mkdir -p secrets
echo "your-db-password" > secrets/db_password.txt
```


### 3️⃣ Update environment variables
Open `docker-compose.yml` and update these values to match your own database settings:
```yaml
DB_USER: your_db_user
DB_NAME: your_db_name
DB_HOST: db           # Or your own database host
DB_PORT: 5432
```
The database password is read securely from `/run/secrets/db_password` (mapped from `secrets/db_password.txt`).

If you want to change the default PostgreSQL database container user and name, also update in the `db` service:
```yaml
POSTGRES_USER: your_db_user
POSTGRES_DB: your_db_name
```

---

### 4️⃣ Start with Docker Compose
```bash
docker compose up -d --build
```

---

### 5️⃣ Open the app
Go to:
```
http://localhost:8000
```
On first run, you’ll see the **Setup Page**. Enter:
- **IP Range** (e.g. `192.168.1.0/24`)
- **Telegram Bot Token**
- **Telegram Chat ID**
- **DB Password** (pre-filled if using `DB_PASSWORD_FILE` secret)

Secrets are encrypted in `/app/config/secrets.enc`.

---

## ⚙ Configuration

### Database connection
By default, the `docker-compose.yml` uses:
```yaml
environment:
  DB_HOST: db
  DB_PORT: 5432
  DB_USER: netadmin
  DB_NAME: network_inventory
  DB_PASSWORD_FILE: /run/secrets/db_password
```

If you want to use **your own database**:
1. Change `DB_HOST`, `DB_USER`, `DB_NAME` in both the `app` and `db` services.
2. Provide the password via `secrets/db_password.txt`.

---

### Telegram alerts
1. Create a Telegram bot: [@BotFather](https://t.me/BotFather)
2. Get your **Bot Token** and **Chat ID**
3. Enter them in the setup page or update via `/reset` route.

---

## 🔄 Resetting Secrets
To change database credentials, IP range, or Telegram settings:
- Visit: `http://localhost:8000/reset`
- Enter new details; they overwrite the encrypted secrets file.

---

## 📂 Project Structure
```
network-inventory-tool-docker/
├── app/                 # Flask app code (routes, scanner, utils)
├── db/                  # SQLAlchemy models, init.sql
├── secrets/             # Local folder for DB password secret
├── config/              # Encrypted config & Fernet key
├── docker-compose.yml   # Multi-container setup
├── Dockerfile           # App container build
├── entrypoint.sh        # Startup script
├── requirements.txt     # Python dependencies
└── run.py               # App entrypoint for Gunicorn
```

---

## 🛠 Development Notes
- Runs via **Gunicorn** inside Docker
- Requires `nmap`, `nmblookup`, and other network tools (installed in Dockerfile)
- Encrypted secrets stored at `/app/config/secrets.enc`
- PostgreSQL container persists data in `pgdata` volume

---

## 🔒 Security Recommendations
- Never commit `secrets/` folder to GitHub
- Use **private Docker Hub** repo if you don’t want your `.py` code accessible
- For public images, you can strip `.py` files after compiling to `.pyc`:
```dockerfile
RUN python -m compileall -q /app && find /app -name "*.py" -delete
```