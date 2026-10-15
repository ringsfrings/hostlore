# app/utils.py
import ipaddress
import os

from app.secrets_manager import SECRETS_FILE, decrypt_secrets, encrypt_secrets

# ---------- encrypted config helpers ----------

def _load_or_default():
    cfg = decrypt_secrets() or {}
    cfg.setdefault("app", {})
    cfg.setdefault("telegram", {})
    cfg.setdefault("database", {})
    return cfg

def _get_env_password() -> str | None:
    """
    Prefer Docker/K8s style secret/env for DB password:
      - DB_PASSWORD_FILE: path to a file containing the password
      - DB_PASSWORD: value directly
    Returns str or None if not set.
    """
    path = os.getenv("DB_PASSWORD_FILE")
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    val = os.getenv("DB_PASSWORD")
    return val.strip() if val else None


def has_env_db_password() -> bool:
    """True when the container/host provides a DB password out-of-band
    (docker secret / env var), so the UI shouldn't ask for one."""
    return _get_env_password() is not None

def _build_db_uri(db_host: str, db_port: str | None, password: str) -> str:
    # Keep your existing username/db name
    user = os.getenv("DB_USER", "netadmin")
    name = os.getenv("DB_NAME", "network_inventory")
    port = db_port or os.getenv("DB_PORT", "5432")
    return f"postgresql+psycopg2://{user}:{password}@{db_host}:{port}/{name}"

def save_form_data(ip_range, token, chat_id, db_password_from_form):
    """
    Initial setup/reset: write all secrets.
    If DB_PASSWORD(_FILE) is provided in env/secrets, use that instead of the form value.
    """
    # Determine DB host/port from env (compose) so we don't hardcode
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = os.environ.get("DB_PORT")  # may be None

    # Prefer secure env/secret over form input
    env_pw = _get_env_password()
    db_password = env_pw if env_pw else (db_password_from_form or "")

    cfg = {
        "app": {"ip_range": ip_range},
        "telegram": {"token": token, "chat_id": chat_id},
        "database": {
            "uri": _build_db_uri(db_host, db_port, db_password)
        },
    }
    os.makedirs(os.path.dirname(SECRETS_FILE), exist_ok=True)
    encrypt_secrets(cfg)
    print(f"[setup] wrote encrypted secrets → {SECRETS_FILE}")

def update_ip_range(ip_range: str):
    """Dashboard path: update only the CIDR while keeping other secrets intact."""
    try:
        _ = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        raise ValueError("Invalid CIDR format.") from e

    cfg = _load_or_default()
    cfg["app"]["ip_range"] = ip_range
    encrypt_secrets(cfg)
    print(f"[secrets] ip_range updated → {ip_range}")

def get_current_settings():
    """Helper for templates & status panels."""
    return _load_or_default()

# ---------- scan profile persistence ----------

PROFILE_FILE = "config/scan_profile.txt"
VALID_PROFILES = {"quick", "balanced", "deep"}

def get_scan_profile() -> str:
    """
    Returns the last selected scan profile (quick|balanced|deep).
    Defaults to 'quick' if the file is missing/invalid.
    """
    try:
        with open(PROFILE_FILE, encoding="utf-8") as f:
            p = (f.read() or "").strip().lower()
            return p if p in VALID_PROFILES else "quick"
    except Exception:
        return "quick"

def set_scan_profile(profile: str) -> None:
    """
    Persists the chosen profile to disk so it survives restarts.
    """
    p = (profile or "").strip().lower()
    if p not in VALID_PROFILES:
        p = "quick"
    os.makedirs(os.path.dirname(PROFILE_FILE), exist_ok=True)
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        f.write(p)
