import logging
import os

import yaml
from cryptography.fernet import Fernet

LOG = logging.getLogger("secrets")

KEY_FILE = "config/secret.key"
SECRETS_FILE = "config/secrets.enc"


def _ensure_parent(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def generate_key() -> None:
    _ensure_parent(KEY_FILE)
    key = Fernet.generate_key()
    # 0600 — only the app user should ever read the Fernet key.
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)


def load_key() -> bytes:
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()


def encrypt_secrets(data: dict) -> None:
    _ensure_parent(SECRETS_FILE)
    key = load_key()
    f = Fernet(key)
    raw = yaml.dump(data).encode()
    encrypted = f.encrypt(raw)
    fd = os.open(SECRETS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f_enc:
        f_enc.write(encrypted)


def decrypt_secrets() -> dict:
    if not os.path.exists(SECRETS_FILE):
        return {}
    try:
        key = load_key()
        f = Fernet(key)
        with open(SECRETS_FILE, "rb") as f_enc:
            decrypted = f.decrypt(f_enc.read())
        return yaml.safe_load(decrypted) or {}
    except Exception as e:
        LOG.warning("failed to decrypt %s: %s", SECRETS_FILE, e)
        return {}
