# app/secrets_manager.py

import os
from cryptography.fernet import Fernet
import yaml

KEY_FILE = "config/secret.key"
SECRETS_FILE = "config/secrets.enc"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_secrets(data: dict):
    key = load_key()
    f = Fernet(key)
    raw = yaml.dump(data).encode()
    encrypted = f.encrypt(raw)
    with open(SECRETS_FILE, "wb") as f_enc:
        f_enc.write(encrypted)

def decrypt_secrets():
    key = load_key()
    f = Fernet(key)
    if not os.path.exists(SECRETS_FILE):
        print("[!] secrets.enc file not found.")
        return {}
    with open(SECRETS_FILE, "rb") as f_enc:
        decrypted = f.decrypt(f_enc.read())
        return yaml.safe_load(decrypted)
