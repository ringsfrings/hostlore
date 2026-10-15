# app/config_loader.py

from app.secrets_manager import decrypt_secrets


def load_config():
    return decrypt_secrets()
