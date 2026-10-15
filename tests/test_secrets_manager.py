"""Tests for the Fernet-backed secret store."""
import os
import stat


def test_encrypt_decrypt_roundtrip(isolated_fs):
    from app.secrets_manager import decrypt_secrets, encrypt_secrets
    data = {"app": {"ip_range": "10.0.0.0/24"},
            "telegram": {"token": "bot-token", "chat_id": "42"}}
    encrypt_secrets(data)
    assert decrypt_secrets() == data


def test_secret_key_written_with_0600_perms(isolated_fs):
    from app.secrets_manager import KEY_FILE, generate_key
    generate_key()
    mode = stat.S_IMODE(os.stat(KEY_FILE).st_mode)
    assert mode == 0o600, f"secret.key must be 0600, got {oct(mode)}"


def test_encrypted_blob_also_0600(isolated_fs):
    from app.secrets_manager import SECRETS_FILE, encrypt_secrets
    encrypt_secrets({"app": {}})
    mode = stat.S_IMODE(os.stat(SECRETS_FILE).st_mode)
    assert mode == 0o600


def test_decrypt_returns_empty_when_no_file(isolated_fs):
    from app.secrets_manager import decrypt_secrets
    assert decrypt_secrets() == {}


def test_decrypt_returns_empty_on_corrupt_blob(isolated_fs):
    from app.secrets_manager import SECRETS_FILE, decrypt_secrets, generate_key
    generate_key()
    with open(SECRETS_FILE, "wb") as f:
        f.write(b"not-a-valid-fernet-token")
    # Should not raise — return empty dict + log warning.
    assert decrypt_secrets() == {}


def test_generate_key_creates_parent_dir(monkeypatch, tmp_path):
    """Regression: earlier code crashed if config/ didn't exist."""
    monkeypatch.chdir(tmp_path)
    # No config/ dir this time.
    from app.secrets_manager import KEY_FILE, generate_key
    generate_key()
    assert os.path.exists(KEY_FILE)
