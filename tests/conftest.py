import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture
def isolated_fs(monkeypatch, tmp_path):
    """
    Each test gets a fresh working directory with empty config/ + logs/.
    All file-based state (secrets, scan profile, logs) lives here.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    return tmp_path


@pytest.fixture(autouse=True)
def _reset_scan_worker_state():
    """Every test starts with a clean scan_worker Redis state (real or in-memory)."""
    from app import scan_worker
    scan_worker.reset_for_tests()
    yield
    scan_worker.reset_for_tests()


@pytest.fixture(autouse=True)
def _reset_auth_cache(monkeypatch):
    """Auth creds are lru_cached; clear them so one test's auth env can't leak into the next."""
    from app.auth import _configured_creds
    monkeypatch.delenv("HOSTLORE_AUTH_USER", raising=False)
    monkeypatch.delenv("HOSTLORE_AUTH_PASSWORD_HASH", raising=False)
    _configured_creds.cache_clear()
    yield
    _configured_creds.cache_clear()


@pytest.fixture
def app(isolated_fs, monkeypatch):
    """Fresh Flask app with DB init stubbed so no Postgres is required."""
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-key-not-real-do-not-use")
    monkeypatch.delenv("SCAN_SCHEDULE_INTERVAL", raising=False)

    # Stub init_db so create_app can succeed without a real DB.
    import db.models as models
    monkeypatch.setattr(models, "init_db", lambda force=False: None)

    from app import create_app
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()
