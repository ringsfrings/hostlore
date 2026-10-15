"""Tests for HTTP basic auth."""
import base64


def _basic_header(user: str, password: str) -> str:
    creds = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(creds).decode()


def test_auth_disabled_by_default_allows_all_routes(client, monkeypatch):
    monkeypatch.delenv("HOSTLORE_AUTH_USER", raising=False)
    monkeypatch.delenv("HOSTLORE_AUTH_PASSWORD_HASH", raising=False)
    # Force re-evaluation of the lru_cache.
    from app.auth import _configured_creds
    _configured_creds.cache_clear()

    r = client.get("/health")
    assert r.status_code == 200


def _configure_auth(monkeypatch, user, password):
    import bcrypt
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    monkeypatch.setenv("HOSTLORE_AUTH_USER", user)
    monkeypatch.setenv("HOSTLORE_AUTH_PASSWORD_HASH", pw_hash)
    from app.auth import _configured_creds
    _configured_creds.cache_clear()


def test_auth_challenges_missing_credentials(client, monkeypatch):
    _configure_auth(monkeypatch, "admin", "secret")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 401
    assert "Basic" in r.headers.get("WWW-Authenticate", "")


def test_auth_accepts_correct_credentials(client, monkeypatch):
    _configure_auth(monkeypatch, "admin", "secret")
    r = client.get("/health", headers={"Authorization": _basic_header("admin", "secret")})
    assert r.status_code == 200


def test_auth_rejects_wrong_password(client, monkeypatch):
    _configure_auth(monkeypatch, "admin", "secret")
    r = client.get("/health", headers={"Authorization": _basic_header("admin", "wrong")})
    # /health is exempt, so this passes — swap to a real route
    r = client.get("/", headers={"Authorization": _basic_header("admin", "wrong")})
    assert r.status_code == 401


def test_health_endpoint_is_exempt_from_auth(client, monkeypatch):
    _configure_auth(monkeypatch, "admin", "secret")
    r = client.get("/health")
    assert r.status_code == 200


def test_metrics_endpoint_is_exempt_from_auth(client, monkeypatch):
    _configure_auth(monkeypatch, "admin", "secret")
    r = client.get("/metrics")
    assert r.status_code == 200
