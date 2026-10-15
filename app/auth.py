"""
HTTP Basic authentication for the whole app.

Enabled when both env vars are set:
  HOSTLORE_AUTH_USER          e.g. "admin"
  HOSTLORE_AUTH_PASSWORD_HASH bcrypt hash — generate with:
      python -c 'import bcrypt; print(bcrypt.hashpw(b"your-pass", bcrypt.gensalt()).decode())'

If either is unset, auth is DISABLED and a loud warning is logged at startup.
This lets developers run locally without setup, but production installs will
never accidentally ship open — set both vars in .env.

Health + metrics endpoints are always exempt so Prometheus / orchestrator
probes keep working.
"""
import base64
import logging
import os
from functools import lru_cache

import bcrypt
from flask import Response, request

LOG = logging.getLogger("auth")

EXEMPT_PATHS = ("/health", "/metrics")


@lru_cache(maxsize=1)
def _configured_creds() -> tuple[str, bytes] | None:
    user = os.getenv("HOSTLORE_AUTH_USER", "").strip()
    pw_hash = os.getenv("HOSTLORE_AUTH_PASSWORD_HASH", "").strip()
    if not user or not pw_hash:
        return None
    return user, pw_hash.encode()


def is_enabled() -> bool:
    return _configured_creds() is not None


def _unauthorized() -> Response:
    return Response(
        "Authentication required.\n",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="Hostlore", charset="UTF-8"'},
    )


def _parse_basic_header(header: str) -> tuple[str, str] | None:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header.split(" ", 1)[1], validate=True).decode("utf-8")
    except Exception:
        return None
    if ":" not in raw:
        return None
    user, pw = raw.split(":", 1)
    return user, pw


def check_auth():
    """Flask before_request hook. Return a Response to short-circuit, or None to allow."""
    if not is_enabled():
        return None
    if request.path in EXEMPT_PATHS:
        return None

    creds = _configured_creds()
    assert creds is not None  # for type checkers; is_enabled() already guaranteed
    expected_user, expected_hash = creds

    parsed = _parse_basic_header(request.headers.get("Authorization", ""))
    if parsed is None:
        return _unauthorized()

    supplied_user, supplied_pw = parsed
    if supplied_user != expected_user:
        return _unauthorized()

    try:
        if not bcrypt.checkpw(supplied_pw.encode("utf-8"), expected_hash):
            return _unauthorized()
    except ValueError:
        # Malformed hash in env — treat as auth failure but log loudly so it's fixable.
        LOG.error("HOSTLORE_AUTH_PASSWORD_HASH is not a valid bcrypt hash")
        return _unauthorized()

    return None


def log_startup_status() -> None:
    if is_enabled():
        LOG.info("HTTP basic auth ENABLED (user=%s)", _configured_creds()[0])
    else:
        LOG.warning(
            "HTTP basic auth DISABLED — set HOSTLORE_AUTH_USER + "
            "HOSTLORE_AUTH_PASSWORD_HASH before exposing this instance."
        )
