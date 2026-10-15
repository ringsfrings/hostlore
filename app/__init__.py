# app/__init__.py

import logging
import logging.config
import os
import secrets

from flask import Flask

# Use shared extension instances to avoid circular import issues
from app.extensions import csrf, limiter


def _configure_logging():
    """Set up rotating file + console logging.

    disable_existing_loggers=False keeps gunicorn.error / gunicorn.access alive so
    worker-boot tracebacks and access logs still surface in `docker compose logs`.
    """
    os.makedirs("logs", exist_ok=True)
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}
        },
        "handlers": {
            "rot": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": "logs/app.log",
                "maxBytes": 1_000_000,
                "backupCount": 3,
                "formatter": "default",
                "level": "INFO",
            },
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "level": "INFO",
            },
        },
        "root": {"handlers": ["rot", "console"], "level": "INFO"},
    })


def create_app():
    _configure_logging()

    app = Flask(__name__)

    # Secret key: prefer env; fallback to ephemeral (dev). For prod, set FLASK_SECRET_KEY.
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    if not os.environ.get("FLASK_SECRET_KEY"):
        app.logger.warning("FLASK_SECRET_KEY not set. Using ephemeral key for this run.")

    # ---- Security headers (CSP updated to allow inline scripts for now) ----
    @app.after_request
    def _sec_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        # NOTE: 'unsafe-inline' is enabled for scripts because dashboard/results have inline JS.
        # For stricter CSP, move JS to /static/app.js and replace with a nonce-based or hashed CSP.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return resp

    # ---- Initialize extensions ----
    csrf.init_app(app)
    limiter.init_app(app)

    # ---- Blueprints ----
    from app.routes import main
    app.register_blueprint(main)

    # ---- HTTP basic auth (opt-in via env vars — see app/auth.py) ----
    from app import auth
    app.before_request(auth.check_auth)
    auth.log_startup_status()

    # ---- DB init (best-effort; fails silently on first run before /setup) ----
    try:
        from db.models import init_db
        init_db()
    except Exception as e:
        app.logger.info("DB not initialized at startup (expected on first run): %s", e)

    # ---- Scheduled scans (opt-in via SCAN_SCHEDULE_INTERVAL) ----
    from app import scheduler
    scheduler.start_if_configured()

    return app
