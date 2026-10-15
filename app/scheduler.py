"""
In-process scan scheduler.

Config:
  SCAN_SCHEDULE_INTERVAL   "15m", "1h", "30s"   → run every N.
                           unset / "0" / ""     → disabled (default).

Uses the Redis client from scan_worker so exactly one gunicorn worker across
the fleet runs the scheduler. SET NX with a short TTL, refreshed by the
running worker — if that worker dies, TTL expires and another one takes over.
"""
import logging
import os
import re
import threading

from app.scan_worker import _r as _redis  # reuse the connection (real Redis or in-memory fallback)

LOG = logging.getLogger("scheduler")

_SCHED_LOCK_KEY = "hostlore:scheduler:lock"
_SCHED_LOCK_TTL = 60
_SCHED_LOCK_REFRESH = 20

_stop_event = threading.Event()
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600}


def _parse_interval(spec: str) -> int:
    """'15m' → 900. '' / '0' → 0 (disabled). Raises ValueError on garbage."""
    s = (spec or "").strip().lower()
    if not s or s == "0":
        return 0
    m = re.fullmatch(r"(\d+)\s*([smh])?", s)
    if not m:
        raise ValueError(f"Invalid SCAN_SCHEDULE_INTERVAL: {spec!r}")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2) or "s"]


def _try_acquire_lock() -> bool:
    return bool(_redis.set(_SCHED_LOCK_KEY, "1", nx=True, ex=_SCHED_LOCK_TTL))


def _refresh_lock() -> None:
    while not _stop_event.is_set():
        _redis.expire(_SCHED_LOCK_KEY, _SCHED_LOCK_TTL)
        _stop_event.wait(_SCHED_LOCK_REFRESH)


def _run(interval_seconds: int) -> None:
    from app import scan_worker as worker
    from app.scanner import start_scan_background
    from app.utils import get_scan_profile

    LOG.info("scheduler active — firing every %ds", interval_seconds)
    _stop_event.wait(min(30, interval_seconds))

    while not _stop_event.is_set():
        try:
            if worker.is_running():
                LOG.info("scheduler: scan already running, skipping this tick")
            else:
                profile = get_scan_profile()
                started = worker.status()  # noqa: F841  (touch state for observability)
                started = start_scan_background({"profile": profile})
                LOG.info("scheduler: fired scan (profile=%s started=%s)", profile, started)
        except Exception as e:
            LOG.warning("scheduler tick failed: %s", e)
        _stop_event.wait(interval_seconds)

    LOG.info("scheduler stopped")


def start_if_configured() -> None:
    spec = os.getenv("SCAN_SCHEDULE_INTERVAL", "")
    try:
        seconds = _parse_interval(spec)
    except ValueError as e:
        LOG.error("%s — scheduler disabled", e)
        return

    if seconds <= 0:
        LOG.info("scheduler disabled (SCAN_SCHEDULE_INTERVAL unset)")
        return

    if not _try_acquire_lock():
        LOG.info("another worker holds the scheduler lock — skipping in this worker")
        return

    threading.Thread(target=_refresh_lock, name="hostlore-sched-lock", daemon=True).start()
    threading.Thread(target=_run, args=(seconds,), name="hostlore-scheduler", daemon=True).start()


def stop() -> None:
    _stop_event.set()
