"""
Redis-backed background-job runner.

Why Redis: gunicorn spawns N worker processes. If scan state lived in Python
globals, POST /scan/start on worker A and GET /scan/status on worker B would
see different worlds — the dashboard would report "Idle" while a scan is
running in another process. Redis gives us one source of truth.

Local-only state:
  - the actual thread running the scan
  - the PIDs of nmap children (used to kill on cancel)
Only the worker that OWNS an active scan holds these. Cancel from a different
worker sets a Redis flag; a small watcher thread inside the owning worker
sees the flag and calls _kill_local_pids().
"""
import json
import logging
import os
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

import redis

LOG = logging.getLogger("worker")

_REDIS_URL = os.getenv("SCAN_STATE_REDIS_URI") or os.getenv("RATE_LIMIT_STORAGE_URI") or "redis://redis:6379/0"

_STATE_KEY = "hostlore:scan:state"
_CANCEL_KEY = "hostlore:scan:cancel"
_LOCK_KEY = "hostlore:scan:lock"           # SET NX EX for atomic start
_LOCK_TTL_SECONDS = 60                        # refreshed by the running worker
_LOCK_REFRESH_INTERVAL = 20


class _InMemoryRedis:
    """Tiny drop-in for tests / dev when Redis isn't reachable.

    Only implements the subset scan_worker actually uses. Not thread-safe against
    itself (fine — a single process); not shared across processes (that's the
    point of the real Redis).
    """
    def __init__(self):
        self._h: dict[str, dict[str, str]] = {}
        self._kv: dict[str, str] = {}

    def hset(self, key, field, value):
        self._h.setdefault(key, {})[field] = value
        return 1

    def hget(self, key, field):
        return self._h.get(key, {}).get(field)

    def hgetall(self, key):
        return dict(self._h.get(key, {}))

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self._h:
                del self._h[k]
                n += 1
            if k in self._kv:
                del self._kv[k]
                n += 1
        return n

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self._kv:
            return None
        self._kv[key] = value
        return True

    def get(self, key):
        return self._kv.get(key)

    def expire(self, key, seconds):
        return 1 if key in self._kv else 0

    def ping(self):
        return True

    def pipeline(self):
        return _InMemoryPipeline(self)


class _InMemoryPipeline:
    def __init__(self, r):
        self._r = r
        self._ops = []

    def hset(self, key, field, value):
        self._ops.append((key, field, value))
        return self

    def execute(self):
        for key, field, value in self._ops:
            self._r.hset(key, field, value)
        self._ops.clear()


def _connect_redis():
    try:
        r = redis.from_url(_REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        r.ping()
        LOG.info("scan state backed by Redis at %s", _REDIS_URL)
        return r
    except Exception as e:
        LOG.warning(
            "Redis unavailable at %s (%s) — falling back to in-memory scan state. "
            "This is fine for tests/dev but breaks multi-worker deployments.",
            _REDIS_URL, e,
        )
        return _InMemoryRedis()


_r = _connect_redis()

# Per-process locals — only meaningful in the worker that owns a running scan.
_local_pids: set[int] = set()
_local_lock = threading.Lock()

_INITIAL_STATE: dict[str, Any] = {
    "scan_id": None,
    "running": False,
    "cancelling": False,
    "current": 0,
    "total": 0,
    "message": "Idle",
    "last_error": "",
    "profile": "quick",
    "eta_seconds": None,
    "last_host": None,
    "started_at": None,
    "finished_at": None,
}


class State:
    """Facade over the Redis hash. All state writes go here."""

    def set(self, **kw: Any) -> None:
        if not kw:
            return
        pipe = _r.pipeline()
        for k, v in kw.items():
            pipe.hset(_STATE_KEY, k, json.dumps(v))
        pipe.execute()

    def snapshot(self) -> dict[str, Any]:
        raw = _r.hgetall(_STATE_KEY) or {}
        result: dict[str, Any] = {}
        for k, v in raw.items():
            try:
                result[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                result[k] = v
        for k, v in _INITIAL_STATE.items():
            result.setdefault(k, v)
        return result

    def add_pid(self, pid: int) -> None:
        with _local_lock:
            _local_pids.add(pid)

    def remove_pid(self, pid: int) -> None:
        with _local_lock:
            _local_pids.discard(pid)


class RedisCancelEvent:
    """threading.Event-compatible view of the cancel flag in Redis."""
    def is_set(self) -> bool:
        return _r.get(_CANCEL_KEY) == "1"


# ---------- public API ----------

def status() -> dict[str, Any]:
    return State().snapshot()


def is_running() -> bool:
    return bool(_r.get(_LOCK_KEY))


def start(target: Callable[..., None], *, profile: str = "quick", **kwargs: Any) -> bool:
    """Atomically claim the running slot via Redis SET NX. Returns False if
    another worker (or this one) already owns an active scan."""
    if not _r.set(_LOCK_KEY, "1", nx=True, ex=_LOCK_TTL_SECONDS):
        return False

    scan_id = str(uuid.uuid4())
    _r.delete(_STATE_KEY, _CANCEL_KEY)

    state = State()
    state.set(
        scan_id=scan_id, running=True, cancelling=False,
        current=0, total=0, message="Starting…", last_error="",
        profile=profile, eta_seconds=None, last_host=None,
        started_at=time.time(), finished_at=None,
    )

    cancel_event = RedisCancelEvent()
    stop_watcher = threading.Event()

    def _refresh_lock():
        while not stop_watcher.is_set():
            _r.expire(_LOCK_KEY, _LOCK_TTL_SECONDS)
            stop_watcher.wait(_LOCK_REFRESH_INTERVAL)

    def _cancel_watcher():
        # Wakes on Redis cancel flag (checked every 0.5s) and kills local subprocesses.
        while not stop_watcher.is_set():
            if cancel_event.is_set():
                _kill_local_pids()
            stop_watcher.wait(0.5)

    def _runner():
        try:
            target(state, cancel_event, profile=profile, **kwargs)
        except Exception as e:
            LOG.exception("background job crashed")
            state.set(last_error=str(e), message="Scan error")
        finally:
            stop_watcher.set()
            _kill_local_pids()
            state.set(running=False, cancelling=False, finished_at=time.time())
            _r.delete(_LOCK_KEY)

    threading.Thread(target=_refresh_lock, name="hostlore-lock", daemon=True).start()
    threading.Thread(target=_cancel_watcher, name="hostlore-cancelwatch", daemon=True).start()
    threading.Thread(target=_runner, name="hostlore-worker", daemon=True).start()
    return True


def cancel() -> None:
    """Broadcast cancel via Redis so whichever worker owns the scan hears it."""
    _r.set(_CANCEL_KEY, "1", ex=300)
    _kill_local_pids()  # in case the running scan is us
    State().set(cancelling=True, message="Cancelling…")


def _kill_local_pids() -> None:
    with _local_lock:
        pids = list(_local_pids)
    for pid in pids:
        try:
            os.killpg(pid, 15)
        except ProcessLookupError:
            pass
        except Exception as e:
            LOG.debug("SIGTERM pid %s failed: %s", pid, e)
    if not pids:
        return
    time.sleep(0.5)
    with _local_lock:
        pids = list(_local_pids)
    for pid in pids:
        try:
            os.killpg(pid, 9)
        except ProcessLookupError:
            pass
        except Exception as e:
            LOG.debug("SIGKILL pid %s failed: %s", pid, e)


def reset_for_tests() -> None:
    """Test helper: nuke all Redis state + local PIDs so tests start clean."""
    _r.delete(_STATE_KEY, _CANCEL_KEY, _LOCK_KEY)
    with _local_lock:
        _local_pids.clear()
