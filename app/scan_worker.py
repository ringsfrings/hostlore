# app/scan_worker.py
import threading
import time
from typing import Dict, Any, Optional, Callable

# In-memory scan state (good enough for single-instance Flask)
_state_lock = threading.Lock()
_state: Dict[str, Any] = {
    "running": False,
    "total": 0,
    "done": 0,
    "current": None,  # current IP
    "started_at": None,
    "finished_at": None,
    "error": None,
}

_worker_thread: Optional[threading.Thread] = None
_cancel_event = threading.Event()

def _set(**kwargs):
    with _state_lock:
        _state.update(kwargs)

def get_status() -> Dict[str, Any]:
    with _state_lock:
        return dict(_state)

def is_running() -> bool:
    with _state_lock:
        return bool(_state["running"])

def cancel():
    _cancel_event.set()

def _progress_callback(total: int = None, done: int = None, current: str = None):
    with _state_lock:
        if total is not None:
            _state["total"] = total
        if done is not None:
            _state["done"] = done
        if current is not None:
            _state["current"] = current

def start(run_fn: Callable[[Callable, threading.Event], None]):
    global _worker_thread
    if is_running():
        return False

    # reset state
    _cancel_event.clear()
    _set(running=True, total=0, done=0, current=None, started_at=time.time(), finished_at=None, error=None)

    def _runner():
        try:
            run_fn(_progress_callback, _cancel_event)
        except Exception as e:
            _set(error=str(e))
        finally:
            _set(running=False, finished_at=time.time(), current=None)

    _worker_thread = threading.Thread(target=_runner, daemon=True)
    _worker_thread.start()
    return True
