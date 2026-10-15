"""Tests for the generic background-job runner."""
import threading
import time

from app import scan_worker as worker


def _reset_worker_state():
    worker.reset_for_tests()


def _wait_until_idle(timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not worker.is_running():
            return True
        time.sleep(0.02)
    return False


def test_start_runs_target_with_state_and_cancel_event():
    _reset_worker_state()

    got = {}
    done = threading.Event()

    def target(state, cancel_event, *, profile):
        got["profile"] = profile
        got["has_cancel"] = hasattr(cancel_event, "is_set")
        got["has_state_api"] = all(hasattr(state, m) for m in ("set", "snapshot", "add_pid", "remove_pid"))
        state.set(message="running")
        done.set()

    assert worker.start(target, profile="balanced") is True
    done.wait(timeout=1)
    assert _wait_until_idle()

    assert got["profile"] == "balanced"
    assert got["has_cancel"] is True
    assert got["has_state_api"] is True


def test_start_refuses_when_already_running():
    _reset_worker_state()
    started = threading.Event()
    can_finish = threading.Event()

    def slow(state, cancel_event, *, profile):
        started.set()
        can_finish.wait(timeout=2)

    assert worker.start(slow, profile="quick") is True
    started.wait(timeout=1)
    # Second start must be rejected.
    assert worker.start(slow, profile="quick") is False
    can_finish.set()
    assert _wait_until_idle()


def test_cancel_signals_target():
    _reset_worker_state()
    started = threading.Event()
    saw_cancel = threading.Event()

    def target(state, cancel_event, *, profile):
        started.set()
        for _ in range(100):
            if cancel_event.is_set():
                saw_cancel.set()
                return
            time.sleep(0.02)

    worker.start(target, profile="quick")
    started.wait(timeout=1)
    worker.cancel()
    saw_cancel.wait(timeout=2)
    assert _wait_until_idle()
    assert saw_cancel.is_set()


def test_status_exposes_scan_id_and_profile():
    _reset_worker_state()
    done = threading.Event()

    def target(state, cancel_event, *, profile):
        done.set()

    worker.start(target, profile="deep")
    done.wait(timeout=1)
    assert _wait_until_idle()

    snap = worker.status()
    assert snap["profile"] == "deep"
    assert snap["scan_id"]  # UUID string, non-empty
    assert snap["running"] is False


def test_exception_in_target_is_captured_in_state():
    _reset_worker_state()

    def crasher(state, cancel_event, *, profile):
        raise RuntimeError("boom")

    worker.start(crasher, profile="quick")
    assert _wait_until_idle()

    snap = worker.status()
    assert "boom" in snap["last_error"]
    assert snap["running"] is False
