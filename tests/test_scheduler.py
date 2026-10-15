"""Tests for the interval parser + lock behavior in app.scheduler."""
import pytest


def test_parse_interval_units():
    from app.scheduler import _parse_interval
    assert _parse_interval("30s") == 30
    assert _parse_interval("15m") == 900
    assert _parse_interval("2h") == 7200
    assert _parse_interval("45") == 45  # bare number defaults to seconds


def test_parse_interval_disabled_forms():
    from app.scheduler import _parse_interval
    assert _parse_interval("") == 0
    assert _parse_interval("   ") == 0
    assert _parse_interval("0") == 0


def test_parse_interval_rejects_garbage():
    from app.scheduler import _parse_interval
    with pytest.raises(ValueError):
        _parse_interval("15minutes")
    with pytest.raises(ValueError):
        _parse_interval("m")


def test_start_if_configured_no_op_when_disabled(monkeypatch):
    monkeypatch.delenv("SCAN_SCHEDULE_INTERVAL", raising=False)
    from app import scheduler
    # Must not raise, must not start a thread.
    scheduler.start_if_configured()
