"""Tests for app.utils (scan profile persistence, CIDR validation)."""
import pytest


def test_scan_profile_defaults_to_quick_when_missing(isolated_fs):
    from app.utils import get_scan_profile
    assert get_scan_profile() == "quick"


def test_scan_profile_round_trip(isolated_fs):
    from app.utils import get_scan_profile, set_scan_profile
    set_scan_profile("balanced")
    assert get_scan_profile() == "balanced"


def test_scan_profile_rejects_invalid_values(isolated_fs):
    from app.utils import get_scan_profile, set_scan_profile
    set_scan_profile("garbage")
    assert get_scan_profile() == "quick"


def test_update_ip_range_validates_cidr(isolated_fs):
    from app.utils import save_form_data, update_ip_range
    save_form_data("10.0.0.0/24", "tok", "chat", "pw")
    update_ip_range("192.168.5.0/28")  # valid — should succeed silently
    with pytest.raises(ValueError):
        update_ip_range("not-a-cidr")


def test_update_ip_range_preserves_telegram_creds(isolated_fs):
    from app.utils import get_current_settings, save_form_data, update_ip_range
    save_form_data("10.0.0.0/24", "the-token", "the-chat", "the-pw")
    update_ip_range("172.16.0.0/16")
    cfg = get_current_settings()
    assert cfg["app"]["ip_range"] == "172.16.0.0/16"
    assert cfg["telegram"]["token"] == "the-token"
    assert cfg["telegram"]["chat_id"] == "the-chat"
