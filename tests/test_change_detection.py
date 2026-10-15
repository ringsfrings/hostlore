"""Change detection + alert formatting (no network, no DB)."""
from app.scanner import diff_host
from app.telegram import _chunks, format_change_digest

WEB_UP = {"status": True, "title": "Home"}


def _prev(ports=(), website=None, is_up=True):
    return {"is_up": is_up, "ports": set(ports), "website": website}


def _cur(ports=(), website=None):
    return {"ports": set(ports), "website": website}


def test_new_device():
    assert diff_host(None, _cur([("tcp", 22)])) == ["🆕 new device"]


def test_no_change_means_no_alert():
    assert diff_host(_prev([("tcp", 22)], WEB_UP), _cur([("tcp", 22)], WEB_UP)) == []


def test_ports_opened_and_closed_are_sorted():
    changes = diff_host(_prev([("tcp", 22), ("tcp", 80)]), _cur([("tcp", 80), ("tcp", 8080), ("tcp", 443)]))
    assert changes == ["🔓 opened tcp/443, tcp/8080", "🔒 closed tcp/22"]


def test_back_online():
    assert diff_host(_prev([("tcp", 22)], is_up=False), _cur([("tcp", 22)])) == ["🔁 back online"]


def test_website_transitions():
    assert diff_host(_prev(), _cur(website=WEB_UP)) == ["🌐 website UP"]
    assert diff_host(_prev(website=WEB_UP), _cur()) == ["🌐 website gone"]
    down = {"status": False, "title": "Home"}
    assert diff_host(_prev(website=WEB_UP), _cur(website=down)) == ["🌐 website DOWN"]
    renamed = {"status": True, "title": "Hacked"}
    assert diff_host(_prev(website=WEB_UP), _cur(website=renamed)) == ["🏷️ title changed: Home → Hacked"]


def test_digest_is_sorted_by_ip_and_escaped():
    msg = format_change_digest("10.0.0.0/24", [
        ("10.0.0.10", "web", ["🔻 went offline"]),
        ("10.0.0.2", "<script>", ["🆕 new device"]),
    ])
    assert msg.index("10.0.0.2") < msg.index("10.0.0.10")
    assert "&lt;script&gt;" in msg and "<script>" not in msg
    assert "2 device(s)" in msg


def test_chunks_respect_limit_and_keep_all_text():
    text = "\n".join(f"line {i} " + "x" * 50 for i in range(500))
    parts = _chunks(text, limit=1000)
    assert all(len(p) <= 1000 for p in parts)
    assert "\n".join(parts) == text
    assert _chunks("y" * 2500, limit=1000) == ["y" * 1000, "y" * 1000, "y" * 500]
