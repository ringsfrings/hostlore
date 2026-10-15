"""Flask route tests — CSRF-free using test client's default config."""
import os


def test_health_before_setup_reports_not_configured(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert data["secrets_configured"] is False


def test_root_redirects_to_setup_on_first_run(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/setup" in r.headers["Location"]


def test_setup_page_rendered_when_no_secrets(client):
    r = client.get("/setup")
    assert r.status_code == 200
    assert b"Initial Setup" in r.data


def test_setup_locks_out_after_secrets_exist(client, isolated_fs):
    """After first-run setup completes, /setup must forward to /reset."""
    from app.secrets_manager import SECRETS_FILE
    with open(SECRETS_FILE, "wb") as f:
        f.write(b"encrypted-blob-placeholder")

    r = client.get("/setup", follow_redirects=False)
    assert r.status_code == 302
    assert "/reset" in r.headers["Location"]


def test_metrics_endpoint_serves_prometheus_text(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.data.decode()
    # A few sentinel metric families defined in app/metrics.py
    assert "hostlore_scans_total" in body
    assert "hostlore_scan_in_progress" in body
    assert "hostlore_nmap_duration_seconds" in body


def test_health_reports_configured_after_secrets_written(client, isolated_fs):
    from app.secrets_manager import SECRETS_FILE
    with open(SECRETS_FILE, "wb") as f:
        f.write(b"placeholder")
    data = client.get("/health").get_json()
    assert data["secrets_configured"] is True
