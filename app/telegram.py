import time, logging, requests
from html import escape
from app.config_loader import load_config
LOG = logging.getLogger("telegram")

def _get_creds():
    cfg = load_config() or {}
    tg = cfg.get("telegram") or {}
    token = tg.get("token")
    chat_id = tg.get("chat_id")
    return token, str(chat_id) if chat_id is not None else None

def _post_telegram(token: str, chat_id: str, text: str, tries: int = 3) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    for i in range(max(1, tries)):
        try:
            r = requests.post(url, data=payload, timeout=6)
            if r.status_code == 200:
                return True
            LOG.warning("Telegram HTTP %s: %s", r.status_code, r.text[:200])
        except Exception as e:
            LOG.warning("Telegram request failed (try %s): %s", i + 1, e)
        time.sleep(0.7 * (i + 1))
    return False

def send_scan_alert(ip: str, hostname: str, os_name: str, website: dict, services: list) -> bool:
    """Send alert for every host on every scan run (your request)."""
    token, chat_id = _get_creds()
    if not token or not chat_id:
        LOG.info("[Telegram] token/chat_id missing; skipping alert.")
        return False

    host_disp = escape(hostname or "Unknown")
    ip_disp = escape(ip)
    os_disp = escape(os_name or "Unknown")

    # Website summary
    status = website.get("status") if website else None
    url = website.get("url") if website else None
    title = website.get("title") if website else None
    status_icon = "✅" if status else "❌"
    url_disp = escape(url or f"http://{ip}")
    title_disp = escape(title or "—")

    # Services compact line (max ~10)
    top = services[:10] if services else []
    svc_line = " ".join([f"{s.get('proto','tcp').upper()}/{s.get('port')}:{(s.get('service') or '')[:10]}" for s in top])
    if services and len(services) > 10:
        svc_line += f" (+{len(services)-10} more)"

    msg = (
        f"📡 <b>Scan result</b>\n"
        f"🖥️ <b>Host:</b> {host_disp} ({ip_disp})\n"
        f"🧩 <b>OS:</b> {os_disp}\n"
        f"{status_icon} <b>Website:</b> <a href=\"{url_disp}\">{url_disp}</a>\n"
        f"🏷️ <b>Title:</b> {title_disp}\n"
        f"🧷 <b>Open:</b> {escape(svc_line) if svc_line else '—'}"
    )

    return _post_telegram(token, chat_id, msg)
