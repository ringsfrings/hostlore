import logging
import os
import time
from html import escape

import requests

from app import metrics as M
from app.config_loader import load_config

LOG = logging.getLogger("telegram")

def _get_creds():
    cfg = load_config() or {}
    tg = cfg.get("telegram") or {}
    token = tg.get("token")
    chat_id = tg.get("chat_id")
    return token, str(chat_id) if chat_id is not None else None

def _post_telegram(token: str, chat_id: str, text: str, tries: int = 3) -> bool:
    # Overridable so the e2e lab can point alerts at a mock Telegram API.
    base = os.getenv("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
    url = f"{base}/bot{token}/sendMessage"
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

TELEGRAM_MAX_CHARS = 4096


def _chunks(text: str, limit: int = TELEGRAM_MAX_CHARS) -> list:
    """Split on line boundaries so no message exceeds Telegram's size limit."""
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:limit])
            line = line[limit:]
        candidate = f"{cur}\n{line}" if cur else line
        if len(candidate) > limit:
            out.append(cur)
            cur = line
        else:
            cur = candidate
    if cur:
        out.append(cur)
    return out


def send_text(text: str) -> bool:
    """Send an HTML message (split if too long). Skipped when Telegram isn't configured."""
    token, chat_id = _get_creds()
    if not token or not chat_id:
        LOG.info("[Telegram] token/chat_id missing; skipping alert.")
        M.TELEGRAM_SENDS_TOTAL.labels(result="skipped").inc()
        return False
    ok = True
    for part in _chunks(text):
        sent = _post_telegram(token, chat_id, part)
        M.TELEGRAM_SENDS_TOTAL.labels(result="ok" if sent else "error").inc()
        ok = ok and sent
    return ok


def format_change_digest(ip_range: str, events: list) -> str:
    """events: [(ip, hostname, [change, ...]), ...] -> one HTML digest message."""
    lines = [f"📡 <b>Network changes</b> in {escape(ip_range)} — {len(events)} device(s)"]
    for ip, hostname, changes in sorted(events, key=lambda e: _ip_key(e[0])):
        name = f" ({escape(hostname)})" if hostname and hostname != "Unknown" else ""
        lines.append(f"\n🖥️ <b>{escape(ip)}</b>{name}")
        lines.extend(f"  • {escape(c)}" for c in changes)
    return "\n".join(lines)


def _ip_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)
