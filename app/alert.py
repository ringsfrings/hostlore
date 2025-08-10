# app/alert.py

import requests
from app.config_loader import load_config

config = load_config()
TELEGRAM_TOKEN = config["telegram"]["token"]
TELEGRAM_CHAT_ID = config["telegram"]["chat_id"]

def send_telegram_alert(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }

    try:
        response = requests.post(url, data=payload, timeout=5)
        if response.status_code != 200:
            print(f"[!] Telegram error: {response.text}")
    except Exception as e:
        print(f"[!] Telegram request failed: {e}")
