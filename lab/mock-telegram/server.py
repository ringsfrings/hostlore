"""Tiny stand-in for the Telegram Bot API, used by the e2e lab.

POST /bot<token>/sendMessage  -> records the message, answers like Telegram
GET  /messages                -> every recorded message as JSON
POST /reset                   -> forget recorded messages
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MESSAGES = []
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/messages":
            with LOCK:
                return self._send(200, list(MESSAGES))
        if self.path == "/health":
            return self._send(200, {"ok": True})
        self._send(404, {"ok": False})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        if self.path == "/reset":
            with LOCK:
                MESSAGES.clear()
            return self._send(200, {"ok": True})
        if self.path.startswith("/bot") and self.path.endswith("/sendMessage"):
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            with LOCK:
                MESSAGES.append({"chat_id": form.get("chat_id"), "text": form.get("text", "")})
            return self._send(200, {"ok": True, "result": {"message_id": len(MESSAGES)}})
        self._send(404, {"ok": False})

    def log_message(self, fmt, *args):
        print("mock-telegram:", fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
