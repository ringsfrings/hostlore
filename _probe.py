import argparse
import socket
import sys
import time
import urllib.request


def wait_db(host: str, port: int, timeout: int) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=2):
                print("db:ready")
                return 0
        except Exception:
            time.sleep(2)
    print("db:not-ready", file=sys.stderr)
    return 1

def probe_http(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return 0 if r.status < 500 else 1
    except Exception:
        return 1

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait-db", action="store_true")
    ap.add_argument("--host", default="db")
    ap.add_argument("--port", default="5432")
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    if args.wait_db:
        sys.exit(wait_db(args.host, int(args.port), args.timeout))
    else:
        sys.exit(probe_http("http://127.0.0.1:8000/"))
