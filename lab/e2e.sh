#!/usr/bin/env bash
# End-to-end test against the docker lab (see docker-compose.lab.yml).
# Brings the stack up, runs first-time setup, scans the lab subnet, checks the
# inventory + alerts, then stops a target and checks the change is detected.
#
#   ./lab/e2e.sh           run (stack is left up for inspection)
#   KEEP=0 ./lab/e2e.sh    tear everything down at the end
set -euo pipefail
cd "$(dirname "$0")/.."

APP=http://localhost:8000
TG=http://localhost:8081
SUBNET=172.30.99.0/24
COMPOSE=(docker compose -p hostlore-lab -f docker-compose.yml -f docker-compose.lab.yml)
JAR=$(mktemp)
trap 'rm -f "$JAR"; [ "${KEEP:-1}" = 0 ] && "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true' EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; "${COMPOSE[@]}" logs --tail 60 app || true; exit 1; }

# json <python expression over `d`>  — reads JSON on stdin
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

csrf_from() {
  curl -fsS -c "$JAR" -b "$JAR" "$APP$1" | python3 -c \
    'import re,sys; m=re.search(r"name=\"csrf[_-]token\"[^>]*(?:value|content)=\"([^\"]+)\"", sys.stdin.read()); print(m.group(1) if m else "")'
}

scan() {
  local token code
  token=$(csrf_from /)
  for _ in $(seq 1 10); do   # /scan/start is rate-limited (5/min): wait on 429
    code=$(curl -sS -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -X POST "$APP/scan/start" \
           -H 'Content-Type: application/json' -H "X-CSRFToken: $token" -d '{"profile":"quick"}')
    [ "$code" = 200 ] && break
    [ "$code" = 429 ] || fail "/scan/start returned HTTP $code"
    sleep 10
  done
  [ "$code" = 200 ] || fail "/scan/start still rate-limited"
  for _ in $(seq 1 120); do
    [ "$(curl -fsS "$APP/scan/status" | json 'd.get("running")')" = "False" ] && return 0
    sleep 2
  done
  fail "scan did not finish within 4 minutes"
}

echo "== 1. start stack + lab"
[ -f secrets/db_password.txt ] || { mkdir -p secrets; openssl rand -hex 24 > secrets/db_password.txt; }
[ -f .env ] || printf 'FLASK_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" > .env
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build >/dev/null
for _ in $(seq 1 60); do curl -fsS "$APP/health" >/dev/null 2>&1 && break; sleep 2; done
curl -fsS "$APP/health" >/dev/null || fail "app never became healthy"
for _ in $(seq 1 30); do curl -fsS "$TG/health" >/dev/null 2>&1 && break; sleep 1; done
pass "app and mock Telegram are up"

echo "== 2. first-run setup"
token=$(csrf_from /setup)
[ -n "$token" ] || fail "no CSRF token on /setup"
curl -fsS -o /dev/null -c "$JAR" -b "$JAR" -X POST "$APP/setup" \
     --data-urlencode "csrf_token=$token" --data-urlencode "ip_range=$SUBNET" \
     --data-urlencode "token=lab-token" --data-urlencode "chat_id=4242"
[ "$(curl -fsS "$APP/health" | json 'd["secrets_configured"]')" = "True" ] || fail "setup did not save settings"
pass "setup saved (range $SUBNET)"

echo "== 3. first scan"
sleep 15   # ssh1/snmp1 install their packages on first boot
scan
RESULTS=$(curl -fsS "$APP/results.json")
has() { echo "$RESULTS" | json "$1"; }
[ "$(has 'any(h["ip"]=="172.30.99.10" and h["website"] and h["website"]["status"] and h["website"]["title"]=="Lab Web 1" for h in d)')" = True ] \
  && pass "web1: website UP, title 'Lab Web 1'" || fail "web1 website not detected: $RESULTS"
[ "$(has 'any(h["ip"]=="172.30.99.10" and any(s["port"]==80 for s in h["services"]) for h in d)')" = True ] \
  && pass "web1: tcp/80 open" || fail "web1 port 80 missing"
[ "$(has 'any(h["ip"]=="172.30.99.10" and h["os"]=="Linux/Unix" for h in d)')" = True ] \
  && pass "web1: OS family from reply TTL (nginx alone reveals no OS)" || fail "web1 OS still unknown"
[ "$(has 'all(h["online"] and h["first_seen"] and h["last_seen"] for h in d)')" = True ] \
  && pass "history: every host online with first/last seen" || fail "history fields missing"
[ "$(has '[h["ip"] for h in d][:3]==["172.30.99.1","172.30.99.2","172.30.99.10"]')" = True ] \
  && pass "results sorted numerically by IP" || fail "IP sort is not numeric"
[ "$(has 'any(h["ip"]=="172.30.99.11" and any(s["port"]==22 for s in h["services"]) for h in d)')" = True ] \
  && pass "ssh1: tcp/22 open" || fail "ssh1 port 22 missing"
[ "$(has 'any(h["ip"]=="172.30.99.12" and h["ram"] and h["os"]=="Linux" for h in d)')" = True ] \
  && pass "snmp1: RAM + OS read over SNMP" || fail "snmp1 SNMP data not read"
[ "$(has 'any(h["ip"]=="172.30.99.12" and any(s["proto"]=="udp" and s["port"]==161 for s in h["services"]) for h in d)')" = True ] \
  && pass "snmp1: udp/161 listed (proven by the SNMP answer)" || fail "snmp1 udp/161 missing"
MSGS=$(curl -fsS "$TG/messages")
[ "$(echo "$MSGS" | json 'len(d)==1 and "Baseline inventory" in d[0]["text"] and d[0]["chat_id"]=="4242"')" = True ] \
  && pass "baseline: exactly one summary message (no per-device spam)" || fail "baseline alert wrong: $MSGS"
[ "$(curl -fsS "$APP/metrics" | awk '/^hostlore_scans_total\{profile="quick",result="complete"\}/ {print int($2)}')" -ge 1 ] \
  && pass "metrics: complete scan counted (shared across gunicorn workers)" || fail "scan metric missing"

echo "== 4. no change -> no new alerts"
curl -fsS -X POST "$TG/reset" >/dev/null
scan
[ "$(curl -fsS "$TG/messages" | json 'len(d)')" = 0 ] && pass "second identical scan sent no alerts" \
  || fail "duplicate alerts: $(curl -fsS "$TG/messages")"

# assert_digest <ip> <text>  — the last Telegram message is a digest mentioning both
assert_digest() {
  local msgs; msgs=$(curl -fsS "$TG/messages")
  [ "$(echo "$msgs" | json "len(d)==1 and 'Network changes' in d[0]['text'] and '$1' in d[0]['text'] and '$2' in d[0]['text']")" = True ] \
    && pass "digest: $1 → $2" || fail "expected one digest with '$1' / '$2', got: $msgs"
  curl -fsS -X POST "$TG/reset" >/dev/null
}

echo "== 5. a new service appears -> 'opened' alert"
docker exec -d lab-ssh1 nc -lk -p 8080 -e /bin/echo "hello from 8080"
sleep 2
scan
assert_digest 172.30.99.11 "opened tcp/8080"

echo "== 6. web1 goes offline -> 'went offline' alert"
docker stop lab-web1 >/dev/null
scan
assert_digest 172.30.99.10 "went offline"
[ "$(curl -fsS "$APP/results.json" | json 'any(h["ip"]=="172.30.99.10" and h["online"] is False for h in d)')" = True ] \
  && pass "history: web1 marked Offline in results" || fail "web1 not marked offline"
curl -fsS "$APP/results" | grep -q "Offline" && pass "results page shows the Offline badge" || fail "no Offline badge"
[ "$(curl -fsS "$APP/metrics" | grep '^hostlore_hosts_discovered ' | awk '{print int($2)}')" -ge 1 ] \
  && pass "metrics: hosts_discovered gauge populated" || fail "hosts_discovered gauge empty"

echo "== 7. web1 comes back -> 'back online' alert"
docker start lab-web1 >/dev/null
sleep 3
scan
assert_digest 172.30.99.10 "back online"

echo; echo "All e2e checks passed."
