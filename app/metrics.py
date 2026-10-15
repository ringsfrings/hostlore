"""
Prometheus metrics for Hostlore.

Instrumented from:
  - scanner.py    (scan lifecycle, nmap durations, host/service counts)
  - telegram.py   (alert send success/failure)
  - render()      (in-progress gauge, read from the Redis scan lock)

Gunicorn runs several worker processes. When PROMETHEUS_MULTIPROC_DIR is set
(the entrypoint does this), every worker writes its samples to that directory
and /metrics aggregates all of them — otherwise each scrape would only see the
counters of whichever worker happened to answer.
"""
import os

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)

MULTIPROC = bool(os.getenv("PROMETHEUS_MULTIPROC_DIR"))
REGISTRY = CollectorRegistry(auto_describe=True)

# Build / static info (Info metrics are not supported in multiprocess mode).
BUILD_INFO = Gauge("hostlore_build_info", "Hostlore build metadata.", ["version"],
                   multiprocess_mode="max", registry=REGISTRY)
BUILD_INFO.labels(version="1.0.0").set(1)

# Scan lifecycle
SCANS_TOTAL = Counter(
    "hostlore_scans_total",
    "Number of scans that reached a terminal state, labelled by outcome and profile.",
    ["profile", "result"],  # result: complete|cancelled|error
    registry=REGISTRY,
)
SCAN_DURATION = Histogram(
    "hostlore_scan_duration_seconds",
    "Wall-clock duration of a full scan.",
    ["profile"],
    buckets=(5, 15, 30, 60, 120, 300, 600, 1200, 3600),
    registry=REGISTRY,
)
SCAN_IN_PROGRESS = Gauge(
    "hostlore_scan_in_progress",
    "1 if a scan is currently running, 0 otherwise.",
    multiprocess_mode="mostrecent",
    registry=REGISTRY,
)

# Per-scan observations (last completed scan)
HOSTS_DISCOVERED = Gauge(
    "hostlore_hosts_discovered",
    "Hosts found up during discovery in the most recent scan.",
    multiprocess_mode="mostrecent",
    registry=REGISTRY,
)
HOSTS_SCANNED = Gauge(
    "hostlore_hosts_scanned",
    "Hosts actually scanned (post-discovery) in the most recent scan.",
    multiprocess_mode="mostrecent",
    registry=REGISTRY,
)
SERVICES_OPEN = Gauge(
    "hostlore_services_open",
    "Total open services observed in the most recent scan.",
    multiprocess_mode="mostrecent",
    registry=REGISTRY,
)
WEBSITES_UP = Gauge(
    "hostlore_websites_up",
    "Websites returning HTTP 2xx/3xx in the most recent scan.",
    multiprocess_mode="mostrecent",
    registry=REGISTRY,
)
WEBSITES_DOWN = Gauge(
    "hostlore_websites_down",
    "Websites returning HTTP 4xx/5xx / no response in the most recent scan.",
    multiprocess_mode="mostrecent",
    registry=REGISTRY,
)

# nmap subprocess timings
NMAP_DURATION = Histogram(
    "hostlore_nmap_duration_seconds",
    "Duration of a single nmap invocation.",
    ["op"],  # op: discover | tcp | udp
    buckets=(1, 5, 10, 30, 60, 120, 300, 600),
    registry=REGISTRY,
)
NMAP_TIMEOUTS_TOTAL = Counter(
    "hostlore_nmap_timeouts_total",
    "Number of nmap invocations killed for exceeding their timeout.",
    ["op"],
    registry=REGISTRY,
)

# Telegram
TELEGRAM_SENDS_TOTAL = Counter(
    "hostlore_telegram_sends_total",
    "Telegram send attempts, labelled by outcome.",
    ["result"],  # result: ok|error|skipped
    registry=REGISTRY,
)


def render() -> tuple[bytes, str]:
    try:
        from app.scan_worker import is_running
        SCAN_IN_PROGRESS.set(1 if is_running() else 0)
    except Exception:
        pass
    if MULTIPROC:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry), CONTENT_TYPE_LATEST
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
