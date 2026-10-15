"""
Scanner logic. All threading/state/cancel plumbing lives in app.scan_worker;
this module only cares about actually running nmap and interpreting results.
"""
import ipaddress
import logging
import os
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

from app import metrics as M
from app import scan_worker as worker
from app.config_loader import load_config
from app.fallback_utils import http_headers_os, netbios_name, smb_os_discovery, upnp_ssdp_friendlyname
from app.snmp_utils import get_snmp_info
from app.telegram import format_change_digest, send_text
from db.models import Host, Service, Website, get_session, init_db

# LAN targets frequently use self-signed certs; verify=False is intentional.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG = logging.getLogger("scanner")

PROFILES = {
    # quick: top-100 ports covers everything meaningful on a LAN; version-intensity 2
    # keeps banner grabs cheap; no -O (OS fingerprint) — inferred from services later.
    "quick":    {"tcp": ["-sV", "--version-intensity", "2", "--top-ports", "100"], "udp": None,                          "timeout": 30, "workers": 12, "os": False},
    "balanced": {"tcp": ["-sV", "--top-ports", "2000"],                            "udp": None,                          "timeout": 60, "workers": 10, "os": True},
    "deep":     {"tcp": ["-sV", "-p-"],                                            "udp": ["-sU", "--top-ports", "200"], "timeout": 120, "workers": 8, "os": True},
}
HTTP_PORTS = {80, 8080, 8000, 8888, 3000}
HTTPS_PORTS = {443, 8443}


# ---------- Public API (thin wrappers over the worker) ----------

def start_scan_background(options=None):
    opts = options or {}
    profile = (opts.get("profile") or "quick").lower()
    if profile not in PROFILES:
        profile = "quick"
    return worker.start(_run_scan, profile=profile)


def cancel_scan():
    worker.cancel()


def scan_status():
    return worker.status()


# ---------- Helpers ----------

def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _http_request(method, url, headers=None, timeout=3, verify=False, tries=2, allow_redirects=True):
    for i in range(max(1, tries)):
        try:
            return requests.request(method, url, headers=headers, timeout=timeout,
                                    verify=verify, allow_redirects=allow_redirects)
        except Exception:
            if i == tries - 1:
                return None
            time.sleep(0.4 * (i + 1))
    return None


def _get_tls_names(ip, port):
    names = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=2) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return names
                subj = dict(x[0] for x in cert.get("subject", []))
                if "commonName" in subj:
                    names.append(subj["commonName"])
                for _typ, n in cert.get("subjectAltName", []):
                    if _typ.lower() == "dns":
                        names.append(n)
    except Exception:
        pass
    return list(dict.fromkeys(names))


def _run_nmap(args, timeout, state, cancel_event, op: str = "tcp"):
    if cancel_event.is_set():
        return ""
    cmd = ["nmap"] + args + ["-oX", "-", "-n"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    state.add_pid(proc.pid)
    t0 = time.time()
    try:
        out, err = proc.communicate(timeout=timeout)
        if proc.returncode != 0 and err:
            LOG.warning("nmap %s exited %s: %s", " ".join(args), proc.returncode,
                        err.decode(errors="ignore")[:300])
        return out.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except Exception:
            pass
        M.NMAP_TIMEOUTS_TOTAL.labels(op=op).inc()
        LOG.info("nmap timed out after %ss: %s", timeout, " ".join(args))
        return ""
    finally:
        M.NMAP_DURATION.labels(op=op).observe(time.time() - t0)
        state.remove_pid(proc.pid)


def _discover_up_hosts(cidr, state, cancel_event):
    args = ["-sn", "-PR", "-PE", "-PA80,443", "--max-retries", "1", "--host-timeout", "10s", cidr]
    xml = _run_nmap(args, 60, state, cancel_event, op="discover")
    up = []
    if not xml:
        return up
    try:
        root = ET.fromstring(xml)
        for h in root.findall("host"):
            st = h.find("status")
            if st is not None and st.get("state") == "up":
                addr = h.find("address")
                if addr is not None and addr.get("addrtype") in ("ipv4", "ipv6"):
                    up.append(addr.get("addr"))
    except ET.ParseError:
        pass
    return up


def _scan_completed(xml):
    """False when nmap gave no usable answer for the host: killed by our timeout
    (empty output), unparsable XML, or nmap's own --host-timeout (timedout="true",
    which still exits 0 but carries no port results)."""
    if not xml:
        return False
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return False
    hosts = root.findall("host")
    return bool(hosts) and not any(h.get("timedout") == "true" for h in hosts)


def _parse_ports_from_xml(xml):
    services, os_guess, os_cpes = [], "Unknown", []
    if not xml:
        return services, os_guess, os_cpes
    try:
        root = ET.fromstring(xml)
        for c in root.findall(".//os/osmatch"):
            if c.get("name"):
                os_guess = c.get("name")
        for c in root.findall(".//os/osclass/cpe"):
            if c.text:
                os_cpes.append(c.text.strip())
        for p in root.findall(".//port"):
            proto = p.get("protocol") or "tcp"
            portid = int(p.get("portid") or 0)
            state_el = p.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = p.find("service")
            name = svc_el.get("name") if svc_el is not None else ""
            product = svc_el.get("product") if svc_el is not None else ""
            version = svc_el.get("version") if svc_el is not None else ""
            tunnel = svc_el.get("tunnel") if svc_el is not None else ""
            cpes = [cpe.text for cpe in (svc_el.findall("cpe") if svc_el is not None else []) if cpe.text]
            services.append({
                "proto": proto, "port": portid, "service": name,
                "product": product, "version": version, "state": "open",
                "tunnel": tunnel, "cpes": cpes,
            })
    except ET.ParseError:
        pass
    return services, os_guess, os_cpes


def _pick_http_candidates(services):
    """Return (scheme, port) candidates found in services. Empty means: no web on this host."""
    cps = []
    for s in services:
        if s["proto"] != "tcp":
            continue
        p = s["port"]
        name = (s["service"] or "").lower()
        tun = (s.get("tunnel") or "").lower()
        if p in HTTP_PORTS or name == "http" or name.startswith("http-"):
            cps.append(("http", p))
        if p in HTTPS_PORTS or "https" in name or tun in ("ssl", "tls"):
            cps.append(("https", p))
    seen = set()
    out = []
    for sc, pt in cps:
        if (sc, pt) not in seen:
            seen.add((sc, pt))
            out.append((sc, pt))
    return out


def _fetch_title(ip, scheme, port, host_header=None):
    base = f"{scheme}://{ip}"
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        base += f":{port}"
    headers = {"Host": host_header} if host_header else None
    # Single-shot GET, no retries — nmap already told us the port is open, so if it
    # times out the server is either broken or ratelimiting us; retrying wastes scan
    # budget. (A HEAD-first probe never returns a body, so titles were always lost.)
    r = _http_request("GET", base, headers=headers, timeout=3, verify=False, tries=1)
    if not r:
        return None
    return {"ok": (r.status_code < 400), "url": r.url, "title": _extract_title(r)}


def _extract_title(resp, max_bytes=65536):
    """<title> of an HTML response; only the first 64 KB are parsed."""
    if "html" not in (resp.headers.get("Content-Type") or "html").lower():
        return None
    try:
        body = resp.content[:max_bytes].decode(resp.encoding or "utf-8", errors="ignore")
        soup = BeautifulSoup(body, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip() or None
    except Exception:
        pass
    return None


def _discover_website(ip, services, hostname_candidates, tls_names):
    candidates = _pick_http_candidates(services)
    if not candidates:
        return None
    # Cap total probes so a slow web server can't monopolize this host's scan budget.
    # Was unbounded (candidates × hostnames); now hard-limited to 4 requests worst case.
    MAX_PROBES = 4
    probes = 0
    names = [n for n in (hostname_candidates + tls_names) if n][:2]  # first 2 names only
    for scheme, port in candidates:
        if probes >= MAX_PROBES:
            break
        probes += 1
        meta = _fetch_title(ip, scheme, port)
        if meta and meta["ok"]:
            return meta
    for scheme, port in candidates:
        for host_header in names:
            if probes >= MAX_PROBES:
                break
            probes += 1
            meta = _fetch_title(ip, scheme, port, host_header=host_header)
            if meta and meta["ok"]:
                parsed = urlparse(meta["url"])
                hostport = host_header
                if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
                    hostport += f":{port}"
                meta["url"] = f"{scheme}://{hostport}{parsed.path or '/'}"
                return meta
    return None


def _infer_os_family(nmap_os, services, snmp_descr, smb_os, http_server, nb_name):
    text = " ".join([
        (nmap_os or ""), (snmp_descr or ""), (smb_os or ""), (http_server or ""), (nb_name or ""),
        " ".join([f"{s.get('service','')} {s.get('product','')} {s.get('version','')} "
                  f"{' '.join(s.get('cpes', []))}" for s in (services or [])]),
    ]).lower()

    if any(x in text for x in ["windows", "microsoft", "msrpc", "workgroup"]) \
       or any(s.get("port") in (445, 3389) for s in services or []):
        return "Windows"
    if any(x in text for x in ["linux", "ubuntu", "debian", "centos", "openssh", "dropbear"]):
        return "Linux"
    if any("cpe:/o:microsoft" in " ".join(s.get("cpes", [])).lower() for s in services or []):
        return "Windows"
    if any("cpe:/o:linux" in " ".join(s.get("cpes", [])).lower() for s in services or []):
        return "Linux"
    return "Unknown"


def _scan_one_host(ip, profile, priv_root, per_host_timeout, state, cancel_event):
    prof = PROFILES[profile]
    # --host-timeout lets nmap bail on unresponsive hosts internally, so we
    # don't spend the full per_host_timeout on every dead IP.
    nmap_host_timeout = f"{max(10, per_host_timeout - 5)}s"
    # --defeat-rst-ratelimit stops nmap from throttling itself on hosts (macOS/BSD
    # kernels rate-limit RST replies, which nmap otherwise interprets as filtered).
    base = ["-T4", "--max-retries", "1", "-Pn", "--defeat-rst-ratelimit",
            "--host-timeout", nmap_host_timeout]
    scan_type = ["-sS"] if priv_root else ["-sT"]
    if priv_root and prof.get("os", True):
        scan_type.append("-O")
    base = scan_type + base

    tcp_xml = _run_nmap(base + (prof["tcp"] or []) + [ip], per_host_timeout, state, cancel_event, op="tcp")
    if not _scan_completed(tcp_xml):
        # Unknown is not "all ports closed": skip this host for this scan rather
        # than store an empty result and fire false "closed" alerts.
        LOG.info("port scan of %s incomplete (timeout) — keeping previous state", ip)
        return None
    tcp_services, nmap_os, _os_cpes = _parse_ports_from_xml(tcp_xml)
    udp_services = []
    if prof["udp"]:
        udp_xml = _run_nmap(base + prof["udp"] + [ip], max(30, per_host_timeout), state, cancel_event, op="udp")
        if not _scan_completed(udp_xml):
            LOG.info("UDP scan of %s incomplete (timeout) — keeping previous state", ip)
            return None
        udp_services, _, _ = _parse_ports_from_xml(udp_xml)

    services = tcp_services + udp_services
    has_445 = any(s["proto"] == "tcp" and s["port"] == 445 for s in services)
    has_http = any(s["proto"] == "tcp" and s["port"] in HTTP_PORTS for s in services)

    ptr = _reverse_dns(ip)
    snmp_descr, snmp_cpu, snmp_ram, snmp_sysname = get_snmp_info(ip)
    nb_name = netbios_name(ip) if has_445 else None
    smb_os = smb_os_discovery(ip) if has_445 else None
    ssdp_server = upnp_ssdp_friendlyname(ip) if any(s["proto"] == "udp" and s["port"] == 1900 for s in services) else None
    http_server = http_headers_os(ip) if has_http else None

    https_ports = [s["port"] for s in services if s["proto"] == "tcp" and s["port"] in HTTPS_PORTS]
    tls_names: list = []
    for p in https_ports:
        tls_names.extend(_get_tls_names(ip, p))
    tls_names = list(dict.fromkeys(tls_names))

    hostname = ptr or snmp_sysname or nb_name or "Unknown"
    fam = _infer_os_family(nmap_os if priv_root else None, services, snmp_descr, smb_os, http_server, nb_name)
    os_name = fam if fam != "Unknown" else (snmp_descr or smb_os or nmap_os or http_server or ssdp_server or "Unknown")

    host_candidates = [ptr, snmp_sysname, nb_name]
    web = _discover_website(ip, services, host_candidates, tls_names)
    website = None
    if web:
        website = {"url": web["url"], "status": bool(web["ok"]), "title": web["title"]}

    return {
        "ip": ip, "hostname": hostname, "os": os_name,
        "cpu": snmp_cpu, "ram": snmp_ram,
        "website": website, "services": services,
    }


# ---------- Change detection (pure, unit-tested) ----------

def diff_host(prev, cur):
    """Human-readable changes between the stored state of a host and a fresh scan.

    prev: None for a never-seen host, else {"is_up", "ports": set[(proto, port)],
          "website": None | {"status", "title"}}
    cur:  {"ports": set[(proto, port)], "website": None | {"status", "title"}}
    """
    if prev is None:
        return ["🆕 new device"]
    changes = []
    if prev.get("is_up") is False:
        changes.append("🔁 back online")
    opened = sorted(cur["ports"] - prev["ports"], key=lambda p: (p[0], p[1]))
    closed = sorted(prev["ports"] - cur["ports"], key=lambda p: (p[0], p[1]))
    if opened:
        changes.append("🔓 opened " + ", ".join(f"{pr}/{po}" for pr, po in opened))
    if closed:
        changes.append("🔒 closed " + ", ".join(f"{pr}/{po}" for pr, po in closed))
    pw, cw = prev.get("website"), cur.get("website")
    if pw and not cw:
        changes.append("🌐 website gone")
    elif cw and not pw:
        changes.append("🌐 website " + ("UP" if cw["status"] else "DOWN"))
    elif pw and cw:
        if bool(pw["status"]) != bool(cw["status"]):
            changes.append("🌐 website " + ("UP" if cw["status"] else "DOWN"))
        elif (pw.get("title") or None) != (cw.get("title") or None):
            changes.append(f"🏷️ title changed: {pw.get('title') or '—'} → {cw.get('title') or '—'}")
    return changes


def _in_range(ip, network):
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


# ---------- Target function (runs inside the worker thread) ----------

def _run_scan(state, cancel_event, *, profile: str = "quick"):
    cfg = load_config() or {}
    ip_range = (cfg.get("app") or {}).get("ip_range", "192.168.1.0/24")
    init_db()
    session = get_session()

    scan_t0 = time.time()
    result = "error"
    try:
        # An empty inventory means this is the baseline scan: record everything,
        # send one summary instead of an alert per device.
        baseline = session.query(Host).count() == 0
        events = []   # (ip, hostname, [changes])

        state.set(message="Discovering hosts…")
        up_hosts = _discover_up_hosts(ip_range, state, cancel_event)
        total = len(up_hosts)
        M.HOSTS_DISCOVERED.set(total)
        state.set(total=total, message=f"Found {total} host(s) up")
        if cancel_event.is_set():
            state.set(message="Cancelled during discovery")
            result = "cancelled"
            return

        try:
            priv_root = (os.geteuid() == 0)
        except Exception:
            priv_root = False

        per_host_timeout = PROFILES[profile]["timeout"]
        workers = PROFILES[profile]["workers"]
        done = 0
        ema = None
        state.set(message=f"Scanning {total} host(s)…" if total else "No hosts up in range")

        def task(ip):
            nonlocal ema
            t0 = time.time()
            try:
                if cancel_event.is_set():
                    return None
                return _scan_one_host(ip, profile, priv_root, per_host_timeout, state, cancel_event)
            finally:
                dt = max(0.1, time.time() - t0)
                ema = dt if ema is None else (0.3 * dt + 0.7 * ema)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(task, ip): ip for ip in up_hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                if cancel_event.is_set():
                    break
                data = None
                try:
                    data = fut.result()
                except Exception as e:
                    LOG.warning("host %s error: %s", ip, e)

                done += 1
                eta = int(max(0, (total - done) * (ema or 0)))
                state.set(current=done, last_host=ip, eta_seconds=eta,
                          message=f"Scanning {ip} — {done}/{total}")

                if not data:
                    continue
                changes = _persist_host(session, data)
                if changes:
                    events.append((ip, data["hostname"], changes))

        if cancel_event.is_set():
            state.set(message=f"Scan cancelled — {done}/{total}")
            result = "cancelled"
        else:
            # Only a complete scan may declare hosts offline.
            events.extend(_mark_offline(session, ip_range, set(up_hosts)))
            state.set(message=f"Scan complete — {total}/{total}", current=total)
            result = "complete"

        M.HOSTS_SCANNED.set(done)
        _refresh_inventory_gauges(session)

        if result == "complete":
            if baseline:
                if total:
                    send_text(f"📋 <b>Baseline inventory</b> of {ip_range}: {total} device(s) recorded. "
                              "From now on you'll get a digest only when something changes.")
            elif events:
                send_text(format_change_digest(ip_range, events))
    finally:
        session.close()
        M.SCAN_DURATION.labels(profile=profile).observe(time.time() - scan_t0)
        M.SCANS_TOTAL.labels(profile=profile, result=result).inc()


def _refresh_inventory_gauges(session):
    """Snapshot the current DB state into the *_up/_down/services gauges."""
    try:
        from sqlalchemy import func as _f
        services_open = session.query(_f.count(Service.id)).filter(Service.state == "open").scalar() or 0
        websites_up = session.query(_f.count(Website.id)).filter(Website.status.is_(True)).scalar() or 0
        websites_down = session.query(_f.count(Website.id)).filter(Website.status.is_(False)).scalar() or 0
        M.SERVICES_OPEN.set(services_open)
        M.WEBSITES_UP.set(websites_up)
        M.WEBSITES_DOWN.set(websites_down)
    except Exception as e:
        LOG.debug("gauge refresh failed: %s", e)


def _mark_offline(session, ip_range, up_ips):
    """Hosts in the scanned range that were up last time but not now -> offline."""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        return []
    events = []
    for host in session.query(Host).filter(Host.is_up.isnot(False)).all():
        if host.ip in up_ips or not _in_range(host.ip, network):
            continue
        host.is_up = False
        events.append((host.ip, host.hostname, ["🔻 went offline"]))
    session.commit()
    return events


def _persist_host(session, data):
    """Upsert host + services + website. Returns the list of changes vs. the stored state."""
    ip = data["ip"]
    now = datetime.utcnow()
    host = session.query(Host).filter_by(ip=ip).first()
    ws = session.query(Website).filter_by(host_id=host.id).one_or_none() if host else None

    prev = None
    if host:
        prev = {
            "is_up": host.is_up,
            "ports": {(s.proto or "tcp", s.port) for s in host.services},
            "website": {"status": ws.status, "title": ws.title} if ws else None,
        }
    new_ws = data.get("website")
    cur = {
        "ports": {(s.get("proto", "tcp"), s["port"]) for s in data["services"]},
        "website": {"status": bool(new_ws["status"]), "title": new_ws["title"]} if new_ws else None,
    }
    changes = diff_host(prev, cur)

    if not host:
        host = Host(ip=ip, first_seen=now)
        session.add(host)
        session.flush()
    host.last_seen = now
    host.is_up = True
    host.hostname = data["hostname"]
    host.os = data["os"]
    if data["cpu"]:
        host.cpu = data["cpu"]
    if data["ram"]:
        host.ram = data["ram"]

    session.query(Service).filter_by(host_id=host.id).delete()
    for s in data["services"]:
        session.add(Service(
            proto=s.get("proto", "tcp"), port=s["port"], service=s.get("service", ""),
            product=s.get("product", ""), version=s.get("version", ""),
            state=s.get("state", "open"), host_id=host.id,
        ))

    if new_ws is None:
        if ws is not None:
            session.delete(ws)
    else:
        if ws is None:
            ws = Website(host_id=host.id)
            session.add(ws)
        ws.url = new_ws["url"]
        ws.status = bool(new_ws["status"])
        ws.title = new_ws["title"]
        if changes:
            ws.last_status, ws.last_title, ws.last_notified_at = ws.status, ws.title, now

    session.commit()
    session.expire(host, ["services"])
    return changes
