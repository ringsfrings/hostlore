import os, socket, threading, time, uuid, xml.etree.ElementTree as ET, subprocess, ssl, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

from db.models import Host, Service, Website, init_db, get_session
from app.config_loader import load_config
from app.snmp_utils import get_snmp_info
from app.fallback_utils import netbios_name, smb_os_discovery, upnp_ssdp_friendlyname, http_headers_os
from app.telegram import send_scan_alert

LOG = logging.getLogger("scanner")

# ----------- State -----------
SCAN_LOCK = threading.Lock()
CANCEL_EVENT = threading.Event()
SCAN_THREAD = None
ACTIVE_PIDS = set()
SCAN_STATE = {
    "scan_id": None, "running": False, "cancelling": False,
    "current": 0, "total": 0, "message": "Idle", "last_error": "",
    "profile": "quick", "eta_seconds": None, "last_host": None,
}

PROFILES = {
    "quick":    {"tcp": ["-sV", "--top-ports", "2000"], "udp": None,                     "timeout": 45,  "workers": 6},
    "balanced": {"tcp": ["-sV", "-p-"],                 "udp": None,                     "timeout": 90,  "workers": 8},
    "deep":     {"tcp": ["-sV", "-p-"],                 "udp": ["-sU", "--top-ports", "200"], "timeout": 120, "workers": 8},
}
HTTP_PORTS = {80, 8080, 8000, 8888, 3000}
HTTPS_PORTS = {443, 8443}

# ----------- Helpers -----------
def _set_state(**kw):
    with SCAN_LOCK:
        SCAN_STATE.update(kw)

def _add_pid(pid: int):
    with SCAN_LOCK:
        ACTIVE_PIDS.add(pid)

def _remove_pid(pid: int):
    with SCAN_LOCK:
        ACTIVE_PIDS.discard(pid)

def _kill_active_pids():
    with SCAN_LOCK:
        pids = list(ACTIVE_PIDS)
    for pid in pids:
        try: os.killpg(pid, 15)
        except ProcessLookupError: pass
    time.sleep(0.5)
    with SCAN_LOCK:
        pids2 = list(ACTIVE_PIDS)
    for pid in pids2:
        try: os.killpg(pid, 9)
        except ProcessLookupError: pass

def reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return None

def http_request(method, url, headers=None, timeout=3, verify=False, tries=2, allow_redirects=True):
    for i in range(max(1, tries)):
        try:
            return requests.request(method, url, headers=headers, timeout=timeout, verify=verify, allow_redirects=allow_redirects)
        except Exception:
            if i == tries - 1: return None
            time.sleep(0.4 * (i + 1))
    return None

def get_tls_names(ip, port=443):
    names = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=2) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                subj = dict(x[0] for x in cert.get("subject", []))
                if "commonName" in subj: names.append(subj["commonName"])
                for _typ, n in cert.get("subjectAltName", []):
                    if _typ.lower() == "dns": names.append(n)
    except Exception:
        pass
    return list(dict.fromkeys(names))

def _run_nmap(args, timeout=120):
    if CANCEL_EVENT.is_set(): return ""
    cmd = ["nmap"] + args + ["-oX", "-", "-n"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    _add_pid(proc.pid)
    try:
        out, err = proc.communicate(timeout=timeout)
        return out.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        try: os.killpg(proc.pid, 9)
        except Exception: pass
        return ""
    finally:
        _remove_pid(proc.pid)

def _discover_up_hosts(cidr: str) -> list:
    args = ["-sn", "-PR", "-PE", "-PA80,443", "--max-retries", "1", "--host-timeout", "10s", cidr]
    xml = _run_nmap(args, timeout=60)
    up = []
    if not xml: return up
    try:
        root = ET.fromstring(xml)
        for h in root.findall("host"):
            status = h.find("status")
            if status is not None and status.get("state") == "up":
                addr = h.find("address")
                if addr is not None and addr.get("addrtype") in ("ipv4", "ipv6"):
                    up.append(addr.get("addr"))
    except ET.ParseError:
        pass
    return up

def _parse_ports_from_xml(xml: str):
    services, os_guess, os_cpes = [], "Unknown", []
    if not xml: return services, os_guess, os_cpes
    try:
        root = ET.fromstring(xml)
        # OS (if present)
        for c in root.findall(".//os/osmatch"):
            if c.get("name"): os_guess = c.get("name")
            # cpe under osclass
        for c in root.findall(".//os/osclass/cpe"):
            if c.text: os_cpes.append(c.text.strip())
        # Ports
        for p in root.findall(".//port"):
            proto = p.get("protocol") or "tcp"
            portid = int(p.get("portid") or 0)
            state_el = p.find("state")
            if state_el is None or state_el.get("state") != "open": continue
            svc_el = p.find("service")
            name = svc_el.get("name") if svc_el is not None else ""
            product = svc_el.get("product") if svc_el is not None else ""
            version = svc_el.get("version") if svc_el is not None else ""
            tunnel = svc_el.get("tunnel") if svc_el is not None else ""
            cpes = [cpe.text for cpe in (svc_el.findall("cpe") if svc_el is not None else []) if cpe.text]
            services.append({
                "proto": proto, "port": portid, "service": name,
                "product": product, "version": version, "state": "open",
                "tunnel": tunnel, "cpes": cpes
            })
    except ET.ParseError:
        pass
    return services, os_guess, os_cpes

def _pick_http_candidates(services):
    cps = []
    for s in services:
        if s["proto"] != "tcp": continue
        p = s["port"]; name = (s["service"] or "").lower(); tun = (s.get("tunnel") or "").lower()
        if p in HTTP_PORTS or "http" in name: cps.append(("http", p))
        if p in HTTPS_PORTS or "https" in name or tun in ("ssl","tls"): cps.append(("https", p))
    seen = set(); out=[]
    for sc, pt in cps:
        if (sc, pt) not in seen: seen.add((sc, pt)); out.append((sc, pt))
    return out or [("http", 80)]

def _fetch_title(ip, scheme, port, host_header=None):
    base = f"{scheme}://{ip}"
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443): base += f":{port}"
    headers = {"Host": host_header} if host_header else None
    r = http_request("HEAD", base, headers=headers, timeout=2, verify=False, tries=2)
    if not r or r.status_code >= 400:
        r = http_request("GET", base, headers=headers, timeout=3, verify=False, tries=1)
    if not r: return None
    final = r.url; title = None
    try:
        body = r.text or ""
        if not body and r.headers.get("Content-Length", "0") == "0":
            r2 = http_request("GET", final, headers=headers, timeout=3, verify=False, tries=1)
            body = (r2.text if r2 else "") or ""
        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.string.strip() if soup.title else None
    except Exception:
        pass
    return {"ok": (r.status_code < 400), "url": final, "title": title}

def _discover_website(ip, services, hostname_candidates, tls_names):
    candidates = _pick_http_candidates(services)
    names = [n for n in hostname_candidates + tls_names if n]
    # IP pass
    for scheme, port in candidates:
        meta = _fetch_title(ip, scheme, port)
        if meta and meta["ok"]: return meta
    # Host header pass (vhosts)
    for scheme, port in candidates:
        for host_header in names:
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
    """Heuristics to classify as Windows / Linux / Other."""
    text = " ".join([
        (nmap_os or ""), (snmp_descr or ""), (smb_os or ""), (http_server or ""), (nb_name or ""),
        " ".join([f"{s.get('service','')} {s.get('product','')} {s.get('version','')} {' '.join(s.get('cpes',[]))}" for s in (services or [])])
    ]).lower()

    # Strong Windows indicators
    if any(x in text for x in ["windows", "microsoft", "msrpc", "workgroup"]) \
       or any(s.get("port") in (445, 3389) for s in services or []):
        return "Windows"
    # Strong Linux/Unix indicators
    if "linux" in text or "ubuntu" in text or "debian" in text or "centos" in text or "openssh" in text or "dropbear" in text:
        return "Linux"
    # CPE hints
    if any("cpe:/o:microsoft" in " ".join(s.get("cpes",[])).lower() for s in services or []):
        return "Windows"
    if any("cpe:/o:linux" in " ".join(s.get("cpes",[])).lower() for s in services or []):
        return "Linux"
    return "Unknown"

def _scan_one_host(ip: str, profile: str, priv_root: bool, per_host_timeout: int):
    prof = PROFILES[profile]
    base = ["-T4", "--max-retries", "1", "-Pn"]
    if priv_root: base = ["-sS", "-O"] + base
    else:         base = ["-sT"] + base

    tcp_xml = _run_nmap(base + (prof["tcp"] or []) + [ip], timeout=per_host_timeout)
    tcp_services, nmap_os, os_cpes = _parse_ports_from_xml(tcp_xml)
    udp_services = []
    if prof["udp"]:
        udp_xml = _run_nmap(base + (prof["udp"] or []) + [ip], timeout=max(30, per_host_timeout))
        u_svc, _, _ = _parse_ports_from_xml(udp_xml)
        udp_services = u_svc

    services = tcp_services + udp_services
    has_445 = any(s["proto"] == "tcp" and s["port"] == 445 for s in services)

    ptr = reverse_dns(ip)
    snmp_descr, snmp_cpu, snmp_ram, snmp_sysname = get_snmp_info(ip)
    nb_name = netbios_name(ip) if has_445 else None
    smb_os = smb_os_discovery(ip) if has_445 else None
    ssdp_server = upnp_ssdp_friendlyname(ip) if any(s["proto"] == "udp" and s["port"] == 1900 for s in services) else None
    http_server = http_headers_os(ip)
    tls_names = get_tls_names(ip, 443) if any(s["proto"] == "tcp" and s["port"] in HTTPS_PORTS for s in services) else []

    hostname = ptr or snmp_sysname or nb_name or "Unknown"
    # OS family inference (works even without root -O)
    fam = _infer_os_family(nmap_os if priv_root else None, services, snmp_descr, smb_os, http_server, nb_name)
    os_name = fam if fam != "Unknown" else (snmp_descr or smb_os or nmap_os or http_server or ssdp_server or "Unknown")

    host_candidates = [ptr, snmp_sysname, nb_name]
    web = _discover_website(ip, services, host_candidates, tls_names)
    website = {"url": f"http://{ip}", "status": False, "title": None}
    if web: website.update({"url": web["url"], "status": bool(web["ok"]), "title": web["title"]})

    return {
        "ip": ip, "hostname": hostname, "os": os_name,
        "cpu": snmp_cpu, "ram": snmp_ram,
        "website": website, "services": services,
    }

# ----------- Public API -----------
def start_scan_background(options=None):
    opts = options or {}
    profile = (opts.get("profile") or "quick").lower()
    if profile not in PROFILES: profile = "quick"

    global SCAN_THREAD
    with SCAN_LOCK:
        if SCAN_STATE["running"]: return False
        SCAN_STATE.update({
            "scan_id": str(uuid.uuid4()), "running": True, "cancelling": False,
            "current": 0, "total": 0, "message": "Discovering hosts…", "last_error": "",
            "profile": profile, "eta_seconds": None, "last_host": None,
        })
        CANCEL_EVENT.clear()

    t = threading.Thread(target=_worker, args=(profile,), name="netscanner-worker", daemon=True)
    t.start(); SCAN_THREAD = t
    return True

def cancel_scan():
    CANCEL_EVENT.set(); _kill_active_pids()
    _set_state(cancelling=True, message="Cancelling…")

def scan_status():
    with SCAN_LOCK:
        return dict(SCAN_STATE)

# ----------- Worker -----------
def _worker(profile: str):
    ema = None
    try:
        cfg = load_config() or {}
        ip_range = (cfg.get("app") or {}).get("ip_range", "192.168.1.0/24")
        init_db(); session = get_session()

        up_hosts = _discover_up_hosts(ip_range)
        total = len(up_hosts)
        _set_state(total=total, message=f"Found {total} host(s) up")
        if CANCEL_EVENT.is_set(): _set_state(message="Cancelled during discovery"); return
        if total == 0: _set_state(message="No hosts up in range", current=0); return

        try: priv_root = (os.geteuid() == 0)
        except Exception: priv_root = False

        per_host_timeout = PROFILES[profile]["timeout"]
        workers = PROFILES[profile]["workers"]
        done = 0; _set_state(message=f"Scanning {total} host(s)…")

        def task(ip):
            t0 = time.time()
            try:
                if CANCEL_EVENT.is_set(): return None
                return _scan_one_host(ip, profile, priv_root, per_host_timeout)
            finally:
                nonlocal ema
                dt = max(0.1, time.time() - t0)
                ema = dt if ema is None else (0.3 * dt + 0.7 * ema)

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(task, ip): ip for ip in up_hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                if CANCEL_EVENT.is_set(): break
                data = None
                try: data = fut.result()
                except Exception as e: LOG.warning("host %s error: %s", ip, e)

                done += 1
                eta = int(max(0, (total - done) * (ema or 0)))
                _set_state(current=done, last_host=ip, eta_seconds=eta, message=f"Scanning {ip} — {done}/{total}")

                if not data: continue

                # DB write
                host = session.query(Host).filter_by(ip=data["ip"]).first()
                if not host:
                    from db.models import Host as H
                    host = H(ip=data["ip"]); session.add(host); session.flush()
                host.hostname = data["hostname"]; host.os = data["os"]
                if data["cpu"]: host.cpu = data["cpu"]
                if data["ram"]: host.ram = data["ram"]

                session.query(Service).filter_by(host_id=host.id).delete()
                for s in data["services"]:
                    session.add(Service(
                        proto=s.get("proto","tcp"), port=s["port"], service=s.get("service",""),
                        product=s.get("product",""), version=s.get("version",""),
                        state=s.get("state","open"), host_id=host.id
                    ))

                prev_ws = session.query(Website).filter_by(host_id=host.id).one_or_none()
                if prev_ws is None:
                    ws = Website(url=data["website"]["url"], status=data["website"]["status"],
                                 title=data["website"]["title"], host_id=host.id)
                    session.add(ws)
                else:
                    prev_ws.url = data["website"]["url"]
                    prev_ws.status = data["website"]["status"]
                    prev_ws.title = data["website"]["title"]

                session.commit()

                # ALERT for every host every scan (your request)
                try:
                    send_scan_alert(
                        ip=data["ip"], hostname=data["hostname"], os_name=data["os"],
                        website=data["website"], services=data["services"]
                    )
                except Exception as e:
                    LOG.warning("Telegram send failed for %s: %s", data["ip"], e)

        if CANCEL_EVENT.is_set(): _set_state(message=f"Scan cancelled — {done}/{total}")
        else: _set_state(message=f"Scan complete — {total}/{total}", current=total)

    except Exception as e:
        _set_state(last_error=str(e), message="Scan error")
        LOG.exception("fatal scan error")
    finally:
        _kill_active_pids(); _set_state(running=False, cancelling=False)
