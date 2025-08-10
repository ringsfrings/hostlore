# app/fallback_utils.py (

import socket
import subprocess
import re
import shutil
import ipaddress
import logging
from typing import Optional

LOG = logging.getLogger(__name__)

# Resolve executables once at import time (None if not found)
NMBLOOKUP_BIN = shutil.which("nmblookup")
NMAP_BIN = shutil.which("nmap")

GENERIC_TITLES = {"RTK Web 0.9", "Router", "Login", "Home", "Welcome"}


def _is_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def netbios_name(ip: str) -> Optional[str]:
    """
    Try NetBIOS (Windows) name. Requires nmblookup installed.
    """
    if not _is_ip(ip) or not NMBLOOKUP_BIN:
        return None
    try:
        out = subprocess.check_output(
            [NMBLOOKUP_BIN, "-A", ip],
            timeout=3
        ).decode(errors="ignore")
        # First non-<GROUP> <00> entry is often the host name
        for line in out.splitlines():
            # Example: MYPC           <00>  -  M <ACTIVE>
            if "<00>" in line and "<GROUP>" not in line:
                name = line.split()[0].strip()
                if name and name.upper() != "MAC":
                    return name
    except subprocess.TimeoutExpired:
        LOG.warning("nmblookup timed out for %s", ip)
    except Exception as e:
        LOG.debug("nmblookup failed for %s: %s", ip, e)
    return None


def smb_os_discovery(ip: str) -> Optional[str]:
    """
    Run nmap smb-os-discovery script on port 445 to fingerprint Windows.
    """
    if not _is_ip(ip) or not NMAP_BIN:
        return None
    try:
        proc = subprocess.run(
            [
                NMAP_BIN, "-n", "-p", "445",
                "--script", "smb-os-discovery",
                "-oX", "-", ip, "-T4", "--host-timeout", "20s", "-Pn"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False
        )
        xml = proc.stdout.decode(errors="ignore")
        # Extract "OS: ..." via a simple regex from XML text for safety
        m = re.search(r"(?:OS:\s*)([^\r\n<]+)", xml, flags=re.IGNORECASE)
        if m:
            return m.group(1).strip()
    except subprocess.TimeoutExpired:
        LOG.warning("nmap smb-os-discovery timed out for %s", ip)
    except Exception as e:
        LOG.debug("nmap smb-os-discovery failed for %s: %s", ip, e)
    return None


def http_headers_os(ip: str) -> Optional[str]:
    """
    Hit http://<ip> HEAD and try to use the Server header as a weak OS hint.
    """
    if not _is_ip(ip):
        return None
    try:
        import requests
        r = requests.head(f"http://{ip}", timeout=2)
        server = r.headers.get("Server")
        if server:
            return server.strip()
    except Exception as e:
        LOG.debug("http_headers_os failed for %s: %s", ip, e)
    return None


def upnp_ssdp_friendlyname(ip: str) -> Optional[str]:
    """
    Send a basic SSDP M-SEARCH to port 1900/udp and try to read a friendly name.
    Only works on same LAN segments typically.
    """
    if not _is_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        ).encode()
        sock.sendto(msg, ("239.255.255.250", 1900))
        # Many devices reply from their IP; read a couple of responses
        for _ in range(3):
            data, (rip, _rport) = sock.recvfrom(8192)
            if rip == ip:
                text = data.decode(errors="ignore")
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
    except socket.timeout:
        pass
    except Exception as e:
        LOG.debug("SSDP query failed for %s: %s", ip, e)
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
    return None
