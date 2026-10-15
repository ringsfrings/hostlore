"""Pure-function tests for scanner.py — no nmap, no network, no DB."""
from app.scanner import (
    _extract_title,
    _infer_os_family,
    _os_family_from_ttl,
    _parse_ports_from_xml,
    _pick_http_candidates,
    _scan_completed,
)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" tunnel="ssl"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x"/>
      <osclass><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass>
    </os>
  </host>
</nmaprun>
"""


def test_parse_ports_returns_only_open():
    services, os_guess, cpes = _parse_ports_from_xml(SAMPLE_XML)
    ports = {s["port"] for s in services}
    assert 22 in ports
    assert 443 in ports
    assert 80 not in ports  # closed → filtered
    assert os_guess == "Linux 5.x"
    assert any("cpe:/o:linux" in c for c in cpes)


def test_parse_ports_captures_service_metadata():
    services, _, _ = _parse_ports_from_xml(SAMPLE_XML)
    ssh = next(s for s in services if s["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.2"

    https = next(s for s in services if s["port"] == 443)
    assert https["tunnel"] == "ssl"


def test_parse_ports_handles_empty_and_malformed():
    assert _parse_ports_from_xml("") == ([], "Unknown", [])
    assert _parse_ports_from_xml("<not>xml</not>") == ([], "Unknown", [])


def test_pick_http_candidates_recognizes_standard_ports():
    services = [
        {"proto": "tcp", "port": 8080, "service": "http", "tunnel": ""},
        {"proto": "tcp", "port": 443, "service": "https", "tunnel": "ssl"},
        {"proto": "tcp", "port": 22, "service": "ssh", "tunnel": ""},
    ]
    cps = _pick_http_candidates(services)
    assert ("http", 8080) in cps
    assert ("https", 443) in cps
    assert not any(port == 22 for _scheme, port in cps)


def test_pick_http_candidates_empty_when_no_web_service():
    """Regression: previous code always returned [('http', 80)] as fallback,
    which caused blind probes to every host on port 80."""
    services = [{"proto": "tcp", "port": 22, "service": "ssh", "tunnel": ""}]
    assert _pick_http_candidates(services) == []


def test_pick_http_candidates_deduplicates():
    services = [
        {"proto": "tcp", "port": 80, "service": "http", "tunnel": ""},
        {"proto": "tcp", "port": 80, "service": "http", "tunnel": ""},
    ]
    assert _pick_http_candidates(services) == [("http", 80)]


def test_infer_os_family_windows_by_smb_port():
    services = [{"proto": "tcp", "port": 445, "service": "microsoft-ds"}]
    assert _infer_os_family(None, services, None, "Windows Server 2019", None, "MYPC") == "Windows"


def test_infer_os_family_linux_by_openssh():
    services = [{"proto": "tcp", "port": 22, "service": "ssh", "product": "OpenSSH"}]
    assert _infer_os_family(None, services, "Linux 5.4 Ubuntu", None, None, None) == "Linux"


def test_infer_os_family_unknown_when_no_signals():
    assert _infer_os_family(None, [], None, None, None, None) == "Unknown"


def test_infer_os_family_windows_by_cpe():
    services = [{"proto": "tcp", "port": 8080, "service": "http",
                 "product": "IIS", "cpes": ["cpe:/o:microsoft:windows_server_2019"]}]
    assert _infer_os_family(None, services, None, None, None, None) == "Windows"


class _Resp:
    def __init__(self, body, ctype="text/html; charset=utf-8"):
        self.content = body.encode()
        self.encoding = "utf-8"
        self.headers = {"Content-Type": ctype}


def test_extract_title_reads_html_title():
    assert _extract_title(_Resp("<html><head><title> Lab Web 1 </title></head></html>")) == "Lab Web 1"


def test_extract_title_none_for_non_html_or_missing():
    assert _extract_title(_Resp('{"a": 1}', ctype="application/json")) is None
    assert _extract_title(_Resp("<html><body>no title</body></html>")) is None
    assert _extract_title(_Resp("<title></title>")) is None


def test_scan_completed_rejects_timeouts_and_garbage():
    ok = '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="22"/></ports></host></nmaprun>'
    timed_out = '<nmaprun><host timedout="true"><status state="up"/></host></nmaprun>'
    assert _scan_completed(ok) is True
    assert _scan_completed(timed_out) is False      # nmap --host-timeout: exit 0, no ports
    assert _scan_completed("") is False             # killed by our own timeout
    assert _scan_completed("<nmaprun>") is False    # truncated XML
    assert _scan_completed("<nmaprun></nmaprun>") is False


def test_os_family_from_ttl():
    assert _os_family_from_ttl([{"ttl": 64}]) == "Linux/Unix"
    assert _os_family_from_ttl([{"ttl": 61}]) == "Linux/Unix"      # 3 hops away
    assert _os_family_from_ttl([{"ttl": 128}, {"ttl": 127}]) == "Windows"
    assert _os_family_from_ttl([{"ttl": 254}]) == "Network device"
    assert _os_family_from_ttl([{"ttl": 0}]) == "Unknown"           # connect scan: not measured
    assert _os_family_from_ttl([]) == "Unknown"


def test_infer_os_family_falls_back_to_ttl():
    nginx_only = [{"port": 80, "service": "http", "product": "nginx", "version": "1.27", "cpes": [], "ttl": 64}]
    assert _infer_os_family(None, nginx_only, None, None, None, None) == "Linux/Unix"
