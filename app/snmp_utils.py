"""
Best-effort SNMP fetch. Designed to bail fast on unresponsive hosts so a full
/24 scan doesn't spend minutes on SNMP timeouts.
"""
import logging

from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
)

LOG = logging.getLogger("snmp")

DEFAULT_COMMUNITIES = ("public", "private", "public123")

OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName":  "1.3.6.1.2.1.1.5.0",
    # UCD-SNMP (Linux) — best-effort, silently ignored on other stacks.
    "cpu":      "1.3.6.1.4.1.2021.11.9.0",
    "ram":      "1.3.6.1.4.1.2021.4.6.0",
}

# One short attempt per community. On a /24 with mostly non-SNMP hosts:
#   worst case per host = len(DEFAULT_COMMUNITIES) * SNMP_TIMEOUT_SECONDS  (~1.8s)
#   previous code:      = 3 * 4 * 1.2s + retries ≈ 14s
SNMP_TIMEOUT_SECONDS = 0.6
SNMP_RETRIES = 0

_NO_OBJECT_MSG = "No Such Object currently exists at this OID"


def _snmp_get(ip: str, oid: str, community: str) -> str | None:
    try:
        error_indication, error_status, _error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT_SECONDS, retries=SNMP_RETRIES),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )
    except Exception as e:
        LOG.debug("snmp %s %s error: %s", ip, oid, e)
        return None

    if error_indication or error_status:
        return None

    for var_bind in var_binds:
        value = str(var_bind[1])
        if value and value != _NO_OBJECT_MSG:
            return value
    return None


def _find_working_community(ip: str) -> tuple[str, str] | None:
    """Probe sysDescr with each community. Return (community, value) on the first hit."""
    for community in DEFAULT_COMMUNITIES:
        value = _snmp_get(ip, OIDS["sysDescr"], community)
        if value:
            return community, value
    return None


def get_snmp_info(ip: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Returns (os_hint, cpu, ram, sys_name). All-None if the host doesn't answer SNMP."""
    found = _find_working_community(ip)
    if not found:
        return None, None, None, None
    community, sys_descr = found

    sys_name = _snmp_get(ip, OIDS["sysName"], community)
    cpu = _snmp_get(ip, OIDS["cpu"], community)
    ram = _snmp_get(ip, OIDS["ram"], community)
    return sys_descr, cpu, ram, sys_name
