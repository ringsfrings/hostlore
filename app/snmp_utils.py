from pysnmp.hlapi import *

DEFAULT_COMMUNITIES = ['public', 'private', 'public123']

OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysName':  '1.3.6.1.2.1.1.5.0',
    # UCD-SNMP (Linux) CPU idle and mem used – best-effort
    'cpu':      '1.3.6.1.4.1.2021.11.9.0',
    'ram':      '1.3.6.1.4.1.2021.4.6.0'
}

def try_snmp(ip, oid, community):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip, 161), timeout=1.2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
        )
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return None

def get_snmp_info(ip):
    """Returns (os_hint, cpu, ram, sys_name) best-effort."""
    for community in DEFAULT_COMMUNITIES:
        results = {}
        for key, oid in OIDS.items():
            results[key] = try_snmp(ip, oid, community)
        if any(results.values()):
            os_hint = results.get('sysDescr') or None
            return os_hint, results.get('cpu'), results.get('ram'), results.get('sysName')
    return None, None, None, None
