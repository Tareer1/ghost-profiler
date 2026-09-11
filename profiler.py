"""
profiler.py — turns raw scan output into a Watch Dogs-style device profile.

Profiles DEVICES, not people. Every field comes from network fingerprints
(open ports, banners, TTL, hostname) of machines you are authorized to scan.
"""

from oui import lookup_vendor, mac_type

# Ports that historically indicate weak/unencrypted/legacy services
RISKY_PORTS = {
    21:   ("FTP", "plaintext credentials possible"),
    23:   ("Telnet", "remote shell with NO encryption"),
    25:   ("SMTP", "open relay / enumeration risk"),
    69:   ("TFTP", "no auth, trivial file grab from device"),
    80:   ("HTTP", "unencrypted web interface"),
    110:  ("POP3", "plaintext mail credentials"),
    111:  ("RPC", "portmapper: enumerates NFS/NIS services"),
    139:  ("NetBIOS", "legacy Windows shares"),
    161:  ("SNMP", "default community strings common"),
    389:  ("LDAP", "often unauthenticated; anonymous enumeration"),
    445:  ("SMB", "historically exploited (EternalBlue family)"),
    514:  ("syslog UDP", "unencrypted log stream; spoofable"),
    515:  ("LPD", "legacy print service"),
    873:  ("Rsync", "module listing / unauthenticated sync if misconfigured"),
    1099: ("Java RMI", "deserialization attack surface"),
    1433: ("MSSQL", "database exposed on network"),
    2049: ("NFS", "exports may be world-readable"),
    2181: ("ZooKeeper", "frequently unauthenticated by default"),
    2375: ("Docker API", "remote root-equivalent REST, NO TLS by default"),
    2376: ("Docker API TLS", "verify cert config; often misdeployed"),
    2379: ("etcd", "cluster secrets/keys readable if unauthenticated"),
    3128: ("Squid proxy", "open proxy abuse / internal pivot"),
    3306: ("MySQL", "database exposed on network"),
    3389: ("RDP", "brute-force / BlueKeep family exposure"),
    5432: ("PostgreSQL", "database exposed on network"),
    5555: ("ADB", "Android debug bridge: full device control"),
    5601: ("Kibana", "dashboard/data exposure; default creds common"),
    5900: ("VNC", "often weak auth, no encryption"),
    5984: ("CouchDB", "admin party (no auth) by default"),
    6379: ("Redis", "frequently unauthenticated by default"),
    8086: ("InfluxDB", "metrics exposure; weak default auth"),
    8443: ("HTTPS-alt", "management interface over TLS of unknown config"),
    8883: ("MQTT TLS", "broker ACLs often weak"),
    9000: ("Portainer/PHP-FPM", "container/PHP management exposure"),
    9200: ("Elasticsearch", "data nodes frequently open, script abuse"),
    10250: ("kubelet", "container exec API; anonymous access known CVEs"),
    11211: ("Memcached", "UDP amplification + data leak"),
    1883: ("MQTT", "plaintext IoT messaging, weak auth"),
    9100: ("JetDirect", "printer raw protocol, firmware attacks"),
}

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    514: "Syslog", 515: "LPD", 631: "IPP", 873: "Rsync", 993: "IMAPS",
    995: "POP3S", 1099: "Java-RMI", 1433: "MSSQL", 1723: "PPTP", 1883: "MQTT",
    1900: "SSDP", 2049: "NFS", 2181: "ZooKeeper", 2375: "Docker-API",
    2376: "Docker-TLS", 2379: "etcd", 3128: "Squid", 3306: "MySQL",
    3389: "RDP", 5000: "HTTP-alt", 5432: "PostgreSQL", 5555: "ADB",
    5601: "Kibana", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    8080: "HTTP-alt", 8086: "InfluxDB", 8443: "HTTPS-alt", 8883: "MQTT-TLS",
    9000: "Portainer", 9100: "JetDirect", 9200: "Elasticsearch",
    10250: "kubelet", 11211: "Memcached", 49152: "Dynamic/UPnP",
}


def guess_os(ttl, open_ports, banner_text):
    """Coarse OS fingerprint from TTL + port personality."""
    text = (banner_text or "").lower()
    if any(k in text for k in ("windows", "iis", "microsoft")):
        return "Windows", "banner fingerprint"
    if any(k in text for k in ("ubuntu", "debian", "openssh", "nginx", "apache")):
        return "Linux", "banner fingerprint"
    if ttl is not None:
        if ttl <= 64:
            return "Linux/Unix-like", "TTL 1-64"
        if ttl <= 128:
            return "Windows", "TTL 65-128"
        return "Network appliance", "TTL 129-255"
    if 3389 in open_ports:
        return "Windows", "RDP exposed"
    if 22 in open_ports:
        return "Linux/Unix-like", "SSH exposed"
    return "Unknown", "no fingerprint"


def guess_device_type(open_ports, hostname):
    """Guess what KIND of machine this is (device, not person)."""
    name = (hostname or "").lower()
    if any(k in name for k in ("router", "gateway", "gw", "fritz", "openwrt")):
        return "Router/Gateway"
    if any(k in name for k in ("printer", "hp", "epson", "brother", "canon")):
        return "Printer"
    if any(k in name for k in ("nas", "synology", "truenas", "qnap")):
        return "NAS / Storage"
    if 9100 in open_ports or 631 in open_ports or 515 in open_ports:
        return "Printer"
    if 53 in open_ports and (80 in open_ports or 443 in open_ports):
        return "Router/Gateway"
    # Container orchestration: Docker/k8s/etcd management plane open
    if {2375, 2376, 2379, 10250} & set(open_ports):
        return "Container host"
    if 1900 in open_ports or 5000 in open_ports:
        return "IoT / Smart device"
    if 8080 in open_ports or (80 in open_ports and 22 not in open_ports):
        return "Web service / admin UI"
    if 3389 in open_ports and 445 in open_ports:
        return "Windows workstation/server"
    if 3306 in open_ports or 5432 in open_ports or 6379 in open_ports:
        return "Database server"
    if 22 in open_ports and len(open_ports) <= 3:
        return "Linux server / SBC"
    if 445 in open_ports or 139 in open_ports:
        return "Windows machine"
    return "Unknown device"


def risk_assessment(open_ports):
    """Score risk from exposed services. Returns (score 0-100, level, notes)."""
    score = 0
    notes = []
    for p in open_ports:
        if p in RISKY_PORTS:
            name, why = RISKY_PORTS[p]
            score += {"Telnet": 25, "VNC": 20, "Redis": 20, "SMB": 15,
                      "RDP": 12, "JetDirect": 10, "Docker API": 35,
                      "kubelet": 25, "ADB": 25, "etcd": 20,
                      "Memcached": 15, "Elasticsearch": 15,
                      "NFS": 12, "CouchDB": 15, "ZooKeeper": 12}.get(name, 8)
            notes.append(f"{name} ({p}): {why}")
    if len(open_ports) >= 8:
        score += 10
        notes.append("Large attack surface (many open ports)")
    score = min(score, 100)
    level = ("CRITICAL" if score >= 60 else "HIGH" if score >= 35
             else "MEDIUM" if score >= 15 else "LOW")
    return score, level, notes


def codename(ip, device_type, index):
    """Watch Dogs-style glitch tag for a device (devices only, never people)."""
    tag = {
        "Router/Gateway": "GATEKEEPER",
        "Printer": "PAPERJAM",
        "NAS / Storage": "DATAVAULT",
        "Database server": "SQLWRAITH",
        "Container host": "DOCKERFIEND",
        "Windows workstation/server": "BLUECOLLAR",
        "Windows machine": "BLUESCREEN",
        "Linux server / SBC": "PENGUINNODE",
        "Web service / admin UI": "WEBWRAITH",
        "IoT / Smart device": "BLINKSPY",
    }.get(device_type, "UNKNOWN")
    last_octet = ip.rsplit(".", 1)[-1] if "." in ip else ip
    return f"{tag}-{last_octet or index}"


def build_profile(host, open_ports, index=0):
    """host: {ip, ttl, hostname, mac}; open_ports: [{port, banner}]."""
    port_nums = [p["port"] for p in open_ports]
    banner_text = " ".join(p["banner"] for p in open_ports)
    os_guess, os_evidence = guess_os(host.get("ttl"), port_nums, banner_text)
    device_type = guess_device_type(port_nums, host.get("hostname"))
    score, level, risk_notes = risk_assessment(port_nums)
    services = [f"{SERVICE_NAMES.get(p['port'], '?')}:{p['port']}" + (f" [{p['banner'][:40]}]" if p["banner"] else "")
                for p in open_ports]
    return {
        "index": index,
        "codename": codename(host["ip"], device_type, index),
        "ip": host["ip"],
        "hostname": host.get("hostname") or "—",
        "mac": host.get("mac") or "—",
        "vendor": host.get("vendor") or "—",
        "mac_type": host.get("mac_type") or "unknown",
        "os": f"{os_guess} ({os_evidence})",
        "device_type": device_type,
        "open_ports": port_nums,
        "services": services or ["none detected"],
        "risk_score": score,
        "risk_level": level,
        "risk_notes": risk_notes,
    }


def posture_grade(profiles: list):
    """Grade the whole network A-F from device risk scores.

    MEDIUM devices weigh in too (+2 each), and the grade is floored at B
    while ANY device carries real findings — a single exposed router must
    not earn the network an 'A — Hardened'.
    """
    if not profiles:
        return "N/A", "No devices profiled"
    avg = sum(p["risk_score"] for p in profiles) / len(profiles)
    worst = max(p["risk_score"] for p in profiles)
    critical = sum(1 for p in profiles if p["risk_level"] == "CRITICAL")
    high = sum(1 for p in profiles if p["risk_level"] == "HIGH")
    medium = sum(1 for p in profiles if p["risk_level"] == "MEDIUM")
    score = avg + (critical * 15) + (high * 7) + (medium * 2) + (10 if worst >= 50 else 0)
    if score >= 70:
        grade, note = "F", "CRITICAL exposure — immediate remediation required"
    elif score >= 45:
        grade, note = "D", "Poor posture — significant exposed services"
    elif score >= 30:
        grade, note = "C", "Fair — several risks need attention"
    elif score >= 15:
        grade, note = "B", "Good posture — minor issues only"
    else:
        grade, note = "A", "Hardened network — minimal exposure"
    if grade == "A" and (critical or high or medium):
        grade, note = "B", "Good posture — but exposed services need attention"
    return grade, note


def enrich_vendor(host: dict):
    """Attach MAC vendor + type to a discovered host dict."""
    mac = host.get("mac")
    if mac and mac != "—":
        host["vendor"] = lookup_vendor(mac) or "unknown vendor"
        host["mac_type"] = mac_type(mac)
    else:
        host["vendor"] = None
        host["mac_type"] = None
    return host
