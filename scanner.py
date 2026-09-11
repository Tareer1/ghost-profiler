"""
scanner.py — host discovery + TCP port scanning for the Ghost Profiler.

Pure stdlib (socket + system ping). Only use against networks you own
or are explicitly authorized to test.
"""

import ipaddress
import platform
import re
import socket
import subprocess
import threading
import concurrent.futures

# Ports probed for liveness when ICMP is blocked
TCP_LIVENESS_PORTS = [80, 443, 22, 445, 3389, 8080, 53, 2375, 9100]

# TCP-only: a connect() scan cannot detect UDP services (TFTP 69, syslog 514,
# SNMP 161-udp, MQTT could be either) — those stay in RISKY_PORTS as a
# fingerprinting safety net but are not probed here.
DEFAULT_PORT_LIST = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    515, 631, 873, 993, 995, 1099, 1433, 1723, 1883, 1900, 2049, 2181,
    2375, 2376, 2379, 3128, 3306, 3389, 5000, 5432, 5555, 5601, 5900, 5984,
    6379, 8080, 8086, 8443, 8883, 9000, 9100, 9200, 10250, 11211, 49152,
]

_fast_ports = [22, 80, 443, 445, 3389, 8080, 3306, 5900, 2375, 9100]

IS_WINDOWS = platform.system().lower() == "windows"


def detect_local_cidr() -> str:
    """Best-effort detection of the local /24 network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return f"{local_ip}/24"


def _ping(ip: str, timeout_s: int = 1):
    """ICMP ping via system binary. Returns TTL (int) or None."""
    flag_count = "-n" if IS_WINDOWS else "-c"
    flag_wait = "-w" if IS_WINDOWS else "-W"
    try:
        out = subprocess.run(
            ["ping", flag_count, "1", flag_wait, str(timeout_s), str(ip)],
            capture_output=True, text=True, timeout=timeout_s + 3,
        ).stdout
    except Exception:
        return None
    m = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
    return int(m.group(1)) if m else (None if "ttl" not in out.lower() else None)


def _tcp_alive(ip: str, timeout: float = 0.4):
    """Fallback liveness: try a few common TCP ports."""
    for port in TCP_LIVENESS_PORTS:
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                if s.connect_ex((str(ip), port)) == 0:
                    return True
        except OSError:
            continue
    return False


def _arp_table() -> dict:
    """Read IP -> MAC from the system ARP table (best effort)."""
    table = {}
    if not IS_WINDOWS:
        try:
            with open("/proc/net/arp") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
                        table[parts[0]] = parts[3].upper()
        except OSError:
            pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).{1,40}?([0-9a-fA-F:]{12,17})", line)
            if m:
                table.setdefault(m.group(1), m.group(2).upper())
    except Exception:
        pass
    return table


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Pull a service banner; for HTTP(S) try to extract the page title."""
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((str(ip), port))
            if port == 443 or port == 8443:
                # TLS: read cert/first bytes for a hint (no full handshake parse)
                data = s.recv(128)
                return ("TLS/SSL service: " + data.hex()[:24] + "...") if data else "TLS/SSL service"
            if port in (80, 8080, 5000, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: profiler\r\n\r\n")
                data = s.recv(2048)
                text = data.decode("utf-8", "ignore")
                server = re.search(r"(?i)server:\s*(.+)", text)
                title = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
                parts = []
                if server:
                    parts.append("Server: " + server.group(1).strip()[:40])
                if title:
                    parts.append("Title: " + title.group(1).strip()[:40])
                return " | ".join(parts) if parts else text.strip().replace("\n", " | ")[:80]
            data = s.recv(128)
            return data.decode("utf-8", "ignore").strip().replace("\n", " | ")[:80]
    except OSError:
        return ""


def scan_ports(ip: str, ports=None, timeout: float = 0.8, workers: int = 120) -> list:
    """TCP connect scan. Returns [{port, banner}] for open ports."""
    ports = ports or DEFAULT_PORT_LIST
    results = []

    def probe(port):
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                if s.connect_ex((str(ip), port)) == 0:
                    results.append({"port": port, "banner": grab_banner(ip, port, timeout)})
        except OSError:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(probe, ports))
    return sorted(results, key=lambda r: r["port"])


def discover_hosts(cidr: str, progress_cb=None) -> list:
    """
    Sweep a CIDR for live hosts.

    Returns [{ip, ttl, hostname, mac}].
    progress_cb(done, total, host_or_None) is called after each host.
    """
    net = ipaddress.ip_network(cidr if "/" in cidr else f"{cidr}/32", strict=False)
    hosts = [h for h in net.hosts()] or [net.network_address]
    live = []
    done = 0
    lock = threading.Lock()

    def check(ip):
        nonlocal done
        ttl = _ping(str(ip))
        alive = ttl is not None or _tcp_alive(str(ip))
        with lock:
            done += 1
            local_done = done
        if alive:
            host = {"ip": str(ip), "ttl": ttl, "hostname": None, "mac": None}
            if progress_cb:
                progress_cb(local_done, len(hosts), host)
            return host
        if progress_cb:
            progress_cb(local_done, len(hosts), None)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for result in ex.map(check, hosts):
            if result:
                live.append(result)

    # Enrich: reverse DNS + MAC
    arp = _arp_table()
    for host in live:
        try:
            host["hostname"] = socket.gethostbyaddr(host["ip"])[0]
        except (socket.herror, OSError):
            pass
        host["mac"] = arp.get(host["ip"])
    return live


def probe_host(ip: str) -> dict | None:
    """
    Deep-probe ONE host with the same enrichment as discover_hosts():
    ICMP ping (TTL) + TCP liveness fallback, reverse DNS, ARP MAC.

    Returns {ip, ttl, hostname, mac} or None if unreachable.
    """
    ttl = _ping(str(ip))
    alive = ttl is not None or _tcp_alive(str(ip))
    arp = _arp_table()  # fetched AFTER liveness probes so TCP connects populate it
    if not alive and not arp.get(str(ip)):
        return None
    host = {"ip": str(ip), "ttl": ttl, "hostname": None, "mac": arp.get(str(ip))}
    try:
        host["hostname"] = socket.gethostbyaddr(host["ip"])[0]
    except (socket.herror, OSError):
        pass
    return host
