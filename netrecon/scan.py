"""Port scanner module — TCP Connect and SYN stealth scans.

Supports TCP Connect (full handshake, no root needed) and SYN stealth
(half-open via scapy, requires root/raw sockets).
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Well-known ports with service names
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017,
]

# IANA service names for common ports (fallback when socket.getservbyport fails)
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "epmap", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongod",
}


def resolve_service(port: int) -> str:
    """Look up service name for a port number."""
    if port < 0 or port > 65535:
        return ""
    try:
        return socket.getservbyport(port)
    except (OSError, ValueError):
        return PORT_SERVICES.get(port, "")


def _tcp_connect_port(host: str, port: int, timeout: float) -> dict:
    """Test a single port via TCP Connect."""
    result = {"port": port, "state": "closed", "service": resolve_service(port)}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))
        sock.close()
        if code == 0:
            result["state"] = "open"
        elif code == 111:
            result["state"] = "closed"
        elif code == 110:
            result["state"] = "filtered"
        else:
            result["state"] = "filtered"
    except socket.gaierror:
        result["state"] = "error"
    except OSError:
        result["state"] = "filtered"
    return result


def tcp_connect_scan(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 50,
) -> list[dict]:
    """TCP Connect port scan.

    Performs a full TCP three-way handshake on each port.
    Does not require root or raw socket privileges.

    Args:
        host: Target hostname or IP
        ports: List of ports to scan (None uses COMMON_PORTS)
        timeout: Seconds to wait per connection
        workers: Max concurrent connections

    Returns:
        List of dicts with port, state ('open'/'closed'/'filtered'), service
    """
    if ports is None:
        ports = COMMON_PORTS

    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_tcp_connect_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                logger.debug("Error scanning port %d on %s: %s", port, host, e)
                results.append({"port": port, "state": "error", "service": resolve_service(port)})

    results.sort(key=lambda r: r["port"])
    return results


def _syn_scan_port(host: str, port: int, timeout: float) -> dict:
    """Scan a single port via SYN stealth."""
    result = {"port": port, "state": "closed", "service": resolve_service(port)}
    try:
        conf.verb = 0
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        reply = sr1(pkt, timeout=timeout, verbose=0)

        if reply is None:
            result["state"] = "filtered"
        elif reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags & 0x12:  # SYN-ACK
                result["state"] = "open"
            elif flags & 0x14:  # RST-ACK
                result["state"] = "closed"
            else:
                result["state"] = "filtered"
        else:
            result["state"] = "filtered"
    except Exception as e:
        logger.debug("SYN scan port %d on %s error: %s", port, host, e)
        result["state"] = "error"
    return result


def syn_scan(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 20,
) -> list[dict]:
    """SYN stealth (half-open) port scan via scapy.

    Sends TCP SYN packets and reads SYN-ACK (open) or RST (closed) replies.
    Requires root/raw socket privileges for scapy.

    Args:
        host: Target hostname or IP
        ports: List of ports (None uses COMMON_PORTS)
        timeout: Seconds to wait per reply
        workers: Max concurrent probes

    Returns:
        List of dicts with port, state, service
    """
    if ports is None:
        ports = COMMON_PORTS
    if not HAS_SCAPY:
        logger.warning("scapy not available, falling back to TCP connect scan")
        return tcp_connect_scan(host, ports, timeout, workers)

    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_syn_scan_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                logger.debug("Error in SYN scan port %d: %s", port, e)
                results.append({"port": port, "state": "error", "service": resolve_service(port)})

    results.sort(key=lambda r: r["port"])
    return results


def parse_ports(port_spec: str) -> list[int]:
    """Parse a port specification into a list of ports.

    Supports:
        - "22,80,443" -> [22, 80, 443]
        - "1-1024" -> [1, 2, ..., 1024]
        - "22,80,1000-1010" -> [22, 80, 1000, ..., 1010]
        - "top-100" -> first 100 common ports
        - "top-1000" -> first 1000 common ports (returns 1-1024)
    """
    if not port_spec:
        return list(COMMON_PORTS)

    port_spec = port_spec.strip()
    ports: list[int] = []

    if port_spec.startswith("top-"):
        count = int(port_spec.split("-")[1])
        if count >= 1024:
            return list(range(1, count + 1))
        return COMMON_PORTS[: min(count, len(COMMON_PORTS))]

    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                logger.warning("Invalid port range: %s", part)
        else:
            try:
                ports.append(int(part))
            except ValueError:
                logger.warning("Invalid port: %s", part)

    return sorted(set(ports))