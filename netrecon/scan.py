"""Port scanner module — TCP Connect and SYN stealth scans."""

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017,
]


def tcp_connect_scan(
    host: str, ports: list[int], timeout: float = 1.0, workers: int = 50
) -> list[dict]:
    """TCP Connect scan. Returns list of {port, state, service} dicts."""
    return []


def syn_scan(host: str, ports: list[int], timeout: float = 1.0) -> list[dict]:
    """SYN stealth scan via scapy. Requires root. Returns list of {port, state, service}."""
    return []


def resolve_service(port: int) -> str:
    """Look up service name for a port number."""
    try:
        import socket
        return socket.getservbyport(port)
    except (OSError, ImportError):
        return ""