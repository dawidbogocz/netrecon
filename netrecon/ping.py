"""Ping sweep module — ICMP-based host discovery."""


def ping_sweep(network: str, timeout: float = 2.0, workers: int = 20) -> list[str]:
    """Ping sweep a CIDR network range. Returns list of responsive IPs."""
    return []