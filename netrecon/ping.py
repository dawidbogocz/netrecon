"""Ping sweep module — ICMP-based host discovery.

Uses scapy for raw ICMP packets with a fallback to system ping.
"""

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, ICMP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def _ping_host_scapy(ip: str, timeout: float) -> bool:
    """Ping a single host via scapy ICMP."""
    try:
        conf.verb = 0  # suppress scapy output
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        return reply is not None
    except Exception as e:
        logger.debug("scapy ping %s failed: %s", ip, e)
        return False


def _ping_host_subprocess(ip: str, timeout: float) -> bool:
    """Ping a single host via system ping command."""
    import subprocess
    import platform

    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-t", str(int(timeout)), ip]
    else:  # Linux
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _ping_host(ip: str, timeout: float, use_scapy: bool) -> bool:
    """Ping a single host, returning True if responsive."""
    if use_scapy:
        return _ping_host_scapy(ip, timeout)
    return _ping_host_subprocess(ip, timeout)


def ping_sweep(
    network: str,
    timeout: float = 2.0,
    workers: int = 20,
    prefer_scapy: bool = True,
) -> list[str]:
    """Ping sweep a CIDR network range.

    Args:
        network: CIDR notation (e.g. "192.168.1.0/24")
        timeout: Seconds to wait for each ping reply
        workers: Max concurrent ping threads
        prefer_scapy: Use scapy ICMP if available (falls back to subprocess ping)

    Returns:
        Sorted list of responsive IP addresses
    """
    network_obj = ipaddress.ip_network(network, strict=False)
    hosts = [str(ip) for ip in network_obj.hosts()]

    use_scapy = prefer_scapy and HAS_SCAPY
    if not use_scapy and not HAS_SCAPY:
        logger.info("scapy not available, using system ping")

    responsive: list[str] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_ping_host, ip, timeout, use_scapy): ip
            for ip in hosts
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    responsive.append(ip)
            except Exception as e:
                logger.debug("Error pinging %s: %s", ip, e)

    responsive.sort(
        key=lambda ip: tuple(int(octet) for octet in ip.split("."))
    )
    return responsive