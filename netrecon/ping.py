"""Ping sweep module — ICMP-based host discovery.

Uses scapy for raw ICMP packets with a fallback to system ping.
Supports CIDR notation (192.168.1.0/24), IP ranges (192.168.0.1-200),
and single IPs (192.168.0.1).
"""

import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, ICMP, sr1, conf
    HAS_SCAPY = True
    # Quick test to see if scapy can actually use raw sockets
    _SCAPY_USABLE = False
    try:
        conf.verb = 0
        _test = IP(dst="127.0.0.1") / ICMP()
        _SCAPY_USABLE = True
    except Exception:
        _SCAPY_USABLE = False
except ImportError:
    HAS_SCAPY = False
    _SCAPY_USABLE = False


def _ping_host_scapy(ip: str, timeout: float) -> bool | None:
    """Ping a single host via scapy ICMP.

    Returns True if responsive, False if not, None if permission error.
    """
    try:
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        return reply is not None
    except PermissionError:
        logger.debug("scapy ping %s: permission denied (need root for raw sockets)", ip)
        return None
    except OSError as e:
        if "Operation not permitted" in str(e):
            logger.debug("scapy ping %s: %s", ip, e)
            return None
        logger.debug("scapy ping %s failed: %s", ip, e)
        return False
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
    """Ping a single host, returning True if responsive.

    Falls back to subprocess ping if scapy is unavailable or lacks
    raw socket permissions.
    """
    if use_scapy:
        result = _ping_host_scapy(ip, timeout)
        if result is not None:
            return result
        # scapy returned None (permission error), fall back to subprocess
    return _ping_host_subprocess(ip, timeout)


def parse_target(target: str) -> list[str]:
    """Parse a target specification into a sorted list of IPs.

    Supports:
      - CIDR:       `192.168.1.0/24`
      - Range:      `192.168.0.1-200`            (same first 3 octets)
      - Full range: `192.168.0.1-192.168.0.200`  (explicit start and end)
      - Single IP:  `192.168.0.1`

    Args:
        target: Network specification string

    Returns:
        Sorted list of IP addresses to scan
    """
    target = target.strip()

    # CIDR notation (contains /)
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation '{target}': {e}") from e

    # Range notation (contains -)
    if "-" in target:
        parts = target.split("-", 1)
        start_str = parts[0].strip()
        end_str = parts[1].strip()

        # Check if end is a full IP or just the last octet
        if "." in end_str and len(end_str.split(".")) == 4:
            # Full IP range: 192.168.0.1-192.168.0.200
            start_ip = ipaddress.ip_address(start_str)
            end_ip = ipaddress.ip_address(end_str)
        else:
            # Partial range: 192.168.0.1-200
            start_parts = start_str.split(".")
            if len(start_parts) != 4:
                raise ValueError(
                    f"Invalid range '{target}': start must be a full IP"
                )
            try:
                end_octet = int(end_str)
            except ValueError as e:
                raise ValueError(
                    f"Invalid range '{target}': '{end_str}' is not a valid number"
                ) from e
            if end_octet < 0 or end_octet > 255:
                raise ValueError(f"Invalid range '{target}': octet out of 0-255 range")
            base_prefix = ".".join(start_parts[:3])
            start_ip = ipaddress.ip_address(start_str)
            end_ip = ipaddress.ip_address(f"{base_prefix}.{end_octet}")

        if start_ip > end_ip:
            start_ip, end_ip = end_ip, start_ip

        return [str(ipaddress.ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]

    # Single IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError as e:
        raise ValueError(
            f"Invalid target '{target}'. Use CIDR (192.168.1.0/24), "
            f"range (192.168.0.1-200), or single IP."
        ) from e


def ping_sweep(
    target: str,
    timeout: float = 2.0,
    workers: int = 20,
    prefer_scapy: bool = True,
) -> list[str]:
    """Ping sweep a network range.

    Accepts CIDR notation (192.168.1.0/24), IP ranges (192.168.0.1-200),
    or single IPs. Automatically falls back to system ping if scapy
    lacks raw socket permissions.

    Args:
        target: Network in CIDR, range, or single IP format
        timeout: Seconds to wait for each ping reply
        workers: Max concurrent ping threads
        prefer_scapy: Use scapy ICMP if available (falls back to subprocess ping)

    Returns:
        Sorted list of responsive IP addresses
    """
    hosts = parse_target(target)

    use_scapy = prefer_scapy and _SCAPY_USABLE
    if use_scapy:
        logger.debug("Using scapy ICMP for ping sweep")
    else:
        logger.debug("Using system ping for ping sweep")

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