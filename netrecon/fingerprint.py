"""OS fingerprinting module — TTL and TCP window size analysis.

Detects operating system by analyzing TTL values and TCP window sizes
from network responses. Uses scapy for raw packet capture with a TTL
fallback from ping.
"""

import logging
import subprocess
import platform
import re

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, sr1, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Known OS signatures (TTL, TCP window size)
# Source: Nmap OS fingerprint DB, IANA assigned TTL values
OS_SIGNATURES: list[dict] = [
    {"name": "Linux", "ttl": 64, "window_range": (5800, 65535), "confidence": 85},
    {"name": "Windows 10/11/Server", "ttl": 128, "window_range": (64240, 65535), "confidence": 85},
    {"name": "Windows 7/8/2008", "ttl": 128, "window_range": (8192, 65535), "confidence": 80},
    {"name": "macOS", "ttl": 64, "window_range": (65535, 65535), "confidence": 85},
    {"name": "iOS", "ttl": 64, "window_range": (65535, 65535), "confidence": 75},
    {"name": "Android", "ttl": 64, "window_range": (5840, 65535), "confidence": 70},
    {"name": "FreeBSD", "ttl": 64, "window_range": (65535, 65535), "confidence": 80},
    {"name": "OpenBSD", "ttl": 64, "window_range": (16384, 16384), "confidence": 85},
    {"name": "Solaris", "ttl": 255, "window_range": (8760, 8760), "confidence": 85},
    {"name": "Cisco IOS", "ttl": 255, "window_range": (4128, 4128), "confidence": 85},
    {"name": "Network Device (generic)", "ttl": 255, "window_range": (4000, 33000), "confidence": 60},
]


def _get_ttl_from_ping(host: str, timeout: float) -> int | None:
    """Get TTL from a ping response using the system ping command."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 1, text=True
        )
        output = result.stdout

        # Extract TTL from ping output
        ttl_patterns = [
            r"ttl=(\d+)",
            r"TTL=(\d+)",
            r"time to live[=:]?\s*(\d+)",
        ]
        for pattern in ttl_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return int(match.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    return None


def _get_tcp_fingerprint(host: str, timeout: float) -> tuple[int | None, int | None]:
    """Get TTL and TCP window size via scapy SYN scan.

    Returns (ttl, window_size) from the SYN-ACK response.
    """
    if not HAS_SCAPY:
        return None, None

    try:
        conf.verb = 0
        # Try common ports that might be open
        for port in [80, 443, 22, 8080]:
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=timeout, verbose=0)

            if reply and reply.haslayer(TCP):
                # Check for SYN-ACK
                if reply[TCP].flags & 0x12:
                    ttl = reply[IP].ttl
                    window = reply[TCP].window
                    return ttl, window

        # Try with an ICMP echo if no TCP response
        from scapy.all import ICMP
        pkt = IP(dst=host) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply:
            ttl = reply[IP].ttl
            return ttl, None
    except Exception as e:
        logger.debug("TCP fingerprint for %s failed: %s", host, e)

    return None, None


def _match_signature(ttl: int | None, window: int | None) -> tuple[str, int]:
    """Match TTL and window against known OS signatures.

    Returns (os_name, confidence_percent).
    """
    if ttl is None:
        return "Unknown", 0

    best_match = "Unknown"
    best_confidence = 0

    for sig in OS_SIGNATURES:
        confidence = 0

        # TTL match
        if sig["ttl"] == ttl:
            confidence += 60
        elif sig["ttl"] - 1 <= ttl <= sig["ttl"] + 1:
            # TTL can decrement by 1 per hop
            confidence += 40
        else:
            continue  # TTL doesn't match at all

        # Window size match (if available)
        if window is not None:
            w_min, w_max = sig["window_range"]
            if w_min <= window <= w_max:
                # Scale window confidence by signature's base confidence
                window_score = int(sig["confidence"] * 0.4)
                confidence += window_score
            elif abs(window - w_min) < 2000 or abs(window - w_max) < 2000:
                confidence += int(sig["confidence"] * 0.2)

        if confidence > best_confidence:
            best_confidence = confidence
            best_match = sig["name"]

    # Clamp confidence
    best_confidence = min(best_confidence, 98)

    return best_match, best_confidence


def fingerprint_os(host: str, timeout: float = 3.0) -> dict:
    """Guess the operating system of a remote host.

    Uses TTL and TCP window size from SYN-ACK responses (via scapy),
    with a fallback to TTL-only from ping.

    Args:
        host: Target hostname or IP
        timeout: Seconds to wait for responses

    Returns:
        dict with os_guess, confidence (0-100), ttl, window_size,
        and method used
    """
    ttl: int | None = None
    window: int | None = None
    method = ""

    # Try scapy TCP fingerprint first
    scapy_ttl, scapy_window = _get_tcp_fingerprint(host, timeout)
    if scapy_ttl is not None:
        ttl = scapy_ttl
        window = scapy_window
        method = "tcp_syn"
    else:
        # Fallback to ping TTL
        ping_ttl = _get_ttl_from_ping(host, timeout)
        if ping_ttl is not None:
            ttl = ping_ttl
            method = "ping_ttl"

    if ttl is None:
        return {
            "host": host,
            "os_guess": "Unknown",
            "confidence": 0,
            "ttl": None,
            "window_size": None,
            "method": "unreachable",
            "details": "Host did not respond to probes",
        }

    os_name, confidence = _match_signature(ttl, window)

    return {
        "host": host,
        "os_guess": os_name,
        "confidence": confidence,
        "ttl": ttl,
        "window_size": window,
        "method": method,
    }