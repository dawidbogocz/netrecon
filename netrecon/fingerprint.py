"""OS fingerprinting module — TTL and TCP window size analysis."""

SIGNATURES = {
    "Linux": {"ttl_range": (64, 64), "window": 65535},
    "Windows": {"ttl_range": (128, 128), "window": 65535},
    "macOS": {"ttl_range": (64, 64), "window": 5840},
    "BSD": {"ttl_range": (64, 64), "window": 65535},
    "Cisco/Network": {"ttl_range": (255, 255), "window": 4128},
    "Solaris": {"ttl_range": (255, 255), "window": 8760},
}


def fingerprint_os(host: str, timeout: float = 3.0) -> dict:
    """Guess OS from TTL + TCP window size. Returns {os_guess, confidence, ttl, window_size}."""
    return {"os_guess": "Unknown", "confidence": 0, "ttl": None, "window_size": None}