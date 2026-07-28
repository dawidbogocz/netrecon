"""Geolocation module — IP address location lookup via ip-api.com.

Free tier: 45 requests/minute, no API key needed.
"""

import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# ip-api.com endpoint (free, no key)
GEO_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,query,timezone"


def geo_lookup(ip: str, timeout: float = 3.0) -> dict:
    """Look up geolocation data for a single IP.

    Args:
        ip: IP address to locate
        timeout: HTTP request timeout

    Returns:
        dict with country, region, city, isp, lat, lon, or error info
    """
    # Skip private/reserved IPs
    if _is_private_ip(ip):
        return {
            "ip": ip,
            "country": "Private",
            "region": "",
            "city": "",
            "isp": "Local Network",
            "lat": None,
            "lon": None,
            "source": "private",
        }

    if not HAS_URLLIB:
        return {"ip": ip, "error": "urllib not available", "source": "unavailable"}

    try:
        url = GEO_API_URL.format(ip=ip)
        req = urllib.request.Request(url, headers={"User-Agent": "netrecon/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") == "success":
            return {
                "ip": data.get("query", ip),
                "country": data.get("country", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone", ""),
                "source": "ip-api",
            }
        else:
            return {"ip": ip, "error": data.get("message", "Unknown"), "source": "ip-api"}
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning("Geo rate limited (45 req/min)")
        return {"ip": ip, "error": f"HTTP {e.code}", "source": "ip-api"}
    except (urllib.error.URLError, socket.timeout) as e:
        return {"ip": ip, "error": str(e), "source": "ip-api"}
    except Exception as e:
        logger.debug("Geo lookup for %s failed: %s", ip, e)
        return {"ip": ip, "error": str(e), "source": "ip-api"}


def geo_lookup_batch(
    ips: list[str],
    timeout: float = 3.0,
    workers: int = 10,
) -> list[dict]:
    """Look up geolocation for multiple IPs concurrently.

    Args:
        ips: List of IP addresses
        timeout: HTTP timeout per request
        workers: Max concurrent lookups

    Returns:
        List of geo dicts in same order as input
    """
    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(geo_lookup, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                logger.debug("Batch geo for %s failed: %s", ip, e)
                results[ip] = {"ip": ip, "error": str(e)}

    return [results.get(ip, {"ip": ip, "error": "not found"}) for ip in ips]


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return True
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8
        if parts[0] == 127:
            return True
        # 169.254.0.0/16 (link-local)
        if parts[0] == 169 and parts[1] == 254:
            return True
        # 100.64.0.0/10 (Tailscale/CGNAT)
        if parts[0] == 100 and 64 <= parts[1] <= 127:
            return True
        return False
    except (ValueError, IndexError):
        return True