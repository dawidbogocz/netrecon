"""DNS enumeration module — lookups, reverse DNS, and subdomain discovery."""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "admin", "api", "dev", "staging", "blog", "vpn",
    "ns1", "ns2", "mx", "ftp", "ssh", "git", "jenkins", "docker",
    "kubernetes", "monitor", "grafana", "prometheus", "webmail",
    "cpanel", "whm", "phpmyadmin", "mysql", "db", "test", "demo",
    "app", "portal", "help", "support", "status", "docs", "wiki",
    "forum", "shop", "store", "cdn", "static", "assets", "media",
    "img", "video", "upload", "download", "backup", "secure",
    "login", "register", "sso", "graphql", "websocket",
]


def _resolve_with_socket(hostname: str) -> list[str]:
    """Fallback: resolve hostname to IPs using socket."""
    try:
        return socket.gethostbyname_ex(hostname)[2]
    except (socket.gaierror, OSError):
        return []


def dns_lookup(hostname: str, timeout: float = 3.0) -> dict:
    """Look up all common DNS record types for a hostname.

    Args:
        hostname: Domain to query
        timeout: Seconds to wait per query

    Returns:
        dict with record types as keys and lists of (value, ttl) tuples
    """
    result: dict[str, list[tuple[str, int]]] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    for rtype in record_types:
        try:
            if HAS_DNSPYTHON:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=timeout)
                records = []
                ttl = answers.rrset.ttl if answers.rrset else 0
                for ans in answers:
                    if rtype == "MX":
                        val = f"{ans.preference} {ans.exchange}"
                    elif rtype == "SOA":
                        val = f"{ans.mname} {ans.rname}"
                    elif rtype == "TXT":
                        val = "".join(
                            s.decode() if isinstance(s, bytes) else s
                            for s in ans.strings
                        )
                    else:
                        val = str(ans)
                    records.append((val, ttl))
                if records:
                    result[rtype] = records
            else:
                if rtype == "A":
                    ips = _resolve_with_socket(hostname)
                    if ips:
                        result["A"] = [(ip, 0) for ip in ips]
                break
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.exception.Timeout:
            logger.debug("DNS lookup timeout for %s %s", hostname, rtype)
        except Exception as e:
            logger.debug("DNS lookup %s %s failed: %s", hostname, rtype, e)

    return result


def dns_reverse(ip: str, timeout: float = 3.0) -> str | None:
    """Reverse DNS lookup — find hostname for an IP.

    Args:
        ip: IP address to look up
        timeout: Seconds to wait

    Returns:
        Hostname or None
    """
    try:
        if HAS_DNSPYTHON:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR", lifetime=timeout)
            return str(answers[0])
        else:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
    except (dns.exception.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except (socket.herror, socket.gaierror):
        return None
    except Exception as e:
        logger.debug("Reverse DNS for %s failed: %s", ip, e)
        return None


def dns_enum(
    domain: str,
    wordlist: list[str] | None = None,
    timeout: float = 2.0,
    workers: int = 20,
) -> list[dict]:
    """Enumerate subdomains using a wordlist.

    Args:
        domain: Base domain (e.g. "example.com")
        wordlist: List of subdomains to try (uses built-in list if None)
        timeout: Seconds to wait per lookup
        workers: Max concurrent lookups

    Returns:
        Sorted list of {subdomain, full_domain, ips} dicts
    """
    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST

    results: list[dict] = []

    def _check_sub(sub: str) -> dict | None:
        full = f"{sub}.{domain}"
        try:
            if HAS_DNSPYTHON:
                answers = dns.resolver.resolve(full, "A", lifetime=timeout)
                ips = [str(a) for a in answers]
            else:
                ips = _resolve_with_socket(full)
            if ips:
                return {"subdomain": sub, "full_domain": full, "ips": ips}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.Timeout:
            pass
        except socket.gaierror:
            pass
        except Exception as e:
            logger.debug("Subdomain %s: %s", full, e)
        return None

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_check_sub, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            try:
                r = future.result()
                if r:
                    results.append(r)
            except Exception as e:
                logger.debug("Subenum worker error: %s", e)

    results.sort(key=lambda r: r["subdomain"])
    return results