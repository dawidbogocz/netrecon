"""Phishing URL Analyzer module — multi-factor risk scoring.

Analyzes URLs for phishing indicators across 8 categories:
suspicious TLDs, URL shorteners, @ symbol tricks, typosquatting,
domain age, HTTPS validity, IP-based hosts, and excessive subdomains.
"""

import logging
import re
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# ── Suspicious TLDs ──────────────────────────────────────────────
SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "work", "loan", "click",
    "download", "review", "stream", "trade",
    "date", "science", "party", "racing",
    "accountant", "men", "mom", "bid",
}

# ── URL Shorteners ────────────────────────────────────────────────
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "shorturl.at",
    "ow.ly", "is.gd", "buff.ly", "tiny.cc",
    "rb.gy", "short.link", "s.id", "cut.ly",
    "2.gy", "zzb.bz", "vgd.ly", "bl.ink",
    "shor.by", "x.co", "lnkd.in", "rbx.ch",
    "db.tt", "goo.gl", "shortlink.io",
}

# ── Famous Brand Domains for Typosquatting ────────────────────────
BRAND_DOMAINS: list[str] = [
    "google.com", "gmail.com", "youtube.com", "facebook.com",
    "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "github.com", "gitlab.com", "microsoft.com", "office.com",
    "outlook.com", "live.com", "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com", "paypal.com", "ebay.com",
    "netflix.com", "spotify.com", "dropbox.com", "whatsapp.com",
    "telegram.org", "discord.com", "reddit.com", "allegro.pl",
    "olx.pl", "poczta-polska.pl", "ing.pl", "mbank.pl",
    "pkobp.pl", "pekao.com.pl",
]


@dataclass
class URLCheck:
    """Result of a single URL analysis check."""
    name: str
    score: int
    max_score: int
    passed: bool
    detail: str = ""


def _parse_url(url: str) -> dict | None:
    """Parse a URL and return its components."""
    if "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "hostname": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "full": url,
        }
    except Exception:
        return None


# ── Check functions ───────────────────────────────────────────────


def _check_suspicious_tld(parsed: dict) -> URLCheck:
    """Check if the domain uses a suspicious TLD."""
    hostname = parsed.get("hostname", "")
    if not hostname:
        return URLCheck("Suspicious TLD", 0, 15, False, "No hostname")

    if HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        tld = ext.suffix
    else:
        parts = hostname.split(".")
        tld = parts[-1] if len(parts) > 1 else ""
    tld = tld.lower().strip(".")

    score = 0
    detail = ""
    if tld in SUSPICIOUS_TLDS:
        score = 10
        detail = f"TLD '.{tld}' is commonly used in phishing"

    # Also check userinfo for @-redirect links
    full = parsed.get("full", "")
    if "://" in full:
        after_scheme = full.split("://", 1)[-1]
        if "@" in after_scheme:
            user_part = after_scheme.split("@", 1)[0]
            if "." in user_part:
                if HAS_TLDEXTRACT:
                    u_ext = tldextract.extract(user_part)
                    if u_ext.suffix:
                        user_tld = u_ext.suffix
                        if user_tld in SUSPICIOUS_TLDS:
                            score = max(score, 15)
                            detail = f"TLD '.{user_tld}' in redirect path — common phishing technique"

    if score > 0:
        return URLCheck("Suspicious TLD", score, 15, True, detail)
    return URLCheck("Suspicious TLD", 0, 15, False, f"TLD '.{tld}' looks normal")


def _check_url_shortener(parsed: dict) -> URLCheck:
    """Check if the URL uses a known URL shortener."""
    hostname = parsed.get("hostname", "").lower()
    for shortener in URL_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            return URLCheck(
                "URL Shortener", 15, 15, True,
                f"Uses known URL shortener '{shortener}'",
            )
    return URLCheck("URL Shortener", 0, 15, False, "Not a known URL shortener")


def _check_at_symbol(parsed: dict) -> URLCheck:
    """Check for @ symbol in URL (credential harvesting redirect trick).

    urlparse strips user:password@ from hostname, so we check raw URL.
    """
    full = parsed.get("full", "")
    after_scheme = full.split("://", 1)[-1] if "://" in full else full
    if "@" in after_scheme:
        return URLCheck(
            "@ Symbol in URL", 10, 10, True,
            "URL contains '@' — may redirect to a different host than expected",
        )
    return URLCheck("@ Symbol in URL", 0, 10, False, "No @ symbol")


def _count_subdomains(hostname: str) -> int:
    """Count the number of subdomain levels (excluding www)."""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        subdomain = ext.subdomain
    else:
        parts = hostname.split(".")
        if len(parts) <= 2:
            return 0
        subdomain = ".".join(parts[:-2])
    subdomain = subdomain.lstrip("www.").strip()
    if not subdomain:
        return 0
    return subdomain.count(".") + 1


def _check_excessive_subdomains(parsed: dict) -> URLCheck:
    """Check for excessive subdomain levels."""
    hostname = parsed.get("hostname", "")
    count = _count_subdomains(hostname)
    if count > 5:
        return URLCheck(
            "Excessive Subdomains", 10, 10, True,
            f"{count} subdomain levels — unusual for legitimate services",
        )
    elif count > 3:
        return URLCheck(
            "Excessive Subdomains", 5, 10, True,
            f"{count} subdomain levels is suspicious",
        )
    return URLCheck("Excessive Subdomains", 0, 10, False, f"{count} subdomain levels")


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _get_registered_domain(hostname: str) -> str:
    """Extract registered domain (domain.tld) from a hostname."""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        if ext.domain:
            return f"{ext.domain}.{ext.suffix}"
        return hostname
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _check_typosquatting(parsed: dict) -> URLCheck:
    """Check for typosquatting against known brand domains.

    Checks both the main hostname and the userinfo part (for @ redirects).
    """
    domains_to_check: list[str] = []

    # Main hostname
    hostname = parsed.get("hostname", "").lower()
    if hostname:
        domains_to_check.append(_get_registered_domain(hostname))

    # Userinfo part (before @)
    full = parsed.get("full", "")
    if "://" in full:
        after_scheme = full.split("://", 1)[-1]
        if "@" in after_scheme:
            user_part = after_scheme.split("@", 1)[0]
            if "." in user_part and not user_part.startswith("http"):
                domains_to_check.append(_get_registered_domain(user_part.lower().strip()))
                # Also try just the brand-like subpart (e.g. "paypall" from "secure-paypall.tk")
                ext = tldextract.extract(user_part) if HAS_TLDEXTRACT else None
                if ext and ext.domain:
                    domains_to_check.append(ext.domain)

    best_match = None
    best_distance = float("inf")
    matched_domain = ""

    for domain_to_check in domains_to_check:
        # Also compare just the domain part (without TLD) against brand domain part
        domain_only = domain_to_check
        if HAS_TLDEXTRACT:
            ext = tldextract.extract(domain_to_check)
            if ext.domain:
                domain_only = ext.domain

        for brand in BRAND_DOMAINS:
            # Compare full domain
            dist = _levenshtein_distance(domain_to_check, brand)
            max_dist = max(1, len(brand) // 3)
            if 0 < dist <= max_dist and dist < best_distance:
                best_distance = dist
                best_match = brand
                matched_domain = domain_to_check

            # Also compare just the domain name against brand's domain part
            brand_name = brand.split(".")[0]
            dist2 = _levenshtein_distance(domain_only, brand_name)
            max_dist2 = max(1, len(brand_name) // 3)
            if 0 < dist2 <= max_dist2 and dist2 < best_distance:
                best_distance = dist2
                best_match = brand
                matched_domain = domain_only

    if best_match:
        return URLCheck(
            "Typosquatting", 15, 15, True,
            f"'{domains_to_check[0]}' is similar to '{best_match}' (distance: {best_distance})",
        )
    return URLCheck("Typosquatting", 0, 15, False, "No typosquatting detected")


def _check_https_validity(parsed: dict, timeout: float) -> URLCheck:
    """Check if the URL uses HTTPS and if the certificate is valid."""
    hostname = parsed.get("hostname", "")
    scheme = parsed.get("scheme", "")

    if scheme != "https":
        return URLCheck("HTTPS Validity", 10, 10, True,
                        "URL does not use HTTPS — data transmitted in plaintext")

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if "notAfter" in cert:
                    expiry = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        return URLCheck("HTTPS Validity", 10, 10, True,
                                        f"TLS certificate expired {abs(days_left)} days ago")
                    elif days_left < 7:
                        return URLCheck("HTTPS Validity", 5, 10, True,
                                        f"TLS certificate expires in {days_left} days")
                else:
                    return URLCheck("HTTPS Validity", 5, 10, True,
                                    "TLS certificate missing expiry date")

                return URLCheck("HTTPS Validity", 0, 10, False,
                                f"Valid HTTPS certificate")
    except ssl.SSLCertVerificationError as e:
        return URLCheck("HTTPS Validity", 10, 10, True,
                        f"TLS certificate verification failed: {e}")
    except socket.timeout:
        return URLCheck("HTTPS Validity", 5, 10, True,
                        "Could not verify TLS certificate (timeout)")
    except ConnectionRefusedError:
        return URLCheck("HTTPS Validity", 5, 10, True,
                        "Connection refused on port 443")
    except Exception as e:
        logger.debug("TLS check for %s: %s", hostname, e)
        return URLCheck("HTTPS Validity", 5, 10, True,
                        f"Could not verify TLS certificate")


def _check_ip_hostname(parsed: dict) -> URLCheck:
    """Check if the URL uses a raw IP address instead of a domain."""
    hostname = parsed.get("hostname", "")
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        parts = [int(x) for x in hostname.split(".")]
        if all(0 <= p <= 255 for p in parts):
            return URLCheck("IP-based Hostname", 10, 10, True,
                            "URL uses raw IP address — harder to trace, common in phishing")
    if ":" in hostname and hostname.startswith("["):
        return URLCheck("IP-based Hostname", 10, 10, True,
                        "URL uses raw IPv6 address")
    return URLCheck("IP-based Hostname", 0, 10, False, "Uses domain name")


def _check_domain_age(parsed: dict, timeout: float) -> URLCheck:
    """Check the domain age via WHOIS or DNS creation date."""
    hostname = parsed.get("hostname", "")
    check_domain = _get_registered_domain(hostname)

    # Try WHOIS lookup
    try:
        result = subprocess.run(
            ["whois", check_domain],
            capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout.lower()

        date_patterns = [
            r"creation date[:\s]+([\d\-/T.:]+)",
            r"created[:\s]+([\d\-/T.:]+)",
            r"domain created[:\s]+([\d\-/T.:]+)",
        ]
        for pattern in date_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                date_str = match.group(1)[:10]
                try:
                    created = datetime.strptime(date_str, "%Y-%m-%d")
                    age_days = (datetime.now() - created).days
                    if age_days < 30:
                        return URLCheck("Domain Age", 15, 15, True,
                                        f"Domain created {age_days} days ago — very recent")
                    elif age_days < 365:
                        return URLCheck("Domain Age", 8, 15, True,
                                        f"Domain created {age_days} days ago — less than a year")
                    else:
                        return URLCheck("Domain Age", 0, 15, False,
                                        f"Domain is {age_days} days old")
                except ValueError:
                    pass

        if "no entries found" in output or "not found" in output:
            return URLCheck("Domain Age", 15, 15, True,
                            "Domain does not appear to be registered")
        return URLCheck("Domain Age", 2, 15, True,
                        "Could not determine exact domain age")
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        logger.debug("WHOIS for %s failed: %s", check_domain, e)

    # Fallback: DNS SOA record serial date
    try:
        if HAS_DNSPYTHON:
            answers = dns.resolver.resolve(check_domain, "SOA", lifetime=timeout)
            for rdata in answers:
                serial = str(rdata.serial)
                if len(serial) >= 8 and serial.isdigit():
                    year = int(serial[:4])
                    if 1990 < year <= datetime.now().year:
                        return URLCheck("Domain Age", 2, 15, True,
                                        f"DNS record serial dates to {year}")
    except Exception:
        pass

    return URLCheck("Domain Age", 2, 15, True,
                    "Could not determine domain age")


def _get_risk_level(score: int) -> str:
    """Convert numeric risk score to a label."""
    if score >= 81:
        return "Confirmed Phishing"
    elif score >= 51:
        return "Likely Phishing"
    elif score >= 21:
        return "Suspicious"
    return "Safe"


def analyze_url(url: str, timeout: float = 5.0) -> dict:
    """Analyze a URL for phishing indicators.

    Performs 8 checks across multiple categories and returns
    a weighted risk score with detailed breakdown.

    Args:
        url: The URL to analyze
        timeout: Max seconds for network operations

    Returns:
        dict with url, risk_score, risk_level, parsed, checks (list of dicts)
    """
    if not url or not url.strip():
        return {
            "url": url or "",
            "risk_score": 100,
            "risk_level": "Invalid URL",
            "parsed": {},
            "checks": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    parsed = _parse_url(url)
    if parsed is None:
        return {
            "url": url,
            "risk_score": 100,
            "risk_level": "Invalid URL",
            "parsed": {},
            "checks": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    net_timeout = max(1.0, timeout / 3)

    checks = [
        _check_suspicious_tld(parsed),
        _check_url_shortener(parsed),
        _check_at_symbol(parsed),
        _check_excessive_subdomains(parsed),
        _check_typosquatting(parsed),
        _check_ip_hostname(parsed),
        _check_https_validity(parsed, net_timeout),
        _check_domain_age(parsed, net_timeout),
    ]

    total_score = sum(c.score for c in checks)
    risk_level = _get_risk_level(total_score)

    return {
        "url": url,
        "risk_score": total_score,
        "risk_level": risk_level,
        "parsed": {
            "scheme": parsed.get("scheme"),
            "hostname": parsed.get("hostname"),
            "path": parsed.get("path"),
        },
        "checks": [
            {
                "name": c.name,
                "score": c.score,
                "max_score": c.max_score,
                "passed": c.passed,
                "detail": c.detail,
            }
            for c in checks
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }