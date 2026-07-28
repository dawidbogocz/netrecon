"""Service banner grabber module.

Connects to open ports, sends probes, and reads service banners.
"""

import logging
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from netrecon.scan import resolve_service

logger = logging.getLogger(__name__)

# Probes to send for different service types
DEFAULT_PROBE = b"\r\n"
HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"
SMTP_PROBE = b"EHLO scan\r\n"
FTP_PROBE = b"\r\n"
SSH_PROBE = b"\r\n"
TELNET_PROBE = b"\r\n"
POP3_PROBE = b"CAPA\r\n"
IMAP_PROBE = b"A01 CAPABILITY\r\n"

PORT_PROBES: dict[int, bytes] = {
    25: SMTP_PROBE,
    80: HTTP_PROBE,
    110: POP3_PROBE,
    143: IMAP_PROBE,
    443: HTTP_PROBE,
    587: SMTP_PROBE,
    8080: HTTP_PROBE,
    8443: HTTP_PROBE,
    993: IMAP_PROBE,
    995: POP3_PROBE,
}


def _get_probe(port: int) -> bytes:
    """Get the appropriate probe for a given port."""
    return PORT_PROBES.get(port, DEFAULT_PROBE)


def _grab_single_banner(host: str, port: int, timeout: float) -> dict:
    """Grab banner from a single port."""
    result = {
        "port": port,
        "banner": "",
        "service": resolve_service(port),
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send a probe
        probe = _get_probe(port)
        try:
            sock.sendall(probe)
        except OSError:
            pass

        # Read the banner
        banner_data = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner_data += chunk
                if len(banner_data) > 4096:
                    break
        except socket.timeout:
            pass

        sock.close()

        if banner_data:
            banner = banner_data.decode("utf-8", errors="replace")
            # Clean up non-printable characters
            banner = re.sub(r"[\r\n]+", " ", banner)
            banner = re.sub(r"[^\x20-\x7E]", "", banner)
            result["banner"] = banner.strip()

            # Try to extract service version from banner
            if not result["service"] and banner:
                result["service"] = _guess_service_from_banner(banner, port)

    except socket.timeout:
        result["banner"] = ""
    except socket.gaierror:
        result["banner"] = "DNS resolution failed"
    except ConnectionRefusedError:
        result["banner"] = ""
    except OSError as e:
        result["banner"] = f"Error: {e}"
    except Exception as e:
        logger.debug("Banner grab on %s:%d failed: %s", host, port, e)
        result["banner"] = f"Error: {e}"

    return result


def _guess_service_from_banner(banner: str, port: int) -> str:
    """Guess the service name from banner content."""
    banner_lower = banner.lower()
    if "ssh" in banner_lower and "openssh" in banner_lower:
        return "ssh"
    if "220" in banner and "ftp" in banner_lower:
        return "ftp"
    if banner_lower.startswith("http/") or "server:" in banner_lower:
        return "http"
    if "smtp" in banner_lower or "esmtp" in banner_lower:
        return "smtp"
    if "pop3" in banner_lower or "+ok" in banner_lower[:4]:
        return "pop3"
    if "imap" in banner_lower or "* ok" in banner_lower[:4]:
        return "imap"
    if "telnet" in banner_lower:
        return "telnet"
    return ""


def grab_banners(
    host: str,
    ports: list[int],
    timeout: float = 3.0,
    workers: int = 10,
) -> list[dict]:
    """Grab service banners from open ports.

    Connects to each port, sends a protocol-appropriate probe,
    and reads the service banner.

    Args:
        host: Target hostname or IP
        ports: List of ports to check
        timeout: Seconds to wait per connection/read
        workers: Max concurrent connections

    Returns:
        List of dicts with port, banner, service
    """
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_grab_single_banner, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                logger.debug("Error grabbing banner on port %d: %s", port, e)
                results.append({
                    "port": port,
                    "banner": f"Error: {e}",
                    "service": resolve_service(port),
                })

    results.sort(key=lambda r: r["port"])
    return results