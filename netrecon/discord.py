"""Discord webhook notification module.

Sends formatted embed messages to Discord channels via webhook URLs.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


def send_webhook(
    webhook_url: str,
    content: str | None = None,
    embeds: list[dict] | None = None,
    username: str = "netrecon",
    timeout: float = 5.0,
) -> bool:
    """Send a message to a Discord webhook URL.

    Args:
        webhook_url: Full Discord webhook URL
        content: Plain text message (optional, used if no embeds)
        embeds: List of Discord embed objects (see https://discord.com/developers/docs/resources/message#embed-object)
        username: Display name for the webhook bot
        timeout: HTTP request timeout

    Returns:
        True if sent successfully
    """
    if not HAS_URLLIB:
        logger.error("urllib not available, cannot send webhook")
        return False

    payload: dict = {"username": username}
    if content:
        payload["content"] = content
    if embeds:
        payload["embeds"] = embeds

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status in (200, 204):
                return True
            logger.warning("Discord webhook returned HTTP %d", resp.status)
            return False
    except urllib.error.HTTPError as e:
        logger.error("Discord webhook HTTP %d: %s", e.code, e.read().decode()[:200])
        return False
    except (urllib.error.URLError, OSError) as e:
        logger.error("Discord webhook request failed: %s", e)
        return False


# ── Convenience builders ──────────────────────────────────────────


def build_alert_embed(
    title: str,
    description: str,
    color: int = 0x58A6FF,
    fields: list[dict] | None = None,
    footer: str | None = None,
) -> dict:
    """Build a Discord embed dict for netrecon alerts.

    Args:
        title: Embed title
        description: Embed description text
        color: Decimal color (default: blue 0x58A6FF)
        fields: List of {name, value, inline} dicts
        footer: Optional footer text

    Returns:
        Discord embed dict
    """
    embed: dict = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed["fields"] = fields
    if footer:
        embed["footer"] = {"text": footer}
    return embed


def send_host_alert(
    webhook_url: str,
    event_type: str,
    ip: str,
    hostname: str | None = None,
    details: str | None = None,
) -> bool:
    """Send a host join/leave alert to Discord.

    Args:
        webhook_url: Discord webhook URL
        event_type: "join", "leave", or "scan_complete"
        ip: Host IP
        hostname: Optional resolved hostname
        details: Optional additional info

    Returns:
        True if sent
    """
    if event_type == "join":
        title = "New Device Detected"
        description = f"**{ip}** joined the network"
        color = 0x3FB950  # green
    elif event_type == "leave":
        title = "Device Offline"
        description = f"**{ip}** went offline"
        color = 0xF85149  # red
    elif event_type == "scan_complete":
        title = "Network Scan Complete"
        description = details or "Scan finished"
        color = 0x58A6FF  # blue
    else:
        title = "netrecon Alert"
        description = f"{event_type}: {ip}"
        color = 0xD29922  # yellow

    fields = []
    if hostname:
        fields.append({"name": "Hostname", "value": hostname, "inline": True})
    fields.append({"name": "IP", "value": ip, "inline": True})

    embed = build_alert_embed(title, description, color, fields, footer="netrecon watch")
    return send_webhook(webhook_url, embeds=[embed])