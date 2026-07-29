"""Daily trend summary script for netrecon enhanced watch.

Queries host_snapshots from the last 24 hours and sends a Discord
summary embed with host counts, port changes, and trends.

Usage:
    python daily_summary.py <target> <webhook_url>
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta

# Add netrecon to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netrecon import db as netrecon_db
from netrecon.discord import send_webhook, build_alert_embed


def generate_summary(target: str) -> dict:
    """Generate a 24-hour trend summary from snapshots.

    Args:
        target: The network target to summarize

    Returns:
        Summary dict with trend data
    """
    snapshots = netrecon_db.get_24h_snapshots(target)

    if not snapshots:
        return {"error": "No data available for the last 24 hours"}

    # Group by scan_id
    scans: dict[str, list[dict]] = {}
    for snap in snapshots:
        sid = snap["scan_id"]
        if sid not in scans:
            scans[sid] = []
        scans[sid].append(snap)

    scan_ids = sorted(scans.keys(), reverse=True)
    total_scans = len(scan_ids)

    # Per-scan host counts
    host_counts = []
    all_ips_seen: set[str] = set()
    all_ports_seen: set[str] = set()
    total_join_events = 0
    total_leave_events = 0
    total_port_opens = 0
    total_port_closes = 0

    for sid in scan_ids:
        entries = scans[sid]
        alive = [e for e in entries if e.get("alive")]
        host_counts.append(len(alive))

        for e in entries:
            ip = e.get("ip", "")
            all_ips_seen.add(ip)
            if e.get("alive") and e.get("ports"):
                for port_str, info in e["ports"].items():
                    if info.get("state") == "open":
                        all_ports_seen.add(f"{ip}:{port_str}")

    # Get events from last 24h
    events = netrecon_db.get_recent_events(limit=500)
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    for ev in events:
        created = ev.get("created_at", "")
        if created >= yesterday.isoformat():
            et = ev.get("event_type", "")
            if et == "join":
                total_join_events += 1
            elif et == "leave":
                total_leave_events += 1

    max_hosts = max(host_counts) if host_counts else 0
    min_hosts = min(host_counts) if host_counts else 0
    avg_hosts = round(sum(host_counts) / len(host_counts), 1) if host_counts else 0

    return {
        "target": target,
        "period": "24h",
        "total_scans": total_scans,
        "unique_hosts": len(all_ips_seen),
        "unique_services": len(all_ports_seen),
        "max_hosts": max_hosts,
        "min_hosts": min_hosts,
        "avg_hosts": avg_hosts,
        "current_hosts": host_counts[0] if host_counts else 0,
        "joins": total_join_events,
        "leaves": total_leave_events,
    }


def send_daily_summary(webhook_url: str, summary: dict) -> bool:
    """Send a daily summary embed to Discord.

    Args:
        webhook_url: Discord webhook URL
        summary: Summary dict from generate_summary()

    Returns:
        True if sent successfully
    """
    if "error" in summary:
        return send_webhook(
            webhook_url,
            embeds=[build_alert_embed(
                "📊 Daily Netrecon Summary — No Data",
                summary["error"],
                0xF85149,
                footer="netrecon daily",
            )],
        )

    lines = [
        f"**Target:** {summary['target']}",
        f"**Period:** Last 24 hours",
        "",
        f"**Scans performed:** {summary['total_scans']}",
        f"**Unique hosts seen:** {summary['unique_hosts']}",
        f"**Services tracked:** {summary['unique_services']}",
        "",
        f"**Hosts online:** {summary['current_hosts']}",
        f"  • Peak: {summary['max_hosts']}",
        f"  • Min: {summary['min_hosts']}",
        f"  • Avg: {summary['avg_hosts']}",
        "",
        f"**Network changes:**",
        f"  • Joins: {summary['joins']}",
        f"  • Leaves: {summary['leaves']}",
        f"  • Net change: {summary['joins'] - summary['leaves']:+d}",
    ]

    description = "\n".join(lines)

    fields = [
        {"name": "Hosts Now", "value": str(summary["current_hosts"]), "inline": True},
        {"name": "24h Peak", "value": str(summary["max_hosts"]), "inline": True},
        {"name": "Changes", "value": f"+{summary['joins']}/-{summary['leaves']}", "inline": True},
    ]

    embed = build_alert_embed(
        "📊 Daily Netrecon Summary",
        description,
        0x58A6FF,
        fields=fields,
        footer="netrecon daily",
    )

    return send_webhook(webhook_url, embeds=[embed])


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python daily_summary.py <target> <webhook_url>")
        sys.exit(1)

    target = sys.argv[1]
    webhook = sys.argv[2]
    summary = generate_summary(target)
    result = send_daily_summary(webhook, summary)
    print(f"Daily summary sent: {result}")
    if not result:
        sys.exit(1)