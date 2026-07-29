"""Enhanced watch mode — deep host scanning with change detection.

Extends the basic ping-only NetworkWatcher with per-host port scanning,
banner grabbing, OS fingerprinting, and stateful change detection
(port opens/closes, banner changes, OS changes).

Usage:
    from netrecon.enhanced_watch import EnhancedWatcher

    watcher = EnhancedWatcher("192.168.0.1-254", discord_webhook="...")
    watcher.run(interval=120, iterations=0)
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from netrecon import ping, scan, banner, fingerprint
from netrecon import db as netrecon_db
from netrecon.discord import send_webhook, build_alert_embed

logger = logging.getLogger(__name__)

# Top 20 ports to scan on each alive host
TOP_PORTS = [
    22, 80, 443, 8080, 8443,
    21, 25, 53, 110, 143,
    3306, 3389, 5432, 6379, 27017,
    5900, 9090, 3000, 5000, 9000,
]


class EnhancedWatcher:
    """Deep network watcher with per-host port/banner/OS tracking.

    Each scan cycle:
      1. Ping sweep the target range
      2. For each alive host: scan top 20 ports, grab banners, fingerprint OS
      3. Compare with previous snapshot
      4. Save current snapshot to DB
      5. Return change report (join/leave, port opened/closed, banner changed, OS changed)
      6. Send rich Discord summary if webhook configured
    """

    def __init__(
        self,
        target: str,
        discord_webhook: str | None = None,
        timeout: float = 1.0,
        workers: int = 50,
        scan_ports: list[int] | None = None,
    ):
        self.target = target
        self.discord_webhook = discord_webhook
        self.timeout = timeout
        self.workers = workers
        self.scan_ports = scan_ports or TOP_PORTS
        self.previous_hosts: set[str] = set()
        self.scan_count = 0
        self._running = False

    def run(
        self,
        interval: int = 60,
        iterations: int = 0,
        on_scan: Callable | None = None,
    ) -> list[dict]:
        """Run the enhanced watch loop.

        Args:
            interval: Seconds between scans
            iterations: Number of scans (0 = infinite)
            on_scan: Optional callback(change_report) after each scan

        Returns:
            List of change report dicts
        """
        self._running = True
        results: list[dict] = []
        iteration = 0

        logger.info(
            "Enhanced watch started on %s (interval=%ds, iterations=%s, ports=%d)",
            self.target, interval,
            "infinite" if iterations == 0 else str(iterations),
            len(self.scan_ports),
        )

        netrecon_db.save_event("enhanced_watch_start", self.target,
                               f"Enhanced watch started on {self.target}")

        while self._running and (iterations == 0 or iteration < iterations):
            iteration += 1
            self.scan_count += 1

            change_report = self._do_enhanced_scan()
            results.append(change_report)

            if on_scan:
                try:
                    on_scan(change_report)
                except Exception as e:
                    logger.error("Watch callback error: %s", e)

            # Send Discord summary
            if self.discord_webhook and change_report.get("has_changes"):
                self._send_discord_summary(change_report)

            if iterations == 0 or iteration < iterations:
                for remaining in range(interval, 0, -1):
                    if not self._running:
                        break
                    import time
                    time.sleep(1)

        netrecon_db.save_event("enhanced_watch_stop", self.target,
                               f"Enhanced watch stopped after {self.scan_count} scans")
        return results

    def stop(self):
        """Stop the watch loop."""
        self._running = False

    def _do_enhanced_scan(self) -> dict:
        """Perform a single enhanced scan cycle.

        Returns:
            Change report dict with:
                - scan_number, timestamp, target
                - total_hosts, hosts (list of host detail dicts)
                - new_hosts, gone_hosts (IP lists)
                - port_changes: [{ip, port, state, service, old_state}]
                - banner_changes: [{ip, port, old_banner, new_banner, service}]
                - os_changes: [{ip, old_os, new_os}]
                - has_changes: bool
                - scan_id: str
        """
        # Collect all hosts via ping sweep
        hosts = ping.ping_sweep(self.target, timeout=self.timeout, workers=self.workers)
        current = set(hosts)

        new_hosts = sorted(current - self.previous_hosts)
        gone_hosts = sorted(self.previous_hosts - current)

        scan_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()

        # Deep scan each alive host
        host_details: list[dict] = []
        port_changes: list[dict] = []
        banner_changes: list[dict] = []
        os_changes: list[dict] = []

        for ip in sorted(current):
            host_info = self._scan_host(ip, scan_id)
            host_details.append(host_info)

            # Get previous snapshot for comparison
            prev = netrecon_db.get_latest_snapshot(self.target, ip)

            if prev and prev.get("alive"):
                previous_ports = prev.get("ports") or {}
                current_ports = host_info.get("ports") or {}

                # Detect port opens
                for port_str, info in current_ports.items():
                    if info.get("state") == "open":
                        old = previous_ports.get(port_str)
                        if old is None or old.get("state") != "open":
                            port_changes.append({
                                "ip": ip,
                                "port": int(port_str),
                                "state": "opened",
                                "service": info.get("service", ""),
                                "banner": info.get("banner", ""),
                            })
                        elif old.get("banner") and old.get("banner") != info.get("banner"):
                            banner_changes.append({
                                "ip": ip,
                                "port": int(port_str),
                                "service": info.get("service", ""),
                                "old_banner": old.get("banner", ""),
                                "new_banner": info.get("banner", ""),
                            })

                # Detect port closes
                for port_str, old_info in previous_ports.items():
                    if old_info.get("state") == "open":
                        cur = current_ports.get(port_str)
                        if cur is None or cur.get("state") != "open":
                            port_changes.append({
                                "ip": ip,
                                "port": int(port_str),
                                "state": "closed",
                                "service": old_info.get("service", ""),
                                "old_banner": old_info.get("banner", ""),
                            })

                # Detect OS changes
                prev_os = prev.get("os")
                curr_os = host_info.get("os")
                if prev_os and curr_os:
                    prev_name = prev_os.get("name", "Unknown") if isinstance(prev_os, dict) else str(prev_os)
                    curr_name = curr_os.get("name", "Unknown") if isinstance(curr_os, dict) else str(curr_os)
                    if prev_name != curr_name and prev_name != "Unknown":
                        os_changes.append({
                            "ip": ip,
                            "old_os": prev_name,
                            "new_os": curr_name,
                        })

        # Save all snapshots
        for info in host_details:
            netrecon_db.save_snapshot(
                scan_id=scan_id,
                target=self.target,
                ip=info["ip"],
                alive=info["alive"],
                ports=info.get("ports"),
                os_info=info.get("os"),
            )

        # Mark gone hosts as offline
        for ip in gone_hosts:
            netrecon_db.save_snapshot(
                scan_id=scan_id,
                target=self.target,
                ip=ip,
                alive=False,
                ports=None,
                os_info=None,
            )

        # Save events
        for ip in new_hosts:
            netrecon_db.save_event("join", ip, f"Device {ip} joined the network")
        for ip in gone_hosts:
            netrecon_db.save_event("leave", ip, f"Device {ip} went offline")

        self.previous_hosts = current

        has_changes = bool(new_hosts or gone_hosts or port_changes or banner_changes or os_changes)

        return {
            "scan_id": scan_id,
            "scan_number": self.scan_count,
            "timestamp": now,
            "target": self.target,
            "total_hosts": len(current),
            "hosts": host_details,
            "new_hosts": new_hosts,
            "gone_hosts": gone_hosts,
            "port_changes": port_changes,
            "banner_changes": banner_changes,
            "os_changes": os_changes,
            "has_changes": has_changes,
        }

    def _scan_host(self, ip: str, scan_id: str) -> dict:
        """Deep scan a single host: ports, banners, OS fingerprint.

        Args:
            ip: Host IP address
            scan_id: Current scan cycle ID

        Returns:
            Dict with ip, alive, ports dict, os info
        """
        info: dict = {"ip": ip, "alive": True, "ports": {}, "os": None}

        # Port scan
        port_results = scan.tcp_connect_scan(ip, self.scan_ports, timeout=self.timeout, workers=min(self.workers, 20))

        # Build ports dict
        ports_dict: dict[str, dict] = {}
        for pr in port_results:
            port_str = str(pr["port"])
            entry: dict = {"state": pr.get("state", "closed"), "service": pr.get("service", "")}
            if pr.get("state") == "open":
                # Grab banner
                try:
                    banner_results = banner.grab_banners(ip, [pr["port"]], timeout=self.timeout)
                    if banner_results and banner_results[0].get("banner"):
                        entry["banner"] = banner_results[0]["banner"][:200]
                except Exception as e:
                    logger.debug("Banner grab for %s:%d failed: %s", ip, pr["port"], e)
            ports_dict[port_str] = entry

        info["ports"] = ports_dict

        # OS fingerprint
        try:
            os_result = fingerprint.fingerprint_os(ip, timeout=self.timeout)
            if os_result and os_result.get("os_guess"):
                info["os"] = {
                    "name": os_result.get("os_guess", "Unknown"),
                    "confidence": os_result.get("confidence", 0),
                }
        except Exception as e:
            logger.debug("OS fingerprint for %s failed: %s", ip, e)

        return info

    def _send_discord_summary(self, report: dict) -> bool:
        """Send a rich Discord embed summarizing the scan cycle.

        Args:
            report: Change report dict from _do_enhanced_scan

        Returns:
            True if sent successfully
        """
        if not self.discord_webhook:
            return False

        lines: list[str] = []
        total_change_count = 0

        if report["new_hosts"]:
            total_change_count += len(report["new_hosts"])
            hosts = ", ".join(report["new_hosts"][:10])
            if len(report["new_hosts"]) > 10:
                hosts += f" +{len(report['new_hosts']) - 10} more"
            lines.append(f"🟢 **New:** {len(report['new_hosts'])} host(s) — {hosts}")

        if report["gone_hosts"]:
            total_change_count += len(report["gone_hosts"])
            hosts = ", ".join(report["gone_hosts"][:10])
            if len(report["gone_hosts"]) > 10:
                hosts += f" +{len(report['gone_hosts']) - 10} more"
            lines.append(f"🔴 **Offline:** {len(report['gone_hosts'])} host(s) — {hosts}")

        for pc in report["port_changes"]:
            total_change_count += 1
            if pc["state"] == "opened":
                banner_str = f" ({pc.get('banner', '')[:60]})" if pc.get("banner") else ""
                lines.append(
                    f"🟠 **Port opened:** {pc['ip']} → {pc['port']} "
                    f"({pc.get('service', 'unknown')}){banner_str}"
                )
            elif pc["state"] == "closed":
                lines.append(
                    f"🔵 **Port closed:** {pc['ip']} → {pc['port']} "
                    f"({pc.get('service', 'unknown')})"
                )

        for bc in report["banner_changes"]:
            total_change_count += 1
            old = bc.get("old_banner", "")[:60]
            new = bc.get("new_banner", "")[:60]
            lines.append(
                f"🟡 **Banner change:** {bc['ip']}:{bc['port']} "
                f"\"{old}\" → \"{new}\""
            )

        for oc in report["os_changes"]:
            total_change_count += 1
            lines.append(
                f"🟣 **OS change:** {oc['ip']} "
                f"{oc['old_os']} → {oc['new_os']}"
            )

        if not lines:
            lines.append("No changes detected.")
            if total_change_count == 0 and report["total_hosts"] > 0:
                lines.append(f"All {report['total_hosts']} hosts stable.")

        description = "\n".join(lines)

        # Build port summary
        total_open_ports = 0
        for host in report["hosts"]:
            for p, info in (host.get("ports") or {}).items():
                if info.get("state") == "open":
                    total_open_ports += 1

        fields = [
            {"name": "Hosts Online", "value": str(report["total_hosts"]), "inline": True},
            {"name": "Open Ports", "value": str(total_open_ports), "inline": True},
            {"name": "Changes", "value": str(total_change_count), "inline": True},
        ]

        # If first scan, add context
        if report["scan_number"] == 1 and report["new_hosts"]:
            fields.append({
                "name": "First Scan",
                "value": "All hosts shown as new (baseline established)",
                "inline": False,
            })

        embed = build_alert_embed(
            f"🔍 Scan #{report['scan_number']} — {report['target']}",
            description,
            0x58A6FF,
            fields=fields,
            footer="netrecon enhanced watch",
        )

        return send_webhook(self.discord_webhook, embeds=[embed])


def run_enhanced_watch(
    target: str,
    interval: int = 60,
    iterations: int = 0,
    timeout: float = 1.0,
    workers: int = 50,
    webhook: str | None = None,
    on_scan: Callable | None = None,
) -> list[dict]:
    """Convenience function to create and run an EnhancedWatcher.

    Args:
        target: Network target (CIDR or IP range)
        interval: Seconds between scans
        iterations: Number of scans (0 = infinite)
        timeout: Per-host probe timeout
        workers: Max concurrent workers
        webhook: Optional Discord webhook URL
        on_scan: Optional callback after each scan

    Returns:
        List of change report dicts
    """
    watcher = EnhancedWatcher(
        target,
        discord_webhook=webhook,
        timeout=timeout,
        workers=workers,
    )
    try:
        return watcher.run(interval=interval, iterations=iterations, on_scan=on_scan)
    except KeyboardInterrupt:
        logger.info("Enhanced watch stopped by user")
        watcher.stop()
        return []