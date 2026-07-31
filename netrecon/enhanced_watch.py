"""Enhanced watch mode — deep host scanning with change detection.

Extends the basic ping-only NetworkWatcher with per-host port scanning,
banner grabbing, OS fingerprinting, and stateful change detection
that only alerts on meaningful events:
  - Host joins/leaves the network
  - Port opens/closes on a known host

Banner and OS fingerprint changes are stored for the web UI but
NEVER trigger Discord alerts (too noisy).

Usage:
    from netrecon.enhanced_watch import EnhancedWatcher

    watcher = EnhancedWatcher("192.168.0.1-254", discord_webhook="...")
    watcher.run(interval=120, iterations=0)
"""

import json
import logging
import re
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
    """Deep network watcher — only alerts on meaningful changes.

    Discord alerts are limited to:
      - New device joined the network
      - Device went offline
      - Port opened on a known host
      - Port closed on a known host

    Banner and OS fingerprint data is collected for the web UI/DB
    but NEVER triggers alerts (too much noise from HTTP Date headers,
    SSH key exchange material, etc.).
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
        self._host_flap: dict[str, int] = {}  # host -> consecutive missed scans
        self._host_pending_join: set[str] = set()  # hosts seen once, waiting for confirmation

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

            # Send Discord summary (skip first scan — it's the baseline)
            if self.discord_webhook and change_report.get("has_changes") and self.scan_count > 1:
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

        Alerts ONLY on:
          - New hosts (joined since last scan)
          - Gone hosts (went offline since last scan)
          - Port opens/closes (service appeared/disappeared)

        Banner and OS changes are stored but never alerted on.

        Returns:
            Change report dict
        """
        hosts = ping.ping_sweep(self.target, timeout=self.timeout, workers=self.workers)
        current = set(hosts)

        new_hosts = sorted(current - self.previous_hosts)
        gone_hosts = sorted(self.previous_hosts - current)

        # Debounce joins: a host needs 2 consecutive scans before being reported as "new"
        confirmed_new = []
        for ip in new_hosts:
            if ip in self._host_pending_join:
                # Seen in 2 consecutive scans — confirmed
                confirmed_new.append(ip)
                self._host_pending_join.discard(ip)
            else:
                # First sighting — add to pending
                self._host_pending_join.add(ip)
        # Clear pending for hosts that disappeared
        self._host_pending_join -= current

        # Debounce leaves: a host needs 2 consecutive misses before being reported as "gone"
        for ip in list(gone_hosts):
            self._host_flap[ip] = self._host_flap.get(ip, 0) + 1
        truly_gone = {ip for ip, count in self._host_flap.items() if count >= 2}
        truly_gone &= self.previous_hosts
        gone_hosts = sorted(truly_gone)
        # Clear flap counter for hosts that reappeared
        for ip in current:
            self._host_flap.pop(ip, None)

        new_hosts = confirmed_new

        scan_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()

        host_details: list[dict] = []
        port_changes: list[dict] = []

        for ip in sorted(current):
            host_info = self._scan_host(ip, scan_id)
            host_details.append(host_info)

            # Compare port states against previous snapshot
            prev = netrecon_db.get_latest_snapshot(self.target, ip)

            if prev and prev.get("alive"):
                previous_ports = prev.get("ports") or {}
                current_ports = host_info.get("ports") or {}

                # Detect port opens — a port that was closed/missing is now open
                for port_str, info in current_ports.items():
                    if info.get("state") == "open":
                        old = previous_ports.get(port_str)
                        if old is None or old.get("state") != "open":
                            port_changes.append({
                                "ip": ip,
                                "port": int(port_str),
                                "state": "opened",
                                "service": info.get("service", ""),
                            })

                # Detect port closes — a port that was open is now closed/missing
                for port_str, old_info in previous_ports.items():
                    if old_info.get("state") == "open":
                        cur = current_ports.get(port_str)
                        if cur is None or cur.get("state") != "open":
                            port_changes.append({
                                "ip": ip,
                                "port": int(port_str),
                                "state": "closed",
                                "service": old_info.get("service", ""),
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

        for ip in gone_hosts:
            netrecon_db.save_snapshot(
                scan_id=scan_id, target=self.target, ip=ip,
                alive=False, ports=None, os_info=None,
            )

        for ip in new_hosts:
            netrecon_db.save_event("join", ip, f"Device {ip} joined the network")
        for ip in gone_hosts:
            netrecon_db.save_event("leave", ip, f"Device {ip} went offline")

        self.previous_hosts = current

        has_changes = bool(new_hosts or gone_hosts or port_changes)

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
            "has_changes": has_changes,
        }

    def _scan_host(self, ip: str, scan_id: str) -> dict:
        """Deep scan a single host: ports, banners, OS fingerprint.

        Banners and OS are stored for the web UI but never compared
        across scans for alerting purposes.

        Args:
            ip: Host IP address
            scan_id: Current scan cycle ID

        Returns:
            Dict with ip, alive, ports dict, os info
        """
        info: dict = {"ip": ip, "alive": True, "ports": {}, "os": None}

        port_results = scan.tcp_connect_scan(ip, self.scan_ports, timeout=self.timeout, workers=min(self.workers, 20))

        ports_dict: dict[str, dict] = {}
        for pr in port_results:
            port_str = str(pr["port"])
            entry: dict = {"state": pr.get("state", "closed"), "service": pr.get("service", "")}
            if pr.get("state") == "open":
                try:
                    banner_results = banner.grab_banners(ip, [pr["port"]], timeout=self.timeout)
                    if banner_results and banner_results[0].get("banner"):
                        entry["banner"] = self._normalize_banner(banner_results[0]["banner"])[:200]
                except Exception as e:
                    logger.debug("Banner grab for %s:%d failed: %s", ip, pr["port"], e)
            ports_dict[port_str] = entry

        info["ports"] = ports_dict

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

    @staticmethod
    def _normalize_banner(banner: str) -> str:
        """Clean a banner for display in the web UI.

        Strips dynamic content so the stored banner is readable.
        This is for display only — banner content is NEVER compared
        across scans for alerting.
        """
        if not banner:
            return ""

        # Strip HTTP headers that change per-request
        cleaned = re.sub(
            r'(?im)^(date|last-modified|expires|age|cache-control|set-cookie):\s.*$',
            '',
            banner,
        )

        # For SSH, keep only the first line (version string)
        lines = cleaned.split('\n')
        if any(l.strip().startswith('SSH-') for l in lines):
            return lines[0].strip()

        # Remove empty lines, join remaining
        cleaned = '\n'.join(l.rstrip() for l in lines if l.strip())
        return cleaned.strip()

    def _send_discord_summary(self, report: dict) -> bool:
        """Send a Discord embed with ONLY meaningful changes.

        No banner or OS changes — those are too noisy.
        Only: host joins/leaves and port opens/closes.
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
                lines.append(
                    f"🟠 **Port opened:** {pc['ip']} → {pc['port']} ({pc.get('service', 'unknown')})"
                )
            elif pc["state"] == "closed":
                lines.append(
                    f"🔵 **Port closed:** {pc['ip']} → {pc['port']} ({pc.get('service', 'unknown')})"
                )

        description = "\n".join(lines)

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
    """Convenience function to create and run an EnhancedWatcher."""
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