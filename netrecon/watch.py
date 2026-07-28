"""Watch mode — continuous network scanning with change detection and alerts.

Tracks hosts over time, detects joins/leaves, and sends Discord notifications.
"""

import logging
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable

from netrecon import ping
from netrecon import db as netrecon_db
from netrecon.discord import send_host_alert, build_alert_embed, send_webhook

logger = logging.getLogger(__name__)


class NetworkWatcher:
    """Continuously scans a network target and detects changes.

    Usage:
        watcher = NetworkWatcher("192.168.0.1-254", discord_webhook="...")
        watcher.run(interval=60, iterations=10)
    """

    def __init__(
        self,
        target: str,
        discord_webhook: str | None = None,
        timeout: float = 1.0,
        workers: int = 50,
    ):
        self.target = target
        self.discord_webhook = discord_webhook
        self.timeout = timeout
        self.workers = workers
        self.previous_hosts: set[str] = set()
        self.scan_count = 0
        self._running = False

    def run(
        self,
        interval: int = 60,
        iterations: int = 0,
        on_scan: Callable | None = None,
    ) -> list[dict]:
        """Run the watch loop.

        Args:
            interval: Seconds between scans
            iterations: Number of scans (0 = infinite)
            on_scan: Optional callback(result) after each scan

        Returns:
            List of scan result dicts
        """
        self._running = True
        results: list[dict] = []
        iteration = 0

        logger.info(
            "Watch started on %s (interval=%ds, iterations=%s)",
            self.target, interval,
            "infinite" if iterations == 0 else str(iterations),
        )

        netrecon_db.save_event("watch_start", self.target,
                               f"Watch started on {self.target}")

        while self._running and (iterations == 0 or iteration < iterations):
            iteration += 1
            self.scan_count += 1

            scan_result = self._do_scan()
            results.append(scan_result)

            if on_scan:
                try:
                    on_scan(scan_result)
                except Exception as e:
                    logger.error("Watch callback error: %s", e)

            if iterations == 0 or iteration < iterations:
                for remaining in range(interval, 0, -1):
                    if not self._running:
                        break
                    time.sleep(1)

        netrecon_db.save_event("watch_stop", self.target,
                               f"Watch stopped after {self.scan_count} scans")
        return results

    def stop(self):
        """Stop the watch loop."""
        self._running = False

    def _do_scan(self) -> dict:
        """Perform a single scan and detect changes."""
        hosts = ping.ping_sweep(
            self.target, timeout=self.timeout, workers=self.workers
        )
        current = set(hosts)

        new_hosts = current - self.previous_hosts
        gone_hosts = self.previous_hosts - current

        scan_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_number": self.scan_count,
            "total_hosts": len(current),
            "hosts": sorted(current),
            "new_hosts": sorted(new_hosts),
            "gone_hosts": sorted(gone_hosts),
        }

        # Log changes
        for ip in new_hosts:
            netrecon_db.save_event("join", ip, f"Device {ip} joined the network")
            logger.info("[+] %s joined", ip)
            if self.discord_webhook:
                send_host_alert(self.discord_webhook, "join", ip)

        for ip in gone_hosts:
            netrecon_db.save_event("leave", ip, f"Device {ip} went offline")
            logger.info("[-] %s left", ip)
            if self.discord_webhook:
                send_host_alert(self.discord_webhook, "leave", ip)

        # Send scan summary to Discord
        if self.discord_webhook and (new_hosts or gone_hosts):
            embed = build_alert_embed(
                f"Scan #{self.scan_count} — {self.target}",
                f"{len(current)} hosts online",
                0x58A6FF,
                fields=[
                    {"name": "New", "value": str(len(new_hosts)), "inline": True},
                    {"name": "Offline", "value": str(len(gone_hosts)), "inline": True},
                    {"name": "Total", "value": str(len(current)), "inline": True},
                ],
                footer="netrecon watch",
            )
            send_webhook(self.discord_webhook, embeds=[embed])

        self.previous_hosts = current
        return scan_info