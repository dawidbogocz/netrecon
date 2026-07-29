"""Network topology discovery module.

Discovers the LAN topology by parsing the local ARP cache,
routing table, and cross-referencing with scan data.

Outputs a graph structure suitable for vis.js visualization:
  {nodes: [{id, label, ip, mac, vendor, group, title}],
   edges: [{from, to, label}]}
"""

import logging
import os
import re
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

# ── MAC OUI database (common vendors) ─────────────────────────────
# Source: IEEE OUI registry. Abbreviated list of common manufacturers.
MAC_VENDORS: dict[str, str] = {
    "00:21:ff": "Hewlett Packard",
    "5c:a6:e6": "TP-Link",
    "28:44:f4": "TP-Link",
    "f0:09:0d": "Tenda",
    "b8:88:80": "Tenda",
    "9c:13:9e": "Xiaomi",
    "5c:e9:31": "Xiaomi",
    "4c:cc:6a": "Samsung",
    "a2:da:2d": "Unknown",
    "8e:a9:52": "Unknown",
    "00:21:ff": "Hewlett Packard",
    "00:1a:79": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5d": "Microsoft Hyper-V",
    "00:1b:21": "Intel",
    "3c:46:d8": "Intel",
    "f4:4d:30": "Intel",
    "20:68:7d": "Apple",
    "3c:22:fb": "Apple",
    "7c:11:be": "Apple",
    "bc:92:6b": "Apple",
    "f0:18:98": "Apple",
    "48:5d:36": "Apple",
    "00:17:88": "Apple",
    "a4:5e:60": "Apple",
    "00:24:36": "Apple",
    "00:26:bb": "Apple",
    "00:24:df": "Amazon",
    "74:75:48": "Amazon",
    "ac:63:be": "Amazon",
    "34:d2:62": "Google/Nest",
    "18:b0:90": "Google/Nest",
    "8c:de:52": "Google/Nest",
    "00:1e:06": "Cisco",
    "00:14:6c": "Cisco",
    "64:16:7f": "Cisco",
    "00:22:6d": "D-Link",
    "1c:7e:e5": "D-Link",
    "f8:e4:3b": "D-Link",
    "e0:46:9a": "ASUS",
    "10:bf:48": "ASUS",
    "90:9a:4a": "ASUS",
    "00:1a:92": "Netgear",
    "90:94:e4": "Netgear",
    "3c:37:86": "Netgear",
    "00:23:cd": "Synology",
    "00:11:32": "Synology",
    "00:0f:e8": "Zyxel",
    "00:19:cb": "Zyxel",
    "00:24:8c": "Huawei",
    "00:1e:10": "Huawei",
    "e0:5a:1b": "Huawei",
    "00:13:3b": "Ubiquiti",
    "74:83:c2": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "b8:69:f4": "Ubiquiti",
    "00:11:50": "Espressif (ESP)",
    "24:0a:c4": "Espressif (ESP)",
    "24:6f:28": "Espressif (ESP)",
    "ec:fa:bc": "Espressif (ESP)",
    "10:06:1c": "Aruba",
    "00:0f:8f": "Aruba",
    "00:23:14": "Aruba",
    "50:76:af": "Sonos",
    "b8:ac:6f": "Sonos",
    "00:0e:4f": "Roku",
    "00:1a:af": "Roku",
    "00:17:3f": "Roku",
    "00:04:4b": "Sony",
    "00:15:c0": "Sony",
    "40:31:3c": "Sony",
    "00:1a:e9": "LG Electronics",
    "c8:3a:35": "LG Electronics",
    "f8:0a:77": "LG Electronics",
    "00:0a:95": "Apple",
    "00:1e:52": "Apple",
    "00:21:e9": "Apple",
    "00:25:00": "Apple",
    "00:25:bc": "Apple",
    "20:68:7d": "Apple",
    "3c:22:fb": "Apple",
    "7c:11:be": "Apple",
    "bc:92:6b": "Apple",
    "f0:18:98": "Apple",
    "48:5d:36": "Apple",
    "00:17:88": "Apple",
    "a4:5e:60": "Apple",
    "00:24:36": "Apple",
}

# Known residential gateway MACs often have these prefixes
GATEWAY_PREFIXES: set[str] = {
    "5c:a6:e6",  # TP-Link
    "28:44:f4",  # TP-Link
    "00:21:ff",  # HP / Aruba
    "f0:09:0d",  # Tenda
    "b8:88:80",  # Tenda
    "00:1a:92",  # Netgear
    "90:94:e4",  # Netgear
    "00:22:6d",  # D-Link
    "e0:46:9a",  # ASUS
    "00:1e:06",  # Cisco
    "00:14:6c",  # Cisco
    "00:0f:e8",  # Zyxel
    "00:24:8c",  # Huawei
    "74:83:c2",  # Ubiquiti
}

# Device group mapping for vis.js node styling
DEVICE_GROUPS: dict[str, str] = {
    "Apple": "apple",
    "Samsung": "mobile",
    "Xiaomi": "mobile",
    "TP-Link": "network",
    "Tenda": "network",
    "D-Link": "network",
    "Netgear": "network",
    "ASUS": "network",
    "Cisco": "network",
    "Zyxel": "network",
    "Huawei": "network",
    "Ubiquiti": "network",
    "Raspberry Pi": "server",
    "Synology": "server",
    "Hewlett Packard": "server",
    "HP": "server",
    "Intel": "computer",
    "VMware": "server",
    "Oracle VirtualBox": "server",
    "Microsoft Hyper-V": "server",
    "Amazon": "iot",
    "Google/Nest": "iot",
    "Sonos": "iot",
    "Roku": "iot",
    "Sony": "iot",
    "LG Electronics": "iot",
    "Espressif (ESP)": "iot",
    "Aruba": "network",
}


def _lookup_vendor(mac: str) -> str:
    """Look up the manufacturer for a MAC address using OUI prefix."""
    prefix = mac.upper()[:8]
    # Check both uppercase and lowercase keys
    result = MAC_VENDORS.get(prefix) or MAC_VENDORS.get(prefix.lower())
    return result or "Unknown"


def _get_device_group(vendor: str) -> str:
    """Map a vendor to a node group for vis.js styling."""
    return DEVICE_GROUPS.get(vendor, "unknown")


def parse_arp_table() -> list[dict]:
    """Parse the system ARP table to discover network neighbors.

    Returns:
        List of {ip, mac, vendor, hostname, iface} dicts
    """
    devices: list[dict] = []

    # Try /proc/net/arp first (Linux)
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                lines = f.read().strip().split("\n")[1:]  # Skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "0x2":  # 0x2 = complete entry
                    ip = parts[0]
                    mac = parts[3].upper()
                    iface = parts[5] if len(parts) > 5 else ""
                    if mac != "00:00:00:00:00:00":
                        vendor = _lookup_vendor(mac)
                        hostname = _resolve_hostname(ip)
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor,
                            "hostname": hostname,
                            "iface": iface,
                        })
        except (OSError, IndexError) as e:
            logger.warning("Failed to parse /proc/net/arp: %s", e)
    else:
        # Fallback: try `arp -a`
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.split("\n"):
                match = re.match(
                    r".*?\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)",
                    line, re.IGNORECASE,
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    vendor = _lookup_vendor(mac)
                    hostname = _resolve_hostname(ip)
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "hostname": hostname, "iface": "",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning("Failed to run arp -a: %s", e)

    return devices


def _resolve_hostname(ip: str) -> str:
    """Try to resolve a hostname for an IP via reverse DNS."""
    try:
        import socket
        name, _, _ = socket.gethostbyaddr(ip)
        return name.split(".")[0]  # Short name only
    except (socket.herror, socket.gaierror, OSError):
        return ""


def get_tailscale_devices() -> list[dict]:
    """Parse 'tailscale status' to get Tailscale mesh devices.

    Returns:
        List of {ip, hostname, os, status, online} dicts.
    """
    devices: list[dict] = []
    try:
        result = subprocess.run(
            ["tailscale", "status"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Format: IP  hostname  user@  OS  status
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = parts[0]
            if not ip.startswith("100."):
                continue
            hostname = parts[1]
            # user is parts[2] (e.g. dawidbogocz070@), skip it
            ts_os = parts[3].lower()
            # Status is everything after the OS column
            status_str = " ".join(parts[4:]) if len(parts) > 4 else ""
            online = "offline" not in status_str and "offline" not in status_str
            devices.append({
                "ip": ip,
                "hostname": hostname,
                "os": ts_os,
                "status": status_str.strip() if status_str else "active",
                "online": online,
            })
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        logger.debug("Failed to run tailscale status: %s", e)
    return devices


def get_gateway_ip() -> Optional[str]:
    """Get the default gateway IP address.

    Returns:
        Gateway IP string or None
    """
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                for line in f.read().strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "00000000":  # Destination = 0.0.0.0
                        # Gateway is in hex, reverse byte order
                        gw_hex = parts[2]
                        gw = ".".join(str(int(gw_hex[i : i + 2], 16)) for i in range(6, -1, -2))
                        return gw
        # Fallback to `ip route`
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        logger.warning("Failed to get gateway: %s", e)
    return None


def get_local_ip() -> Optional[str]:
    """Get the local machine's primary IP address."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", result.stdout)
        if match:
            return match.group(1)

        # Fallback: hostname -I
        result = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5,
        )
        if result.stdout:
            return result.stdout.strip().split()[0]
    except Exception as e:
        logger.warning("Failed to get local IP: %s", e)
    return None


def build_topology(
    extra_hosts: list[dict] | None = None,
    include_tailscale: bool = True,
) -> dict:
    """Build a network topology graph from ARP cache, scan data, and Tailscale.

    Args:
        extra_hosts: Optional list of {ip, ports, os} from a scan cycle
                     to enrich node data with open ports and OS info.
        include_tailscale: Whether to include Tailscale mesh devices (default: True).

    Returns:
        {nodes: [...], edges: [...]} dict suitable for vis.js
    """
    devices = parse_arp_table()
    gateway = get_gateway_ip()
    local_ip = get_local_ip()
    tailscale_devices = get_tailscale_devices() if include_tailscale else []

    # Index extra hosts by IP for enrichment
    extra_by_ip: dict[str, dict] = {}
    if extra_hosts:
        for h in extra_hosts:
            ip = h.get("ip", "")
            if ip:
                extra_by_ip[ip] = h

    nodes: list[dict] = []
    edges: list[dict] = []
    seen_ips: set[str] = set()

    # Add gateway node first
    if gateway:
        gw_mac = ""
        gw_vendor = "Unknown"
        gw_hostname = ""
        for d in devices:
            if d["ip"] == gateway:
                gw_mac = d["mac"]
                gw_vendor = d["vendor"]
                gw_hostname = d["hostname"]
                break
        gw_group = "network" if _get_device_group(gw_vendor) in ("unknown",) else _get_device_group(gw_vendor)
        label = gw_hostname or f"Gateway ({gateway})"
        nodes.append({
            "id": gateway,
            "label": label,
            "ip": gateway,
            "mac": gw_mac,
            "vendor": gw_vendor,
            "group": gw_group,
            "title": f"Gateway<br>IP: {gateway}<br>MAC: {gw_mac}<br>Vendor: {gw_vendor}",
            "shape": "star" if gw_group == "network" else "dot",
            "size": 30,
        })
        seen_ips.add(gateway)

    # Add local machine node
    if local_ip and local_ip not in seen_ips:
        local_mac = ""
        local_vendor = "Linux"
        for d in devices:
            if d["ip"] == local_ip:
                local_mac = d["mac"]
                local_vendor = d["vendor"]
                break
        nodes.append({
            "id": local_ip,
            "label": f"this server ({local_ip})",
            "ip": local_ip,
            "mac": local_mac,
            "vendor": local_vendor,
            "group": "server",
            "title": f"This Server<br>IP: {local_ip}<br>MAC: {local_mac}<br>Vendor: {local_vendor}",
            "shape": "diamond",
            "size": 25,
        })
        seen_ips.add(local_ip)

        # Edge from local machine to gateway
        if gateway:
            edges.append({"from": local_ip, "to": gateway, "label": "", "dashes": False})

    # Add all ARP devices
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        vendor = d["vendor"]
        group = _get_device_group(vendor)
        hostname = d["hostname"]
        mac = d["mac"]

        # Enrich with scan data if available
        extra = extra_by_ip.get(ip, {})
        ports = extra.get("ports", {})
        os_info = extra.get("os", {})

        open_ports_str = ""
        if ports:
            open_list = [p for p, info in ports.items() if info.get("state") == "open"]
            if open_list:
                open_ports_str = "<br>Open Ports: " + ", ".join(open_list)

        os_str = ""
        if os_info:
            name = os_info.get("name", "") if isinstance(os_info, dict) else str(os_info)
            if name:
                os_str = f"<br>OS: {name}"

        label = hostname or ip
        if group == "iot":
            shape = "box"
            size = 15
        elif group == "mobile":
            shape = "box"
            size = 18
        elif group == "network":
            shape = "hexagon"
            size = 22
        elif group == "server":
            shape = "diamond"
            size = 20
        else:
            shape = "dot"
            size = 18

        nodes.append({
            "id": ip,
            "label": label,
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "group": group,
            "title": (
                f"<b>{label}</b><br>"
                f"IP: {ip}<br>"
                f"MAC: {mac}<br>"
                f"Vendor: {vendor}"
                f"{os_str}"
                f"{open_ports_str}"
            ),
            "shape": shape,
            "size": size,
        })

        # Edge to gateway (star topology for home networks)
        if gateway and ip != gateway:
            edges.append({"from": ip, "to": gateway, "label": "", "dashes": False})

    # ── Tailscale devices ──────────────────────────────────────────
    if tailscale_devices:
        # Find the local machine's Tailscale IP
        local_ts_ip = ""
        for t in tailscale_devices:
            if t["ip"] == local_ip or t["hostname"] == "agentserver":
                local_ts_ip = t["ip"]
                break

        # Try to match each Tailscale device to a LAN device by hostname
        def _find_lan_match(ts_device: dict) -> str | None:
            """Find a LAN IP that matches a Tailscale device."""
            ts_hostname = ts_device["hostname"].lower()
            ts_ip = ts_device["ip"]

            # 1. This server: always connect LAN ↔ Tailscale
            if ts_ip == local_ts_ip and local_ip:
                return local_ip

            # 2. Check if any LAN device's hostname matches
            for d in devices:
                lan_hostname = d.get("hostname", "").lower()
                lan_ip = d["ip"]
                if lan_hostname and (lan_hostname == ts_hostname or ts_hostname.startswith(lan_hostname) or lan_hostname.startswith(ts_hostname)):
                    return lan_ip

            # 3. Check if the hostname appears in any node label
            for n in nodes:
                n_label = n.get("label", "").lower()
                n_id = n.get("id", "")
                if ts_hostname in n_label and n_id not in (local_ip, gateway or ""):
                    return n_id

            return None

        # Track which Tailscale devices are matched to LAN
        matched_lan_ips: set[str] = set()
        ts_hub_needed = False

        for t in tailscale_devices:
            ip = t["ip"]
            if ip in seen_ips:
                continue

            hostname = t["hostname"]
            ts_os = t["os"]
            online = t["online"]
            status_label = "online" if online else "offline"
            lan_match = _find_lan_match(t)

            shape = "dot"
            size = 16
            group = "computer"
            if ts_os == "linux":
                group = "server"
                shape = "diamond"
                size = 18
            elif ts_os == "android":
                group = "mobile"
                shape = "box"
                size = 16
            elif ts_os == "windows":
                group = "computer"
                shape = "dot"
                size = 16

            color = "#3fb950" if online else "#8b949e"
            title = (
                f"<b>{hostname}</b><br>"
                f"Tailscale IP: {ip}<br>"
                f"OS: {ts_os}<br>"
                f"Status: {status_label}"
            )

            seen_ips.add(ip)
            nodes.append({
                "id": ip,
                "label": hostname,
                "ip": ip,
                "mac": "",
                "vendor": "Tailscale",
                "group": group,
                "title": title,
                "shape": shape,
                "size": size,
                "color": color,
            })

            if lan_match:
                # Connect directly to the matching LAN device
                matched_lan_ips.add(lan_match)
                edges.append({
                    "from": ip,
                    "to": lan_match,
                    "label": "Tailscale",
                    "dashes": True,
                    "color": {"color": "#58a6ff", "opacity": 0.5},
                })
                # Also update the LAN node's title to show Tailscale IP
                for n in nodes:
                    if n["id"] == lan_match:
                        n["title"] += f"<br>Tailscale: {ip}"
                        n["label"] = n.get("label", "").replace(f" ({lan_match})", "") + f" ({lan_match})"
                        break
            else:
                # Tailscale-only device — needs the hub
                ts_hub_needed = True
                ts_hub_id = "tailscale-cloud"

                # Create hub on first use
                if ts_hub_id not in seen_ips:
                    nodes.append({
                        "id": ts_hub_id,
                        "label": "Tailscale Mesh",
                        "ip": "100.x.x.x",
                        "mac": "",
                        "vendor": "Tailscale",
                        "group": "network",
                        "title": "<b>Tailscale Mesh</b><br>Virtual overlay network",
                        "shape": "hexagon",
                        "size": 28,
                        "color": "#58a6ff",
                    })
                    seen_ips.add(ts_hub_id)

                edges.append({
                    "from": ip,
                    "to": ts_hub_id,
                    "label": "",
                    "dashes": True,
                    "color": {"color": "#58a6ff", "opacity": 0.5},
                })

    return {"nodes": nodes, "edges": edges}