"""HTML report generator — standalone reports from scan history.

Produces a self-contained HTML file with results tables, geolocation
maps (Leaflet.js via CDN), and risk scoring summaries.
"""

import json
import logging
import os
from datetime import datetime, timezone
from html import escape

from netrecon import db as netrecon_db

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>netrecon Report — {title}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 2rem; }}
  h1 {{ color: #58a6ff; font-size: 1.8rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
  h2 {{ color: #58a6ff; font-size: 1.3rem; margin-top: 1.5rem; }}
  .meta {{ color: #8b949e; font-size: 0.9rem; margin-top: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
  th {{ text-align: left; color: #8b949e; border-bottom: 1px solid #30363d; padding: 0.5rem; }}
  td {{ padding: 0.5rem; border-bottom: 1px solid #21262d; }}
  .open {{ color: #3fb950; }} .closed {{ color: #f85149; }} .filtered {{ color: #d29922; }}
  .risk-critical {{ color: #f85149; font-weight: bold; }}
  .risk-high {{ color: #d29922; font-weight: bold; }}
  .risk-medium {{ color: #58a6ff; }}
  .risk-low {{ color: #3fb950; }}
  #map {{ height: 400px; margin-top: 1rem; border-radius: 8px; border: 1px solid #30363d; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
  .badge-success {{ background: #1a3b2a; color: #3fb950; border: 1px solid #3fb950; }}
  .badge-warning {{ background: #3b2e1a; color: #d29922; border: 1px solid #d29922; }}
  .badge-danger {{ background: #3b1f1f; color: #f85149; border: 1px solid #f85149; }}
  .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin-top: 1rem; }}
  .stat {{ display: inline-block; margin-right: 2rem; }}
  .stat-value {{ font-size: 1.5rem; font-weight: bold; }}
  .stat-label {{ font-size: 0.8rem; color: #8b949e; }}
</style>
</head>
<body>
<div class="container">
  <h1>netrecon Report</h1>
  <div class="meta">Generated: {generated} | Target: {target}</div>

  <div class="summary-card">
    <h2>Summary</h2>
    <div class="stat"><div class="stat-value">{total_hosts}</div><div class="stat-label">Hosts Found</div></div>
    <div class="stat"><div class="stat-value">{open_ports}</div><div class="stat-label">Open Ports</div></div>
    <div class="stat"><div class="stat-value">{phish_score}</div><div class="stat-label">Phish Risk</div></div>
  </div>

  {map_section}

  <h2>Hosts</h2>
  {hosts_table}

  <h2>Port Scan</h2>
  {ports_table}

  <h2>Phishing Analysis</h2>
  {phish_section}

  {events_section}
</div>
</body>
</html>"""


def generate_report(
    target: str | None = None,
    scan_id: str | None = None,
    output_path: str = "netrecon_report.html",
    include_map: bool = True,
) -> str:
    """Generate a standalone HTML report.

    Args:
        target: Filter by scan target
        scan_id: Specific scan ID
        output_path: HTML file path to write
        include_map: Include Leaflet.js geolocation map

    Returns:
        Path to generated report
    """
    scans = netrecon_db.get_recent_scans(limit=50)

    # Filter
    if scan_id:
        scan = netrecon_db.get_scan(scan_id)
        scans = [scan] if scan else []
    elif target:
        scans = [s for s in scans if target in s.get("target", "")]

    total_hosts = 0
    open_ports = 0
    phish_score = 0
    hosts_data: list[dict] = []
    ports_data: list[dict] = []
    phish_data: dict = {}
    geo_data: list[dict] = []
    events_data: list[dict] = []

    for scan in scans:
        stype = scan.get("scan_type", "")
        raw = scan.get("raw_result") or {}

        if stype == "ping" and isinstance(raw, list):
            total_hosts += len(raw)
            for h in raw:
                if isinstance(h, dict) and h.get("ip"):
                    hosts_data.append(h)

        elif stype == "scan" and isinstance(raw, list):
            for p in raw:
                if isinstance(p, dict) and p.get("state") == "open":
                    open_ports += 1
                ports_data.append(p)

        elif stype == "phish" and isinstance(raw, dict):
            phish_data = raw
            phish_score = raw.get("risk_score", 0)

    # Geolocation for hosts
    if include_map and hosts_data:
        try:
            from netrecon.geo import geo_lookup_batch
            ips = [h["ip"] for h in hosts_data if h.get("ip")]
            geo_data = geo_lookup_batch(ips)
        except Exception as e:
            logger.warning("Geo lookup for report failed: %s", e)

    # Events
    events_data = netrecon_db.get_recent_events(limit=20)

    # Build map section
    map_section = ""
    if include_map and geo_data:
        locations = []
        for g in geo_data:
            if g.get("lat") and g.get("lon") and g.get("source") != "private":
                locations.append(g)

        if locations:
            points_json = json.dumps([
                {"lat": g["lat"], "lon": g["lon"], "ip": g["ip"],
                 "city": g.get("city", ""), "country": g.get("country", "")}
                for g in locations
            ])
            map_section = f"""
            <h2>Geolocation</h2>
            <div id="map"></div>
            <script>
              var map = L.map('map').setView([20, 0], 2);
              L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                attribution: '&copy; OpenStreetMap'
              }}).addTo(map);
              var points = {points_json};
              points.forEach(function(p) {{
                L.circleMarker([p.lat, p.lon], {{
                  radius: 8, fillColor: '#58a6ff', color: '#fff',
                  weight: 1, fillOpacity: 0.8
                }}).addTo(map).bindPopup(p.ip + '<br>' + p.city + ', ' + p.country);
              }});
              if (points.length > 0) {{
                var bounds = points.map(p => [p.lat, p.lon]);
                map.fitBounds(bounds, {{padding: [50, 50]}});
              }}
            </script>"""

    # Build tables
    hosts_table = _build_hosts_table(hosts_data)
    ports_table = _build_ports_table(ports_data)
    phish_section = _build_phish_section(phish_data)
    events_section = _build_events_section(events_data)

    title = escape(target or "Network Scan")
    generated = datetime.now(timezone.utc).isoformat()[:19]

    html = REPORT_TEMPLATE.format(
        title=title,
        generated=generated,
        target=escape(target or "All scans"),
        total_hosts=total_hosts,
        open_ports=open_ports,
        phish_score=phish_score,
        map_section=map_section,
        hosts_table=hosts_table,
        ports_table=ports_table,
        phish_section=phish_section,
        events_section=events_section,
    )

    with open(output_path, "w") as f:
        f.write(html)

    logger.info("Report written to %s", output_path)
    return output_path


def _build_hosts_table(data: list[dict]) -> str:
    if not data:
        return "<p class='meta'>No host data available.</p>"
    rows = ""
    for h in data:
        ip = escape(h.get("ip", ""))
        status = h.get("status", "unknown")
        cls = {"alive": "open"}.get(status, "")
        rows += f"<tr><td>{ip}</td><td class='{cls}'>{status}</td></tr>\n"
    return f"<table><thead><tr><th>IP</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"


def _build_ports_table(data: list[dict]) -> str:
    if not data:
        return "<p class='meta'>No port scan data available.</p>"
    rows = ""
    for p in data:
        port = p.get("port", "")
        state = p.get("state", "")
        svc = escape(p.get("service", ""))
        cls = {"open": "open", "closed": "closed", "filtered": "filtered"}.get(state, "")
        rows += f"<tr><td>{port}</td><td class='{cls}'>{state}</td><td>{svc}</td></tr>\n"
    return f"<table><thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead><tbody>{rows}</tbody></table>"


def _build_phish_section(data: dict) -> str:
    if not data:
        return "<p class='meta'>No phishing analysis available.</p>"
    score = data.get("risk_score", 0)
    level = data.get("risk_level", "Unknown")
    url = escape(data.get("url", ""))
    cls = {"Safe": "badge-success", "Suspicious": "badge-warning",
           "Likely Phishing": "badge-warning", "Confirmed Phishing": "badge-danger"}.get(level, "")

    checks_html = ""
    for c in data.get("checks", []):
        name = escape(c.get("name", ""))
        sc = c.get("score", 0)
        detail = escape(c.get("detail", ""))
        color = "open" if sc == 0 else "closed"
        checks_html += f"<tr><td>{name}</td><td class='{color}'>+{sc}</td><td>{detail}</td></tr>\n"

    return f"""
    <div class="summary-card">
        <p><strong>URL:</strong> {url}</p>
        <p><strong>Risk: <span class='{cls}'>{score}/100 - {level}</span></strong></p>
    </div>
    <table><thead><tr><th>Check</th><th>Score</th><th>Detail</th></tr></thead><tbody>{checks_html}</tbody></table>
    """


def _build_events_section(data: list[dict]) -> str:
    if not data:
        return ""
    rows = ""
    for e in data:
        ts = e.get("created_at", "")[:19]
        etype = e.get("event_type", "")
        target = escape(e.get("target", ""))
        msg = escape(e.get("message", ""))
        cls = {"join": "open", "leave": "closed", "watch_start": "", "watch_stop": ""}.get(etype, "")
        rows += f"<tr><td>{ts}</td><td class='{cls}'>{etype}</td><td>{target}</td><td>{msg}</td></tr>\n"
    return f"""
    <h2>Events</h2>
    <table><thead><tr><th>Time</th><th>Type</th><th>Target</th><th>Message</th></tr></thead><tbody>{rows}</tbody></table>
    """