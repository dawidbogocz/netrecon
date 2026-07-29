"""FastAPI web application for netrecon dashboard.

Provides an htmx-powered web interface with SSE live progress
for all netrecon reconnaissance tools.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import jinja2
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os

from netrecon import ping, scan, banner, fingerprint, phish
from netrecon import dns as netrecon_dns
from netrecon import geo as netrecon_geo
from netrecon import watch as netrecon_watch
from netrecon import enhanced_watch as netrecon_enhanced_watch
from netrecon import topo as netrecon_topo
from netrecon import db as netrecon_db
from netrecon.scan import parse_ports

logger = logging.getLogger(__name__)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="netrecon", description="Network Reconnaissance Dashboard")

_jinja_env = Environment(
    loader=FileSystemLoader(templates_dir),
    autoescape=select_autoescape(),
    cache_size=50,
)

app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ── In-memory scan progress store ─────────────────────────────────
_scan_progress: dict[str, dict] = {}


def _render(name: str, **context) -> str:
    template = _jinja_env.get_template(name)
    return template.render(**context)


# ── HTML Pages ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    html = _render("index.html", request=request)
    return HTMLResponse(html)


@app.get("/history", response_class=HTMLResponse)
async def history_partial(request: Request):
    recent = netrecon_db.get_recent_scans(limit=15)
    html = _render("_history.html", request=request, scans=recent)
    return HTMLResponse(html)


# ── SSE Progress Stream ────────────────────────────────────────────

@app.get("/scan/stream/{scan_id}")
async def scan_stream(scan_id: str):
    """SSE endpoint that streams scan progress events."""

    async def event_generator() -> AsyncGenerator[str, None]:
        while True:
            progress = _scan_progress.get(scan_id)
            if progress is None:
                yield f"event: error\ndata: scan not found\n\n"
                break
            if progress.get("status") == "complete":
                yield f"event: complete\ndata: {json.dumps(progress)}\n\n"
                break
            if progress.get("status") == "error":
                yield f"event: error\ndata: {json.dumps(progress)}\n\n"
                break
            # Send current progress
            yield f"event: progress\ndata: {json.dumps(progress)}\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _update_progress(scan_id: str, **kwargs):
    """Update scan progress in the in-memory store."""
    if scan_id in _scan_progress:
        _scan_progress[scan_id].update(kwargs)


async def _run_scan_with_progress(
    scan_id: str,
    target: str,
    mode: str,
    ports: str | None,
    timeout: float,
):
    """Run a scan in the background, updating progress via SSE."""
    try:
        _scan_progress[scan_id] = {
            "status": "running",
            "mode": mode,
            "target": target,
            "progress": 0,
            "message": "Starting scan...",
        }

        result = None
        summary = None

        if mode == "ping":
            await _update_progress(scan_id, message="Pinging hosts...", progress=10)
            result, summary = _run_ping(target, timeout)
            await _update_progress(scan_id, message=f"Found {len(result)} host(s)", progress=100)

        elif mode == "scan":
            port_list = parse_ports(ports) if ports else scan.COMMON_PORTS
            total = len(port_list)
            await _update_progress(scan_id, message=f"Scanning {total} ports...", progress=10)

            def progress_callback(done: int):
                pct = min(95, 10 + int(done / total * 80))
                _scan_progress[scan_id]["progress"] = pct
                _scan_progress[scan_id]["message"] = f"Scanning {done}/{total} ports..."

            result = scan.tcp_connect_scan(target, port_list, timeout=timeout)
            open_ports = [r for r in result if r["state"] == "open"]
            summary = {"ports_scanned": total, "open_count": len(open_ports)}
            await _update_progress(scan_id, message=f"{len(open_ports)} open ports found", progress=100)

        elif mode == "banner":
            port_list = parse_ports(ports) if ports else [22, 80, 443, 8080]
            await _update_progress(scan_id, message="Grabbing banners...", progress=10)
            result = banner.grab_banners(target, port_list, timeout=timeout)
            with_banner = [r for r in result if r.get("banner")]
            summary = {"ports_checked": len(port_list), "banners_found": len(with_banner)}
            await _update_progress(scan_id, message=f"{len(with_banner)} banners found", progress=100)

        elif mode == "fingerprint":
            await _update_progress(scan_id, message="Fingerprinting OS...", progress=30)
            result = fingerprint.fingerprint_os(target, timeout=timeout)
            summary = {"os_guess": result.get("os_guess"), "confidence": result.get("confidence")}
            await _update_progress(scan_id, message=f"OS: {result.get('os_guess', 'Unknown')}", progress=100)

        elif mode == "phish":
            await _update_progress(scan_id, message="Analyzing URL...", progress=20)
            result = phish.analyze_url(target, timeout=timeout)
            checks = result.get("checks", [])
            summary = {
                "risk_score": result.get("risk_score"),
                "risk_level": result.get("risk_level"),
            }
            await _update_progress(scan_id, message=f"Risk: {result.get('risk_level', 'Unknown')}", progress=100)

        # Save result
        now = datetime.now(timezone.utc).isoformat()
        netrecon_db.save_scan({
            "id": scan_id,
            "scan_type": mode,
            "target": target,
            "started_at": now,
            "completed_at": now,
            "status": "completed",
            "summary": summary,
            "raw_result": result,
        })

        # Render the result partial HTML
        html = _render(f"_result_{mode}.html", target=target, result=result, scan_id=scan_id)
        _scan_progress[scan_id] = {
            "status": "complete",
            "html": html,
        }

    except Exception as e:
        logger.exception("Scan failed")
        _scan_progress[scan_id] = {
            "status": "error",
            "error": str(e),
        }


# ── Scan Trigger ──────────────────────────────────────────────────

@app.get("/scan", response_class=HTMLResponse)
async def scan_endpoint(
    request: Request,
    target: str = Query(...),
    mode: str = Query("ping"),
    ports: str | None = Query(None),
    timeout: float = Query(2.0),
):
    """Trigger a scan. Returns immediate HTML with SSE progress."""
    scan_id = str(uuid.uuid4())[:12]

    # Start background task
    asyncio.create_task(
        _run_scan_with_progress(scan_id, target, mode, ports, timeout)
    )

    # Return a placeholder that connects to SSE
    return HTMLResponse(
        _render("_scan_loading.html", scan_id=scan_id, mode=mode, target=target)
    )


# ── DNS ──────────────────────────────────────────────────────────

@app.get("/dns", response_class=HTMLResponse)
async def dns_endpoint(
    request: Request,
    target: str = Query(...),
    mode: str = Query("lookup"),
    timeout: float = Query(3.0),
):
    """DNS lookup, reverse DNS, or subdomain enumeration."""
    scan_id = str(uuid.uuid4())[:12]

    asyncio.create_task(
        _run_dns_with_progress(scan_id, target, mode, timeout)
    )

    return HTMLResponse(
        _render("_scan_loading.html", scan_id=scan_id, mode=f"dns/{mode}", target=target)
    )


async def _run_dns_with_progress(scan_id: str, target: str, mode: str, timeout: float):
    try:
        _scan_progress[scan_id] = {"status": "running", "mode": f"dns/{mode}", "target": target, "progress": 0, "message": "Starting DNS query..."}

        if mode == "reverse":
            await _update_progress(scan_id, message="Looking up PTR record...", progress=30)
            hostname = netrecon_dns.dns_reverse(target, timeout=timeout)
            await _update_progress(scan_id, message="Done", progress=100)
            result = hostname
            html = _render("_result_dns_reverse.html", target=target, result=result, scan_id=scan_id)
        elif mode == "enum":
            await _update_progress(scan_id, message="Enumerating subdomains...", progress=20)
            subdomains = netrecon_dns.dns_enum(target, timeout=timeout)
            await _update_progress(scan_id, message=f"Found {len(subdomains)} subdomains", progress=100)
            result = {"subdomains": subdomains}
            html = _render("_result_dns_enum.html", target=target, result=subdomains, scan_id=scan_id)
        else:
            await _update_progress(scan_id, message="Looking up DNS records...", progress=30)
            records = netrecon_dns.dns_lookup(target, timeout=timeout)
            await _update_progress(scan_id, message=f"Found {sum(len(v) for v in records.values())} records", progress=100)
            result = records
            html = _render("_result_dns.html", target=target, result=records, scan_id=scan_id)

        now = datetime.now(timezone.utc).isoformat()
        netrecon_db.save_scan({
            "id": scan_id, "scan_type": f"dns/{mode}", "target": target,
            "started_at": now, "completed_at": now, "status": "completed",
            "summary": {"mode": mode, "target": target},
            "raw_result": str(result)[:5000],
        })
        _scan_progress[scan_id] = {"status": "complete", "html": html}
    except Exception as e:
        logger.exception("DNS lookup failed")
        html = _render("_result_dns.html", target=target, error=str(e), scan_id=scan_id)
        _scan_progress[scan_id] = {"status": "complete", "html": html}


# ── Geo ──────────────────────────────────────────────────────────

@app.get("/geo", response_class=HTMLResponse)
async def geo_endpoint(
    request: Request,
    target: str = Query(...),
    timeout: float = Query(3.0),
):
    """Geolocation lookup for an IP address."""
    scan_id = str(uuid.uuid4())[:12]

    asyncio.create_task(
        _run_geo_with_progress(scan_id, target, timeout)
    )

    return HTMLResponse(
        _render("_scan_loading.html", scan_id=scan_id, mode="geo", target=target)
    )


async def _run_geo_with_progress(scan_id: str, target: str, timeout: float):
    try:
        _scan_progress[scan_id] = {"status": "running", "mode": "geo", "target": target, "progress": 0, "message": "Looking up geolocation..."}

        await _update_progress(scan_id, message="Querying ip-api.com...", progress=50)
        result = netrecon_geo.geo_lookup(target, timeout=timeout)
        await _update_progress(scan_id, message="Done", progress=100)

        now = datetime.now(timezone.utc).isoformat()
        netrecon_db.save_scan({
            "id": scan_id, "scan_type": "geo", "target": target,
            "started_at": now, "completed_at": now, "status": "completed",
            "summary": {"ip": result.get("ip"), "country": result.get("country"), "city": result.get("city")},
            "raw_result": result,
        })
        html = _render("_result_geo.html", target=target, result=result, scan_id=scan_id)
        _scan_progress[scan_id] = {"status": "complete", "html": html}
    except Exception as e:
        logger.exception("Geo lookup failed")
        html = _render("_result_geo.html", target=target, error=str(e), scan_id=scan_id)
        _scan_progress[scan_id] = {"status": "complete", "html": html}


# ── Watch ────────────────────────────────────────────────────────

@app.get("/watch", response_class=HTMLResponse)
async def watch_endpoint(
    request: Request,
    target: str = Query(...),
    interval: int = Query(60),
    iterations: int = Query(5),
    timeout: float = Query(1.0),
    webhook: str | None = Query(None),
    enhanced: str | None = Query(None),
):
    """Run a basic or enhanced watch scan."""
    scan_id = str(uuid.uuid4())[:12]
    is_enhanced = enhanced == "1"

    asyncio.create_task(
        _run_watch_with_progress(scan_id, target, interval, iterations, timeout, webhook, is_enhanced)
    )

    return HTMLResponse(
        _render("_scan_loading.html", scan_id=scan_id, mode="watch" + (" (enhanced)" if is_enhanced else ""), target=target)
    )


async def _run_watch_with_progress(scan_id: str, target: str, interval: int, iterations: int, timeout: float, webhook: str | None, enhanced: bool = False):
    try:
        _scan_progress[scan_id] = {"status": "running", "mode": "watch", "target": target, "progress": 0, "message": "Starting watch..."}

        # Create watcher ONCE so previous_hosts persists across iterations
        if enhanced:
            watcher = netrecon_enhanced_watch.EnhancedWatcher(
                target, discord_webhook=webhook, timeout=timeout,
            )
        else:
            watcher = netrecon_watch.NetworkWatcher(
                target, discord_webhook=webhook, timeout=timeout,
            )

        results = []
        for i in range(iterations):
            await _update_progress(scan_id, message=f"Scan {i+1}/{iterations}...", progress=int((i / iterations) * 90))

            if enhanced:
                scan_result = watcher._do_enhanced_scan()
                # Only send Discord when things actually change
                if webhook and scan_result.get("has_changes") and i > 0:
                    watcher._send_discord_summary(scan_result)
            else:
                scan_result = watcher._do_scan()

            results.append(scan_result)
            if i < iterations - 1:
                import asyncio
                await asyncio.sleep(interval)

        await _update_progress(scan_id, message=f"{iterations} scans complete", progress=100)

        last_result = results[-1] if results else {}

        now = datetime.now(timezone.utc).isoformat()
        netrecon_db.save_scan({
            "id": scan_id, "scan_type": "watch" + ("-enhanced" if enhanced else ""), "target": target,
            "started_at": now, "completed_at": now, "status": "completed",
            "summary": {"scans": len(results), "total_hosts": last_result.get("total_hosts", 0), "enhanced": enhanced},
            "raw_result": {"results": results} if results else {},
        })

        html = _render("_result_watch.html", target=target, result=last_result, scan_id=scan_id, enhanced=enhanced)
        _scan_progress[scan_id] = {"status": "complete", "html": html}
    except Exception as e:
        logger.exception("Watch scan failed")
        html = _render("_result_watch.html", target=target, error=str(e), scan_id=scan_id)
        _scan_progress[scan_id] = {"status": "complete", "html": html}


# ── Internal Scan Runners ─────────────────────────────────────────


# ── Topology ──────────────────────────────────────────────────────


@app.get("/topology", response_class=JSONResponse)
async def topology_endpoint():
    """Return the current network topology as JSON for vis.js."""
    graph = netrecon_topo.build_topology()
    return JSONResponse(graph)


# ── Internal Scan Runners ─────────────────────────────────────────

def _run_ping(target: str, timeout: float):
    hosts = ping.ping_sweep(target, timeout=timeout)
    summary = {"hosts_found": len(hosts), "hosts": hosts[:50]}
    result = [{"ip": ip, "status": "alive"} for ip in hosts]
    return result, summary


def _run_scan(target: str, ports_str: str | None, timeout: float):
    port_list = parse_ports(ports_str) if ports_str else scan.COMMON_PORTS
    results = scan.tcp_connect_scan(target, port_list, timeout=timeout)
    open_ports = [r for r in results if r["state"] == "open"]
    summary = {"ports_scanned": len(port_list), "open_count": len(open_ports)}
    return results, summary


def _run_banner(target: str, ports_str: str | None, timeout: float):
    port_list = parse_ports(ports_str) if ports_str else [22, 80, 443, 8080]
    results = banner.grab_banners(target, port_list, timeout=timeout)
    with_banner = [r for r in results if r.get("banner")]
    summary = {"ports_checked": len(port_list), "banners_found": len(with_banner)}
    return results, summary


def _run_fingerprint(target: str, timeout: float):
    result = fingerprint.fingerprint_os(target, timeout=timeout)
    summary = {"os_guess": result.get("os_guess"), "confidence": result.get("confidence")}
    return result, summary


def _run_phish(target: str, timeout: float):
    result = phish.analyze_url(target, timeout=timeout)
    checks = result.get("checks", [])
    summary = {
        "risk_score": result.get("risk_score"),
        "risk_level": result.get("risk_level"),
        "checks_passed": sum(1 for c in checks if c.get("passed") and c.get("score", 0) > 0),
    }
    return result, summary