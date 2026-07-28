"""FastAPI web application for netrecon dashboard.

Provides an htmx-powered web interface for running all netrecon
reconnaissance tools from the browser.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import os

from netrecon import ping, scan, banner, fingerprint, phish
from netrecon import db as netrecon_db
from netrecon.scan import parse_ports

logger = logging.getLogger(__name__)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="netrecon", description="Network Reconnaissance Dashboard")

# Use Jinja2 directly instead of Starlette's wrapper to avoid cache issues
import jinja2
from jinja2 import Environment, FileSystemLoader, select_autoescape

_jinja_env = Environment(
    loader=FileSystemLoader(templates_dir),
    autoescape=select_autoescape(),
    cache_size=50,
)

app.mount("/static", StaticFiles(directory=static_dir), name="static")


def _render(name: str, **context) -> str:
    """Render a Jinja2 template to string."""
    template = _jinja_env.get_template(name)
    return template.render(**context)


# ── HTML Pages ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Dashboard home page."""
    html = _render("index.html", request=request)
    return HTMLResponse(html)


@app.get("/history", response_class=HTMLResponse)
async def history_partial(request: Request):
    """HTMX partial: recent scans sidebar."""
    recent = netrecon_db.get_recent_scans(limit=15)
    html = _render("_history.html", request=request, scans=recent)
    return HTMLResponse(html)


# ── Scan Endpoints ────────────────────────────────────────────────

@app.get("/scan", response_class=HTMLResponse)
async def scan_endpoint(
    request: Request,
    target: str = Query(...),
    mode: str = Query("ping"),
    ports: str | None = Query(None),
    timeout: float = Query(2.0),
):
    """Route scans to the appropriate module based on mode."""
    scan_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()

    try:
        if mode == "ping":
            result, summary = _run_ping(target, timeout)
        elif mode == "scan":
            result, summary = _run_scan(target, ports, timeout)
        elif mode == "banner":
            result, summary = _run_banner(target, ports, timeout)
        elif mode == "fingerprint":
            result, summary = _run_fingerprint(target, timeout)
        elif mode == "phish":
            result, summary = _run_phish(target, timeout)
        else:
            return HTMLResponse(f"<p class='error'>Unknown mode: {mode}</p>")

        netrecon_db.save_scan({
            "id": scan_id,
            "scan_type": mode,
            "target": target,
            "started_at": now,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "summary": summary,
            "raw_result": result,
        })

        html = _render(
            f"_result_{mode}.html",
            request=request,
            target=target,
            result=result,
            scan_id=scan_id,
        )
        return HTMLResponse(html)

    except Exception as e:
        logger.exception("Scan failed")
        return HTMLResponse(
            f'<div class="error-panel"><h3>Scan Failed</h3>'
            f'<p>{str(e)}</p></div>'
        )


@app.get("/scan/{scan_id}", response_class=JSONResponse)
async def get_scan_result(scan_id: str):
    """Get a saved scan result."""
    result = netrecon_db.get_scan(scan_id)
    if result is None:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return JSONResponse(result)


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
    summary = {
        "ports_scanned": len(port_list),
        "open_count": len(open_ports),
        "open_ports": [r["port"] for r in open_ports],
    }
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