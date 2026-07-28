"""CLI entry point for netrecon — network reconnaissance toolkit.

Subcommands:
  ping        ICMP ping sweep
  scan        TCP port scan (connect + SYN)
  banner      Service banner grabbing
  fingerprint OS fingerprinting
  phish       Phishing URL analysis
  all         Run all reconnaissance modules on a target
  web         Launch web dashboard
"""

import logging
import sys

import click

from netrecon import __version__
from netrecon.scan import parse_ports, COMMON_PORTS

# Module references (lazy-imported in commands to keep CLI fast)
PING = None
SCAN = None
BANNER = None
FINGERPRINT = None
PHISH = None
OUTPUT = None


def _lazy_import():
    global PING, SCAN, BANNER, FINGERPRINT, PHISH, OUTPUT
    if PING is not None:
        return
    from netrecon import ping as _p
    from netrecon import scan as _s
    from netrecon import banner as _b
    from netrecon import fingerprint as _f
    from netrecon import phish as _ph
    from netrecon import output as _o
    PING, SCAN, BANNER, FINGERPRINT, PHISH, OUTPUT = _p, _s, _b, _f, _ph, _o


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="netrecon")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("--output", type=click.Choice(["table", "json", "csv"]), default="table",
              help="Output format (default: table)")
@click.option("--output-file", type=click.Path(), help="Write results to file")
@click.pass_context
def main(ctx, verbose, output, output_file):
    """netrecon — Network Reconnaissance Toolkit

    A modular toolkit for network exploration and security analysis.
    Supports ping sweeps, port scanning, banner grabbing, OS
    fingerprinting, and phishing URL analysis.
    """
    _setup_logging(verbose)
    _lazy_import()

    # Store global options in context
    ctx.ensure_object(dict)
    ctx.obj["output"] = output
    ctx.obj["output_file"] = output_file

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def _handle_output(data, ctx, extra_formatter=None):
    """Route results to the appropriate output handler based on context settings."""
    fmt = ctx.obj["output"]
    out_file = ctx.obj.get("output_file")

    # Use custom formatter if provided
    if extra_formatter:
        extra_formatter(data, fmt)
    elif isinstance(data, dict):
        OUTPUT.print_results(data, fmt)
    else:
        OUTPUT.print_results(data, fmt)

    # Write to file if requested
    if out_file:
        ext_fmt = fmt if fmt in ("json", "csv") else "json"
        path = OUTPUT.export_results(data, ext_fmt, out_file)
        if path:
            click.echo(f"Results written to {path}", err=True)


# ── ping ──────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--timeout", default=2.0, type=float, help="Ping timeout in seconds")
@click.option("--workers", default=20, type=int, help="Max concurrent pings")
@click.pass_context
def ping(ctx, target, timeout, workers):
    """ICMP ping sweep of a network range.

    Accepts CIDR notation (192.168.1.0/24), IP ranges (192.168.0.1-200),
    or single IPs.

    Examples:

        netrecon ping 192.168.1.0/24

        netrecon ping 192.168.0.1-200

        netrecon ping 192.168.0.1
    """
    _lazy_import()
    results = PING.ping_sweep(target, timeout=timeout, workers=workers)

    if not results:
        click.echo(f"No responsive hosts found in {network}")
        return

    output_data = [{"ip": ip, "status": "alive"} for ip in results]
    click.echo(f"Found {len(results)} responsive host(s):")
    _handle_output(output_data, ctx)


# ── scan ──────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-p", "--ports", default=None, help="Ports: 22,80,443 or 1-1024 or top-100")
@click.option("--syn", is_flag=True, help="Use SYN stealth scan (requires root)")
@click.option("--timeout", default=1.0, type=float, help="Connection timeout per port")
@click.option("--workers", default=50, type=int, help="Max concurrent probes")
@click.pass_context
def scan(ctx, host, ports, syn, timeout, workers):
    """TCP port scan on a host.

    Supports TCP Connect (default) and SYN stealth (--syn, requires root).

    Examples:

        netrecon scan 192.168.1.1

        netrecon scan 192.168.1.1 -p 22,80,443

        netrecon scan 192.168.1.1 -p 1-1024

        netrecon scan 192.168.1.1 --top-ports 100

        netrecon scan 192.168.1.1 --syn (requires root)
    """
    _lazy_import()

    port_list = parse_ports(ports) if ports else COMMON_PORTS

    if syn:
        click.echo("Using SYN stealth scan (may require root)...", err=True)
        results = SCAN.syn_scan(host, port_list, timeout=timeout, workers=workers)
    else:
        click.echo("Using TCP Connect scan...", err=True)
        results = SCAN.tcp_connect_scan(host, port_list, timeout=timeout, workers=workers)

    open_ports = [r for r in results if r["state"] == "open"]
    click.echo(
        f"Scan complete: {len(open_ports)} open port(s) "
        f"of {len(port_list)} scanned",
        err=True,
    )

    _handle_output(results, ctx)


# ── banner ─────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-p", "--ports", required=True, help="Ports: 22,80,443 or 1-1024")
@click.option("--timeout", default=3.0, type=float, help="Connection timeout")
@click.option("--workers", default=10, type=int, help="Max concurrent grabs")
@click.pass_context
def banner(ctx, host, ports, timeout, workers):
    """Grab service banners from open ports.

    Example: netrecon banner 192.168.1.1 -p 22,80,443
    """
    _lazy_import()

    port_list = parse_ports(ports)
    results = BANNER.grab_banners(host, port_list, timeout=timeout, workers=workers)

    with_banner = [r for r in results if r.get("banner")]
    click.echo(
        f"Banner grab complete: {len(with_banner)} with banners",
        err=True,
    )

    _handle_output(results, ctx)


# ── fingerprint ────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("--timeout", default=3.0, type=float, help="Timeout for probes")
@click.pass_context
def fingerprint(ctx, host, timeout):
    """OS fingerprinting via TTL and TCP window analysis.

    Example: netrecon fingerprint 192.168.1.1
    """
    _lazy_import()

    click.echo(f"Fingerprinting {host}...", err=True)
    result = FINGERPRINT.fingerprint_os(host, timeout=timeout)

    OUTPUT.print_fingerprint_result(result, ctx.obj["output"])

    if ctx.obj.get("output_file"):
        ext_fmt = ctx.obj["output"] if ctx.obj["output"] in ("json", "csv") else "json"
        OUTPUT.export_results(result, ext_fmt, ctx.obj["output_file"])


# ── phish ──────────────────────────────────────────────────────────

@main.command()
@click.argument("url")
@click.option("--timeout", default=5.0, type=float, help="Max analysis time")
@click.pass_context
def phish(ctx, url, timeout):
    """Analyze a URL for phishing indicators.

    Performs 8 checks: suspicious TLDs, URL shorteners, @ symbol,
    typosquatting, domain age, HTTPS validity, IP-based hosts,
    and excessive subdomains.

    Example: netrecon phish https://suspicious-link.tk/login
    """
    _lazy_import()

    click.echo(f"Analyzing {url}...", err=True)
    result = PHISH.analyze_url(url, timeout=timeout)

    OUTPUT.print_phish_result(result, ctx.obj["output"])

    if ctx.obj.get("output_file"):
        ext_fmt = ctx.obj["output"] if ctx.obj["output"] in ("json", "csv") else "json"
        OUTPUT.export_results(result, ext_fmt, ctx.obj["output_file"])


# ── all ────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("-p", "--ports", default=None, help="Ports: 22,80,443 or 1-1024")
@click.option("--timeout", default=2.0, type=float, help="Timeout for probes")
@click.pass_context
def all(ctx, target, ports, timeout):
    """Run all reconnaissance modules on a target.

    Runs ping (if CIDR), scan, banner, fingerprint, and phish
    (if URL-like) on the given target.

    Example: netrecon all 192.168.1.1
    """
    _lazy_import()

    is_url = "://" in target or "." in target and "/" in target.split(".")[-1]
    is_cidr = "/" in target

    if is_url:
        click.echo("[1/1] Running phishing URL analysis...", err=True)
        result = PHISH.analyze_url(target, timeout=timeout)
        OUTPUT.print_phish_result(result, ctx.obj["output"])
        return

    if is_cidr:
        # Ping sweep first
        click.echo("[1/4] Running ping sweep...", err=True)
        ping_results = PING.ping_sweep(target, timeout=timeout)
        click.echo(f"  -> {len(ping_results)} responsive host(s)", err=True)

        if not ping_results:
            click.echo("No responsive hosts found. Skipping further scans.")
            return

        # Scan the first responsive host
        target_host = ping_results[0]
        click.echo(f"\n[2/4] Port scanning {target_host}...", err=True)
    else:
        target_host = target
        click.echo(f"[1/3] Port scanning {target_host}...", err=True)

    port_list = parse_ports(ports) if ports else COMMON_PORTS[:10]
    scan_results = SCAN.tcp_connect_scan(target_host, port_list, timeout=timeout, workers=30)

    open_ports = [r for r in scan_results if r["state"] == "open"]
    click.echo(f"  -> {len(open_ports)} open port(s)", err=True)

    # Banner grab on open ports
    if open_ports:
        open_port_nums = [r["port"] for r in open_ports]
        click.echo(f"\n[3/3] Grabbing banners from {len(open_port_nums)} ports...", err=True)
        banner_results = BANNER.grab_banners(target_host, open_port_nums, timeout=timeout)
        with_banner = [r for r in banner_results if r.get("banner")]
        click.echo(f"  -> {len(with_banner)} with banners", err=True)
    else:
        banner_results = []

    # Output
    click.echo("\n=== Ping Results ===")
    OUTPUT.print_results([{"ip": ip, "status": "alive"} for ip in ping_results if is_cidr and ping_results], ctx.obj["output"])

    click.echo("\n=== Port Scan Results ===")
    OUTPUT.print_results(scan_results, ctx.obj["output"])

    click.echo("\n=== Banner Results ===")
    OUTPUT.print_results(banner_results, ctx.obj["output"])

    # Export combined
    if ctx.obj.get("output_file"):
        combined = {
            "target": target_host,
            "ping": ping_results if is_cidr else [],
            "scan": scan_results,
            "banners": banner_results,
        }
        ext_fmt = ctx.obj["output"] if ctx.obj["output"] in ("json", "csv") else "json"
        OUTPUT.export_results(combined, ext_fmt, ctx.obj["output_file"])


# ── web ────────────────────────────────────────────────────────────

@main.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=8080, type=int, help="Bind port")
@click.option("--db", default=None, help="Path to SQLite database file")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development)")
def web(host, port, db, reload):
    """Launch the web dashboard.

    Starts a FastAPI web server with an htmx-powered interface
    for running all netrecon scans from the browser.

    Example: netrecon web --port 8080
    """
    import uvicorn
    from netrecon.web.app import app as web_app

    click.echo(f"Starting netrecon dashboard at http://{host}:{port}")
    click.echo("Press Ctrl+C to stop.")

    uvicorn.run(
        "netrecon.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()