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
import os
import sys

import click

from netrecon import __version__
from netrecon.scan import parse_ports, COMMON_PORTS

# Discord webhook URL (optional, set via env var for watch mode)
DISCORD_WEBHOOK = ""

# Module references (lazy-imported in commands to keep CLI fast)
PING = None
SCAN = None
BANNER = None
FINGERPRINT = None
PHISH = None
OUTPUT = None
DNS = None
GEO = None
WATCH = None
REPORT = None
ENHANCED_WATCH = None


def _lazy_import():
    global PING, SCAN, BANNER, FINGERPRINT, PHISH, OUTPUT, DNS, GEO, WATCH, REPORT, ENHANCED_WATCH
    if PING is not None:
        return
    from netrecon import ping as _p
    from netrecon import scan as _s
    from netrecon import banner as _b
    from netrecon import fingerprint as _f
    from netrecon import phish as _ph
    from netrecon import output as _o
    from netrecon import dns as _d
    from netrecon import geo as _g
    from netrecon import watch as _w
    from netrecon import report as _r
    from netrecon import enhanced_watch as _ew
    PING, SCAN, BANNER, FINGERPRINT, PHISH, OUTPUT = _p, _s, _b, _f, _ph, _o
    DNS, GEO, WATCH, REPORT = _d, _g, _w, _r
    ENHANCED_WATCH = _ew


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
        click.echo(f"No responsive hosts found in {target}")
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


# ── dns ────────────────────────────────────────────────────────────

@main.group()
def dns():
    """DNS lookups and subdomain enumeration.

    Examples:

        netrecon dns lookup example.com

        netrecon dns reverse 8.8.8.8

        netrecon dns enum example.com
    """
    pass


@dns.command("lookup")
@click.argument("hostname")
@click.option("--timeout", default=3.0, type=float)
@click.pass_context
def dns_lookup(ctx, hostname, timeout):
    """Look up all DNS record types for a hostname."""
    _lazy_import()
    result = DNS.dns_lookup(hostname, timeout=timeout)
    if not result:
        click.echo(f"No DNS records found for {hostname}")
        return
    OUTPUT.print_results(
        [{"type": k, "value": v[0][0], "ttl": v[0][1]} for k, v in result.items()],
        ctx.obj["output"],
    )
    if ctx.obj.get("output_file"):
        ext = ctx.obj["output"] if ctx.obj["output"] in ("json", "csv") else "json"
        OUTPUT.export_results(result, ext, ctx.obj["output_file"])


@dns.command("reverse")
@click.argument("ip")
@click.option("--timeout", default=3.0, type=float)
@click.pass_context
def dns_reverse(ctx, ip, timeout):
    """Reverse DNS lookup — find hostname for an IP."""
    _lazy_import()
    hostname = DNS.dns_reverse(ip, timeout=timeout)
    if hostname:
        click.echo(f"{ip} -> {hostname}")
    else:
        click.echo(f"No PTR record for {ip}")


@dns.command("enum")
@click.argument("domain")
@click.option("--timeout", default=2.0, type=float)
@click.option("--workers", default=20, type=int)
@click.pass_context
def dns_enum(ctx, domain, timeout, workers):
    """Enumerate subdomains using a built-in wordlist."""
    _lazy_import()
    click.echo(f"Enumerating subdomains of {domain}...", err=True)
    results = DNS.dns_enum(domain, timeout=timeout, workers=workers)
    if results:
        click.echo(f"Found {len(results)} subdomain(s):")
        OUTPUT.print_results(results, ctx.obj["output"])
    else:
        click.echo("No subdomains found")
    if ctx.obj.get("output_file"):
        ext = ctx.obj["output"] if ctx.obj["output"] in ("json", "csv") else "json"
        OUTPUT.export_results(results, ext, ctx.obj["output_file"])


# ── geo ────────────────────────────────────────────────────────────

@main.command()
@click.argument("ip")
@click.option("--timeout", default=3.0, type=float)
@click.pass_context
def geo(ctx, ip, timeout):
    """Look up geolocation data for an IP address.

    Uses ip-api.com (free, no key needed).

    Example: netrecon geo 8.8.8.8
    """
    _lazy_import()
    result = GEO.geo_lookup(ip, timeout=timeout)
    OUTPUT.print_results([result], ctx.obj["output"])


# ── watch ──────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--interval", default=60, type=int, help="Seconds between scans")
@click.option("--iterations", default=0, type=int, help="Number of scans (0=infinite)")
@click.option("--timeout", default=1.0, type=float)
@click.option("--workers", default=50, type=int)
@click.option("--webhook", default=None, help="Discord webhook URL for alerts")
@click.option("--enhanced", is_flag=True, help="Deep scan: port scan, banner grab, OS fingerprint per host")
def watch(target, interval, iterations, timeout, workers, webhook, enhanced):
    """Continuously scan a network and detect changes.

    Scans the target at regular intervals, detects new and offline
    hosts, logs to database, and optionally sends Discord alerts.

    With --enhanced: also scans top 20 ports, grabs banners, fingerprints
    OS on each host and detects port opens/closes and banner changes.

    Examples:

        netrecon watch 192.168.0.1-254 --interval 60

        netrecon watch 192.168.0.1-254 --webhook <url> --interval 300

        netrecon watch 192.168.0.1-254 --enhanced --webhook <url> --interval 120
    """
    _lazy_import()

    if enhanced or os.environ.get("NETRECON_ENHANCED_WATCH"):
        click.echo("Starting enhanced watch (port scans, banners, OS fingerprint)...", err=True)
        watcher = ENHANCED_WATCH.EnhancedWatcher(
            target,
            discord_webhook=webhook or DISCORD_WEBHOOK,
            timeout=timeout,
            workers=workers,
        )
        try:
            watcher.run(interval=interval, iterations=iterations)
        except KeyboardInterrupt:
            click.echo("\nEnhanced watch stopped by user")
            watcher.stop()
        return

    watcher = WATCH.NetworkWatcher(
        target,
        discord_webhook=webhook or DISCORD_WEBHOOK,
        timeout=timeout,
        workers=workers,
    )
    try:
        watcher.run(interval=interval, iterations=iterations)
    except KeyboardInterrupt:
        click.echo("\nWatch stopped by user")
        watcher.stop()


# ── report ─────────────────────────────────────────────────────────

@main.command()
@click.option("--target", default=None, help="Filter by scan target")
@click.option("--scan-id", default=None, help="Report on a specific scan")
@click.option("--output", default="netrecon_report.html", help="Output file path")
def report(target, scan_id, output):
    """Generate an HTML report from scan history.

    Produces a standalone HTML file with results, port maps,
    geolocation maps, and phishing analysis.

    Example: netrecon report --target 192.168.0.0/24
    """
    _lazy_import()
    path = REPORT.generate_report(
        target=target,
        scan_id=scan_id,
        output_path=output,
    )
    click.echo(f"Report generated: {path}")


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