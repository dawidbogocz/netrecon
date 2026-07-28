# netrecon — Network Reconnaissance Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)

A modular network reconnaissance toolkit with CLI and web dashboard. Ping sweeps, port scanning, banner grabbing, OS fingerprinting, DNS enumeration, phishing URL analysis, geolocation, continuous network watch with Discord alerts, and HTML reports.

## Features

- **Ping Sweep** — ICMP host discovery. CIDR (`192.168.1.0/24`) or range (`192.168.0.1-200`)
- **Port Scanning** — TCP Connect (no root) and SYN stealth (scapy)
- **Banner Grabbing** — Protocol-aware probes (HTTP, SSH, SMTP, etc.)
- **OS Fingerprinting** — TTL + TCP window signature matching
- **Phishing URL Analysis** — 8-factor risk scoring (suspicious TLDs, typosquatting via Levenshtein, @-redirects, URL shorteners, HTTPS cert inspection, domain age via WHOIS, IP-based hosts, excessive subdomains)
- **DNS Enumeration** — Lookup (A, MX, NS, TXT, SOA, CNAME), reverse DNS, subdomain brute-force
- **Geolocation** — IP location via ip-api.com (free, no key)
- **Network Watch** — Continuous scanning with change detection and Discord webhook alerts
- **HTML Reports** — Standalone reports with tables, maps, and risk scoring
- **Web Dashboard** — FastAPI + htmx + SSE live progress, dark terminal aesthetic
- **Export** — Terminal tables (rich), JSON, CSV

## Installation

```bash
pip install netrecon
```

Or from source:

```bash
git clone https://github.com/dawidbogocz/netrecon.git
cd netrecon
pip install -e ".[dev]"
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `ping <target>` | Ping sweep (CIDR, range, or single IP) |
| `scan <host>` | TCP port scan (`-p 22,80,443`, `-p 1-1024`, `--syn`) |
| `banner <host>` | Service banner grabbing (`-p required`) |
| `fingerprint <host>` | OS fingerprinting |
| `phish <url>` | Phishing URL risk analysis |
| `dns lookup <domain>` | DNS record lookup (A, MX, NS, TXT, SOA, CNAME) |
| `dns reverse <ip>` | Reverse DNS (PTR) lookup |
| `dns enum <domain>` | Subdomain brute-force enumeration |
| `geo <ip>` | IP geolocation |
| `watch <target>` | Continuous network scanner with Discord alerts |
| `report` | Generate HTML report from scan history |
| `all <target>` | Run all recon modules |
| `web` | Launch web dashboard |

Global options: `--output json|csv`, `--output-file <path>`, `-v`

### Examples

```bash
netrecon ping 192.168.0.1-200                     # IP range
netrecon scan 192.168.1.1 -p 22,80,443 --output json
netrecon phish http://paypall.tk@192.168.1.1/login
netrecon dns lookup google.com --timeout 3
netrecon dns reverse 8.8.8.8
netrecon dns enum example.com
netrecon geo 8.8.8.8
netrecon watch 192.168.0.1-254 --interval 60 --webhook <url>
netrecon report --target 192.168.0.0/24 --output scan_report.html
netrecon web --port 8080
```

## Dashboard

```bash
netrecon web --port 8080 --host 0.0.0.0
```

Features:
- Live scan progress via Server-Sent Events (SSE)
- Ping sweep, port scan, banner grab, OS fingerprint, phishing analysis
- Scan history saved to SQLite
- Dark terminal aesthetic

## Watch Mode & Discord Alerts

Monitor your network continuously:

```bash
netrecon watch 192.168.0.1-254 --interval 60 --webhook <discord_webhook_url>
```

Detects new devices (join) and offline devices (leave), logs all events, and sends formatted Discord embeds.

## Project Structure

```
netrecon/
├── netrecon/
│   ├── cli.py          # Click CLI entry point
│   ├── ping.py         # Ping sweep (CIDR + range)
│   ├── scan.py         # Port scanner
│   ├── banner.py       # Service banner grabber
│   ├── fingerprint.py  # OS fingerprinting
│   ├── phish.py        # Phishing URL analyzer
│   ├── dns.py          # DNS lookup + subdomain enum
│   ├── geo.py          # IP geolocation
│   ├── watch.py        # Continuous network watch
│   ├── discord.py      # Discord webhook alerts
│   ├── report.py       # HTML report generator
│   ├── output.py       # Rich/JSON/CSV formatters
│   ├── db.py           # SQLite scan history + events
│   └── web/            # FastAPI + htmx dashboard
│       ├── app.py      # SSE live progress
│       ├── templates/  # Jinja2 templates
│       └── static/     # CSS
├── tests/              # 102 unit tests
└── README.md
```

## License

MIT