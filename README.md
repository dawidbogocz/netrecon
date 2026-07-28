# netrecon — Network Reconnaissance Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)

A modular network reconnaissance toolkit with CLI and web dashboard. Supports ping sweeps, port scanning, service banner grabbing, OS fingerprinting, and phishing URL analysis.

## Features

- **Ping Sweep** — ICMP-based host discovery across CIDR ranges (concurrent, with progress)
- **Port Scanning** — TCP Connect (no root) and SYN stealth (scapy, requires root)
- **Banner Grabbing** — Protocol-aware probes to read service banners
- **OS Fingerprinting** — TTL + TCP window size signature matching
- **Phishing URL Analysis** — 8-factor risk scoring (suspicious TLDs, typosquatting, URL shorteners, @-redirects, HTTPS validity, domain age, IP-based hosts, excessive subdomains)
- **Web Dashboard** — FastAPI + htmx, dark terminal aesthetic
- **Export** — Terminal tables (rich), JSON, CSV

## Installation

```bash
pip install netrecon
```

Or from source:

```bash
git clone https://github.com/dawidbogocz/netrecon.git
cd netrecon
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## CLI Usage

```
netrecon ping 192.168.1.0/24
netrecon scan 192.168.1.1 -p 22,80,443
netrecon scan 192.168.1.1 -p 1-1024
netrecon scan 192.168.1.1 --top-ports 100
netrecon scan 192.168.1.1 --syn              # requires root
netrecon banner 192.168.1.1 -p 22,80,443
netrecon fingerprint 192.168.1.1
netrecon phish https://suspicious-link.tk/login
netrecon all 192.168.1.1                     # runs all recon modules
netrecon web --port 8080                     # launch dashboard
```

Global options:

```
--output json|csv     Output format
--output-file path    Write to file
-v                    Verbose debug logging
```

Port specifications:

| Spec | Example | Result |
|------|---------|--------|
| Comma-separated | `-p 22,80,443` | Ports 22, 80, 443 |
| Range | `-p 1-1024` | Ports 1 through 1024 |
| Top ports | `-p top-100` | First 100 common ports |
| Mixed | `-p 22,443,8000-8010` | Combined |

## Dashboard

Start the web dashboard:

```bash
netrecon web --port 8080
```

Then open `http://localhost:8080`. The dashboard lets you run all scan types from the browser with a dark terminal-themed interface. Results are saved to SQLite history.

## Phishing Analysis

The `phish` module scores URLs from 0 (Safe) to 100 (Confirmed Phishing) across 8 categories:

| Check | Weight | What it detects |
|-------|--------|-----------------|
| Suspicious TLD | 15 | `.tk`, `.ml`, `.ga`, `.xyz`, `.top`, etc. |
| URL Shortener | 15 | `bit.ly`, `tinyurl.com`, `t.co`, etc. |
| @ Symbol | 10 | Credential harvesting redirects |
| Excessive Subdomains | 10 | >3 subdomain levels |
| Typosquatting | 15 | Levenshtein matching against 30+ brands |
| IP-based Hostname | 10 | Raw IP instead of domain |
| HTTPS Validity | 10 | Missing/expired/invalid TLS cert |
| Domain Age | 15 | Newly registered domains |

Risk levels: Safe (0-20), Suspicious (21-50), Likely Phishing (51-80), Confirmed Phishing (81-100)

## Project Structure

```
netrecon/
├── netrecon/
│   ├── __init__.py
│   ├── cli.py          # Click CLI entry point
│   ├── ping.py         # Ping sweep module
│   ├── scan.py         # Port scanner (connect + SYN)
│   ├── banner.py       # Service banner grabber
│   ├── fingerprint.py  # OS fingerprinting
│   ├── phish.py        # Phishing URL analyzer
│   ├── output.py       # Rich/JSON/CSV formatters
│   ├── db.py           # SQLite scan history
│   └── web/            # FastAPI + htmx dashboard
│       ├── app.py
│       ├── templates/
│       └── static/
├── tests/
├── pyproject.toml
└── README.md
```

## License

MIT