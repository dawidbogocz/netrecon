"""Output formatters — rich tables, JSON, CSV.

Handles formatting scan results for terminal display (via rich),
JSON export, and CSV export.
"""

import csv
import json
import sys
from io import StringIO

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich.columns import Columns
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Console singleton for consistent output
_console = None


def _get_console():
    global _console
    if _console is None and HAS_RICH:
        _console = Console()
    return _console


def print_results(data: list[dict] | dict, fmt: str = "table"):
    """Print results in the requested format.

    Args:
        data: Scan results (list of dicts or single dict)
        fmt: Output format: "table", "json", or "csv"
    """
    if fmt == "json":
        print_json(data)
    elif fmt == "csv":
        if isinstance(data, dict):
            print_csv([data])
        else:
            print_csv(data)
    else:
        print_table(data)


def print_table(data: list[dict] | dict):
    """Print results as a rich table."""
    if not HAS_RICH:
        print_json(data)
        return

    console = _get_console()
    if isinstance(data, dict):
        data = [data]

    if not data:
        console.print("[yellow]No results[/yellow]")
        return

    # Determine columns from first item
    fieldnames = list(data[0].keys())
    # Skip verbose columns in table view
    skip_fields = {"checks", "parsed", "timestamp", "raw_result"}

    table = Table(box=box.ROUNDED, header_style="bold cyan")
    for field in fieldnames:
        if field not in skip_fields:
            table.add_column(field.replace("_", " ").title(), no_wrap=True)

    for row in data:
        values = []
        for field in fieldnames:
            if field in skip_fields:
                continue
            val = row.get(field)
            if val is None:
                values.append("[dim]—[/dim]")
            elif isinstance(val, bool):
                if val:
                    values.append("[green]Yes[/green]")
                else:
                    values.append("[red]No[/red]")
            elif field == "state":
                if val == "open":
                    values.append(f"[green]{val}[/green]")
                elif val == "closed":
                    values.append(f"[dim]{val}[/dim]")
                elif val == "filtered":
                    values.append(f"[yellow]{val}[/yellow]")
                else:
                    values.append(f"[red]{val}[/red]")
            elif field == "risk_level":
                if val in ("Confirmed Phishing",):
                    values.append(f"[bold red]{val}[/bold red]")
                elif val in ("Likely Phishing",):
                    values.append(f"[bold yellow]{val}[/bold yellow]")
                elif val == "Suspicious":
                    values.append(f"[yellow]{val}[/yellow]")
                else:
                    values.append(f"[green]{val}[/green]")
            elif field == "risk_score":
                try:
                    score = int(val)
                    if score >= 51:
                        values.append(f"[red]{score}[/red]")
                    elif score >= 21:
                        values.append(f"[yellow]{score}[/yellow]")
                    else:
                        values.append(f"[green]{score}[/green]")
                except (ValueError, TypeError):
                    values.append(str(val))
            elif field == "os_guess":
                if val and val != "Unknown":
                    values.append(f"[cyan]{val}[/cyan]")
                else:
                    values.append(f"[dim]{val}[/dim]")
            else:
                values.append(str(val)[:80])

        table.add_row(*values)

    console.print(table)


def print_phish_result(result: dict, fmt: str = "table"):
    """Print phishing analysis results with detailed check breakdown."""
    if fmt == "json":
        print_json(result)
        return

    if not HAS_RICH:
        print_json(result)
        return

    console = _get_console()

    risk_level = result.get("risk_level", "Unknown")
    risk_score = result.get("risk_score", 0)

    # Risk level styling
    level_style = {
        "Safe": "green",
        "Suspicious": "yellow",
        "Likely Phishing": "bold yellow",
        "Confirmed Phishing": "bold red",
        "Invalid URL": "red",
    }.get(risk_level, "white")

    # Summary panel
    summary = (
        f"URL:       [cyan]{result['url']}[/cyan]\n"
        f"Hostname:  {result['parsed'].get('hostname', '')}\n"
        f"Risk:      [{level_style}]{risk_score}/100 - {risk_level}[/{level_style}]"
    )
    console.print(Panel(summary, title="[bold]Phishing Analysis[/bold]", border_style="cyan"))

    # Check breakdown table
    checks = result.get("checks", [])
    if checks:
        check_table = Table(box=box.SIMPLE, header_style="bold")
        check_table.add_column("Check", style="cyan")
        check_table.add_column("Score", justify="right")
        check_table.add_column("Detail")

        for check in checks:
            name = check["name"]
            score = check["score"]
            detail = check["detail"]
            if score > 0:
                score_str = f"[red]+{score}[/red]"
            else:
                score_str = "[green]0[/green]"

            check_table.add_row(name, score_str, detail[:100])

        console.print()
        console.print(check_table)


def print_fingerprint_result(result: dict, fmt: str = "table"):
    """Print OS fingerprinting results."""
    if fmt == "json":
        print_json(result)
        return

    if not HAS_RICH:
        print_json(result)
        return

    console = _get_console()

    os_guess = result.get("os_guess", "Unknown")
    confidence = result.get("confidence", 0)

    if confidence > 70:
        os_style = "bold cyan"
    elif confidence > 40:
        os_style = "cyan"
    else:
        os_style = "dim"

    summary = (
        f"Host:       [cyan]{result['host']}[/cyan]\n"
        f"OS Guess:   [{os_style}]{os_guess}[/{os_style}]\n"
        f"Confidence: {confidence}%\n"
        f"TTL:        {result.get('ttl', 'N/A')}\n"
        f"Window:     {result.get('window_size', 'N/A')}\n"
        f"Method:     {result.get('method', 'N/A')}"
    )
    console.print(Panel(summary, title="[bold]OS Fingerprint[/bold]", border_style="cyan"))


def print_json(data: list[dict] | dict):
    """Print data as formatted JSON."""
    output = json.dumps(data, indent=2, default=str)
    print(output)


def print_csv(data: list[dict]):
    """Print data as CSV to stdout."""
    if not data:
        return

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(data[0].keys()))
    writer.writeheader()
    writer.writerows(data)
    print(output.getvalue(), end="")


def export_results(data: list[dict] | dict, fmt: str, path: str) -> str | None:
    """Export results to a file.

    Args:
        data: Scan results
        fmt: "json" or "csv"
        path: File path to write

    Returns:
        Path if written, None on error
    """
    try:
        if fmt == "json":
            content = json.dumps(data, indent=2, default=str)
        elif fmt == "csv":
            if isinstance(data, dict):
                data = [data]
            output = StringIO()
            if data:
                writer = csv.DictWriter(output, fieldnames=list(data[0].keys()))
                writer.writeheader()
                writer.writerows(data)
            content = output.getvalue()
        else:
            return None

        with open(path, "w") as f:
            f.write(content)
        return path
    except Exception as e:
        logger = __import__("logging").getLogger(__name__)
        logger.error("Failed to export to %s: %s", path, e)
        return None