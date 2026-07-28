"""Output formatters — rich tables, JSON, CSV."""


def print_results(data: list[dict], fmt: str = "table"):
    """Print scan results in the requested format."""
    if fmt == "json":
        print_json(data)
    elif fmt == "csv":
        print_csv(data)
    else:
        print_table(data)


def print_table(data: list[dict]):
    """Print results as a rich table."""
    print(data)


def print_json(data: list[dict]):
    """Print results as JSON."""
    import json
    print(json.dumps(data, indent=2, default=str))


def print_csv(data: list[dict]):
    """Print results as CSV."""
    import csv, sys
    if not data:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(data[0].keys()))
    writer.writeheader()
    writer.writerows(data)


def export_results(data: list[dict], fmt: str, path: str = None) -> str | None:
    """Export results to a file or return as string."""
    return None