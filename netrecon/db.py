"""SQLite database layer for scan history."""


def save_scan(scan_data: dict) -> str:
    """Save a scan result to the database. Returns scan_id."""
    return ""


def get_scan(scan_id: str) -> dict | None:
    """Retrieve a scan by ID."""
    return None


def get_recent_scans(limit: int = 20) -> list[dict]:
    """Get the most recent scans."""
    return []


def delete_scan(scan_id: str) -> bool:
    """Delete a scan by ID."""
    return False