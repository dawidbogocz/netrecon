"""SQLite database layer for scan history persistence.

Stores scan results with timestamps, types, targets,
and full result data for the web dashboard history.
"""

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Default database path
DEFAULT_DB_PATH = os.path.join(
    os.path.expanduser("~"),
    ".netrecon",
    "netrecon.db",
)

_local = threading.local()


def _get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Get a thread-local database connection."""
    if db_path is None:
        key = "netrecon_db"
        if not hasattr(_local, key):
            os.makedirs(os.path.dirname(DEFAULT_DB_PATH), exist_ok=True)
            _local.__dict__[key] = _create_connection(DEFAULT_DB_PATH)
        return _local.__dict__[key]
    return _create_connection(db_path)


def _create_connection(db_path: str) -> sqlite3.Connection:
    """Create and initialize a database connection."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    """Create schema tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT DEFAULT 'running',
            summary TEXT,
            raw_result TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scans_started
            ON scans(started_at DESC);

        CREATE INDEX IF NOT EXISTS idx_scans_type
            ON scans(scan_type);
    """)


def save_scan(
    scan_data: dict,
    db_path: str | None = None,
) -> str:
    """Save a scan result to the database.

    Args:
        scan_data: dict with scan_type, target, status, summary, raw_result
        db_path: Optional custom database path

    Returns:
        scan_id string
    """
    scan_id = scan_data.get("id") or str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_connection(db_path)
    conn.execute(
        """INSERT OR REPLACE INTO scans
           (id, scan_type, target, started_at, completed_at, status, summary, raw_result)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id,
            scan_data.get("scan_type", ""),
            scan_data.get("target", ""),
            scan_data.get("started_at", now),
            scan_data.get("completed_at", now),
            scan_data.get("status", "completed"),
            json.dumps(scan_data.get("summary", {})),
            json.dumps(scan_data.get("raw_result", {}), default=str),
        ),
    )
    conn.commit()
    return scan_id


def get_scan(
    scan_id: str,
    db_path: str | None = None,
) -> dict | None:
    """Retrieve a scan by ID.

    Args:
        scan_id: The scan UUID
        db_path: Optional custom database path

    Returns:
        Scan dict or None
    """
    conn = _get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()

    if row is None:
        return None

    return _row_to_dict(row)


def get_recent_scans(
    limit: int = 20,
    scan_type: str | None = None,
    db_path: str | None = None,
) -> list[dict]:
    """Get the most recent scans.

    Args:
        limit: Max number of scans to return
        scan_type: Optional filter (ping, scan, banner, phish)
        db_path: Optional custom database path

    Returns:
        List of scan dicts (without raw_result for efficiency)
    """
    conn = _get_connection(db_path)

    if scan_type:
        rows = conn.execute(
            """SELECT id, scan_type, target, started_at, completed_at,
                      status, summary
               FROM scans
               WHERE scan_type = ?
               ORDER BY started_at DESC
               LIMIT ?""",
            (scan_type, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT id, scan_type, target, started_at, completed_at,
                      status, summary
               FROM scans
               ORDER BY started_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()

    return [_row_to_dict(row) for row in rows]


def delete_scan(scan_id: str, db_path: str | None = None) -> bool:
    """Delete a scan by ID.

    Args:
        scan_id: The scan ID to delete
        db_path: Optional custom database path

    Returns:
        True if deleted, False if not found
    """
    conn = _get_connection(db_path)
    cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    return cursor.rowcount > 0


def get_stats(db_path: str | None = None) -> dict:
    """Get summary statistics about stored scans.

    Args:
        db_path: Optional custom database path

    Returns:
        dict with total_scans, per_type counts, latest_scan timestamp
    """
    conn = _get_connection(db_path)
    total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]

    type_counts = {
        row["scan_type"]: row["c"]
        for row in conn.execute(
            "SELECT scan_type, COUNT(*) as c FROM scans GROUP BY scan_type"
        ).fetchall()
    }

    latest = conn.execute(
        "SELECT started_at FROM scans ORDER BY started_at DESC LIMIT 1"
    ).fetchone()

    return {
        "total_scans": total,
        "by_type": type_counts,
        "latest_scan": latest["started_at"] if latest else None,
    }


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a regular dict with parsed JSON fields."""
    result = dict(row)

    # Parse JSON fields back to dicts
    for field in ("summary", "raw_result"):
        if field in result and isinstance(result[field], str):
            try:
                result[field] = json.loads(result[field])
            except (json.JSONDecodeError, TypeError):
                pass

    return result