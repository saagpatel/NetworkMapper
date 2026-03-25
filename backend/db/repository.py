"""SQLite repository — all read/write operations for scan data."""

import logging
import sqlite3
from datetime import datetime, UTC
from pathlib import Path

logger = logging.getLogger(__name__)


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Create a database connection with standard settings."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# --- Scan Runs ---


def create_scan_run(conn: sqlite3.Connection, target_cidr: str, profile: str) -> int:
    """Create a new scan run. Returns the scan_run id."""
    cursor = conn.execute(
        "INSERT INTO scan_runs (target_cidr, profile, status) VALUES (?, ?, 'running')",
        (target_cidr, profile),
    )
    conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


def update_scan_run(
    conn: sqlite3.Connection,
    scan_id: int,
    *,
    status: str | None = None,
    host_count: int | None = None,
    completed_at: str | None = None,
    error_msg: str | None = None,
) -> None:
    """Update fields on a scan run."""
    updates: list[str] = []
    params: list[object] = []

    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if host_count is not None:
        updates.append("host_count = ?")
        params.append(host_count)
    if completed_at is not None:
        updates.append("completed_at = ?")
        params.append(completed_at)
    if error_msg is not None:
        updates.append("error_msg = ?")
        params.append(error_msg)

    if not updates:
        return

    params.append(scan_id)
    conn.execute(f"UPDATE scan_runs SET {', '.join(updates)} WHERE id = ?", params)
    conn.commit()


def get_scan_run(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """Get a single scan run by ID."""
    row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def list_scan_runs(
    conn: sqlite3.Connection, cursor: int | None = None, limit: int = 20
) -> tuple[list[dict], int | None]:
    """List scan runs with cursor-based pagination. Returns (rows, next_cursor)."""
    if cursor is not None:
        rows = conn.execute(
            "SELECT * FROM scan_runs WHERE id < ? ORDER BY id DESC LIMIT ?",
            (cursor, limit + 1),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit + 1,)
        ).fetchall()

    result = [dict(r) for r in rows[:limit]]
    next_cursor = result[-1]["id"] if len(rows) > limit else None
    return result, next_cursor


# --- Devices ---


def upsert_device(
    conn: sqlite3.Connection,
    *,
    mac_address: str,
    ip_address: str,
    hostname: str | None,
    vendor: str | None,
    device_type: str,
    os_guess: str | None,
    os_accuracy: int,
    scan_id: int,
    risk_score: int,
) -> int:
    """Insert or update a device keyed on mac_address. Returns device id.

    On conflict: updates ip, hostname, vendor, device_type, os_guess, os_accuracy,
    last_seen_scan, and risk_score. Preserves first_seen_scan.
    """
    cursor = conn.execute(
        """
        INSERT INTO devices (
            mac_address, ip_address, hostname, vendor, device_type,
            os_guess, os_accuracy, first_seen_scan, last_seen_scan, risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            ip_address = excluded.ip_address,
            hostname = COALESCE(excluded.hostname, devices.hostname),
            vendor = COALESCE(excluded.vendor, devices.vendor),
            device_type = excluded.device_type,
            os_guess = COALESCE(excluded.os_guess, devices.os_guess),
            os_accuracy = CASE
                WHEN excluded.os_accuracy > devices.os_accuracy
                THEN excluded.os_accuracy ELSE devices.os_accuracy
            END,
            last_seen_scan = excluded.last_seen_scan,
            risk_score = excluded.risk_score
        """,
        (
            mac_address, ip_address, hostname, vendor, device_type,
            os_guess, os_accuracy, scan_id, scan_id, risk_score,
        ),
    )
    conn.commit()

    # Get the device id (works for both insert and update)
    row = conn.execute(
        "SELECT id FROM devices WHERE mac_address = ?", (mac_address,)
    ).fetchone()
    return row["id"]  # type: ignore[index]


def get_device(conn: sqlite3.Connection, device_id: int) -> dict | None:
    """Get a single device by ID."""
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return dict(row) if row else None


def list_devices(conn: sqlite3.Connection) -> list[dict]:
    """List all known devices ordered by risk score descending."""
    rows = conn.execute("SELECT * FROM devices ORDER BY risk_score DESC").fetchall()
    return [dict(r) for r in rows]


# --- Ports ---


def insert_port(
    conn: sqlite3.Connection,
    *,
    device_id: int,
    scan_run_id: int,
    port: int,
    protocol: str,
    state: str,
    service: str | None,
    version: str | None,
    risk_flag: str | None,
) -> None:
    """Insert a port result for a device in a scan."""
    conn.execute(
        """
        INSERT OR IGNORE INTO open_ports
            (device_id, scan_run_id, port, protocol, state, service, version, risk_flag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, scan_run_id, port, protocol, state, service, version, risk_flag),
    )
    conn.commit()


def get_device_ports(
    conn: sqlite3.Connection, device_id: int, scan_run_id: int | None = None
) -> list[dict]:
    """Get ports for a device, optionally filtered by scan run.

    If scan_run_id is None, returns ports from the most recent scan.
    """
    if scan_run_id is not None:
        rows = conn.execute(
            "SELECT port, protocol, state, service, version, risk_flag "
            "FROM open_ports WHERE device_id = ? AND scan_run_id = ? ORDER BY port",
            (device_id, scan_run_id),
        ).fetchall()
    else:
        # Get ports from the latest scan for this device
        rows = conn.execute(
            """
            SELECT op.port, op.protocol, op.state, op.service, op.version, op.risk_flag
            FROM open_ports op
            JOIN devices d ON d.id = op.device_id
            WHERE op.device_id = ? AND op.scan_run_id = d.last_seen_scan
            ORDER BY op.port
            """,
            (device_id,),
        ).fetchall()

    return [dict(r) for r in rows]


# --- Scan Device Appearances ---


def insert_appearance(
    conn: sqlite3.Connection, scan_run_id: int, device_id: int, ip_address: str
) -> None:
    """Record a device appearing in a scan."""
    conn.execute(
        "INSERT OR IGNORE INTO scan_device_appearances (scan_run_id, device_id, ip_address) "
        "VALUES (?, ?, ?)",
        (scan_run_id, device_id, ip_address),
    )
    conn.commit()


# --- CVE Matches ---


def insert_cve_match(
    conn: sqlite3.Connection,
    *,
    device_id: int,
    scan_run_id: int,
    port: int,
    cve_id: str,
    cvss_score: float | None,
    severity: str | None,
    description: str,
    service: str | None,
    version: str | None,
) -> None:
    """Insert a CVE match for a device port in a scan."""
    conn.execute(
        """
        INSERT INTO cve_matches
            (device_id, scan_run_id, port, cve_id, cvss_score, severity,
             description, service, version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, scan_run_id, port, cve_id, cvss_score, severity,
         description, service, version),
    )
    conn.commit()


def get_device_cve_matches(
    conn: sqlite3.Connection, device_id: int, scan_run_id: int | None = None
) -> list[dict]:
    """Get CVE matches for a device. Returns empty list until Phase 2."""
    if scan_run_id is not None:
        rows = conn.execute(
            "SELECT cve_id, cvss_score, severity, description, port, service, version "
            "FROM cve_matches WHERE device_id = ? AND scan_run_id = ? "
            "ORDER BY cvss_score DESC",
            (device_id, scan_run_id),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT cm.cve_id, cm.cvss_score, cm.severity, cm.description,
                   cm.port, cm.service, cm.version
            FROM cve_matches cm
            JOIN devices d ON d.id = cm.device_id
            WHERE cm.device_id = ? AND cm.scan_run_id = d.last_seen_scan
            ORDER BY cm.cvss_score DESC
            """,
            (device_id,),
        ).fetchall()

    return [dict(r) for r in rows]
