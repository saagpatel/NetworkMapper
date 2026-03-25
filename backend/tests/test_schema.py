"""Tests for db/schema.py — SQLite schema initialization."""

import sqlite3
from pathlib import Path

from db.schema import init_db

EXPECTED_TABLES = {
    "scan_runs",
    "devices",
    "scan_device_appearances",
    "open_ports",
    "cve_matches",
    "app_config",
}


def test_all_tables_created(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)

    conn = sqlite3.connect(str(db_path))
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    conn.close()

    assert tables == EXPECTED_TABLES


def test_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)
    init_db(db_path)  # Should not raise

    conn = sqlite3.connect(str(db_path))
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    conn.close()

    assert tables == EXPECTED_TABLES


def test_scan_runs_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)

    conn = sqlite3.connect(str(db_path))
    columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_runs)").fetchall()}
    conn.close()

    expected = {"id", "started_at", "completed_at", "target_cidr", "profile", "status", "host_count", "error_msg"}
    assert columns == expected


def test_devices_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)

    conn = sqlite3.connect(str(db_path))
    columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
    conn.close()

    expected = {
        "id", "mac_address", "ip_address", "hostname", "vendor", "device_type",
        "os_guess", "os_accuracy", "first_seen_scan", "last_seen_scan", "risk_score",
    }
    assert columns == expected


def test_indexes_created(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)

    conn = sqlite3.connect(str(db_path))
    indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    conn.close()

    expected_indexes = {
        "idx_scan_runs_started",
        "idx_devices_ip",
        "idx_devices_risk",
        "idx_ports_device",
        "idx_cve_device",
        "idx_cve_severity",
    }
    assert expected_indexes.issubset(indexes)


def test_wal_mode_enabled(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)

    conn = sqlite3.connect(str(db_path))
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()

    assert mode == "wal"
