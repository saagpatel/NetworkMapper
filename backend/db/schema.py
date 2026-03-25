"""SQLite schema — all CREATE TABLE statements, run on startup."""

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    target_cidr  TEXT NOT NULL,
    profile      TEXT NOT NULL CHECK (profile IN ('quick', 'standard', 'deep')),
    status       TEXT NOT NULL DEFAULT 'running'
                      CHECK (status IN ('running', 'completed', 'failed')),
    host_count   INTEGER DEFAULT 0,
    error_msg    TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at DESC);

CREATE TABLE IF NOT EXISTS devices (
    mac_address     TEXT NOT NULL,
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    vendor          TEXT,
    device_type     TEXT CHECK (device_type IN
                        ('router', 'server', 'workstation', 'mobile', 'iot', 'printer', 'unknown')),
    os_guess        TEXT,
    os_accuracy     INTEGER,
    first_seen_scan INTEGER NOT NULL REFERENCES scan_runs(id),
    last_seen_scan  INTEGER NOT NULL REFERENCES scan_runs(id),
    risk_score      INTEGER NOT NULL DEFAULT 0,
    UNIQUE(mac_address)
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score DESC);

CREATE TABLE IF NOT EXISTS scan_device_appearances (
    scan_run_id  INTEGER NOT NULL REFERENCES scan_runs(id),
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    ip_address   TEXT NOT NULL,
    PRIMARY KEY (scan_run_id, device_id)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL,
    service     TEXT,
    version     TEXT,
    risk_flag   TEXT,
    UNIQUE(device_id, scan_run_id, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_device ON open_ports(device_id, scan_run_id);

CREATE TABLE IF NOT EXISTS cve_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES scan_runs(id),
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    port        INTEGER NOT NULL,
    cve_id      TEXT NOT NULL,
    cvss_score  REAL,
    severity    TEXT CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    description TEXT,
    service     TEXT,
    version     TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_device ON cve_matches(device_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_matches(severity, cvss_score DESC);

CREATE TABLE IF NOT EXISTS app_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def init_db(db_path: Path) -> None:
    """Initialize the database schema. Idempotent — safe to call on every startup."""
    logger.info("Initializing database at %s", db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        logger.info("Database schema initialized successfully")
    finally:
        conn.close()
