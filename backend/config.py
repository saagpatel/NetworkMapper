"""Configuration system — data directory management and app_config key-value store."""

import json
import logging
import os
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, str] = {
    "whitelist_cidrs": json.dumps(["192.168.1.0/24"]),
    "schedule_cron": "",
    "nvd_last_updated": "",
    "nvd_download_complete": "0",
}


def get_data_dir() -> Path:
    """Return the NetMapper data directory, creating it if needed."""
    data_dir = Path(os.environ.get("NETMAPPER_DATA_DIR", Path.home() / ".netmapper"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_db_path() -> Path:
    """Return the path to the SQLite database file."""
    return get_data_dir() / "netmapper.db"


class AppConfig:
    """Typed wrapper around the app_config key-value table in SQLite."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or get_db_path()
        self._seed_defaults()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _seed_defaults(self) -> None:
        """Insert default config values if they don't already exist."""
        conn = self._conn()
        try:
            for key, value in _DEFAULTS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO app_config (key, value) VALUES (?, ?)",
                    (key, value),
                )
            conn.commit()
            logger.info("Config defaults seeded")
        finally:
            conn.close()

    def get(self, key: str) -> str | None:
        """Get a config value by key. Returns None if key doesn't exist or value is empty."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT value FROM app_config WHERE key = ?", (key,)
            ).fetchone()
            if row is None or row[0] == "":
                return None
            return row[0]
        finally:
            conn.close()

    def set(self, key: str, value: str) -> None:
        """Set a config value, inserting or updating as needed."""
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO app_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()

    @property
    def whitelist_cidrs(self) -> list[str]:
        """Return the list of whitelisted CIDRs."""
        raw = self.get("whitelist_cidrs")
        if raw is None:
            return []
        return json.loads(raw)

    @property
    def schedule_cron(self) -> str | None:
        """Return the cron schedule expression, or None if disabled."""
        return self.get("schedule_cron")

    @property
    def nvd_download_complete(self) -> bool:
        """Return whether the NVD feed download has completed."""
        return self.get("nvd_download_complete") == "1"

    @property
    def nvd_last_updated(self) -> str | None:
        """Return the ISO datetime of the last NVD feed update."""
        return self.get("nvd_last_updated")
