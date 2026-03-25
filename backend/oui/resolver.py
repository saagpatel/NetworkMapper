"""IEEE OUI resolver — download OUI CSV and look up MAC vendor names."""

import csv
import io
import logging
from pathlib import Path

import requests

from config import get_data_dir

logger = logging.getLogger(__name__)

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_DOWNLOAD_TIMEOUT = 60


class OUIResolver:
    """Resolve MAC address prefixes to vendor names using the IEEE OUI database."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir or get_data_dir()
        self._oui_path = self._data_dir / "oui.csv"
        self._table: dict[str, str] = {}
        self._load()

    def _download(self) -> None:
        """Download the IEEE OUI CSV file."""
        logger.info("Downloading OUI database from %s", OUI_URL)
        try:
            resp = requests.get(OUI_URL, timeout=_DOWNLOAD_TIMEOUT, stream=True)
            resp.raise_for_status()
            with open(self._oui_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info("OUI database saved to %s", self._oui_path)
        except requests.RequestException:
            logger.exception("Failed to download OUI database — vendor lookup will be unavailable")

    def _load(self) -> None:
        """Parse the OUI CSV into the lookup table."""
        if not self._oui_path.exists():
            self._download()

        if not self._oui_path.exists():
            logger.warning("OUI database not available — vendor lookup disabled")
            return

        try:
            with open(self._oui_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    assignment = row.get("Assignment", "").strip().upper()
                    org_name = row.get("Organization Name", "").strip()
                    if assignment and org_name:
                        self._table[assignment] = org_name
            logger.info("OUI database loaded: %d entries", len(self._table))
        except (csv.Error, KeyError, UnicodeDecodeError):
            logger.exception("Failed to parse OUI database")
            self._table = {}

    def lookup(self, mac: str) -> str | None:
        """Look up the vendor name for a MAC address.

        Accepts MAC in any common format: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF,
        AABB.CCDD.EEFF, or AABBCCDDEEFF.
        """
        prefix = mac.upper().replace(":", "").replace("-", "").replace(".", "")[:6]
        return self._table.get(prefix)

    @property
    def entry_count(self) -> int:
        """Number of OUI entries loaded."""
        return len(self._table)
