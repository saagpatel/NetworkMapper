"""In-memory CPE → CVE lookup index built from NVD data."""

import logging
import re
from pathlib import Path

from cve.loader import parse_cve_page
from models.internal import CVERecord

logger = logging.getLogger(__name__)

# Maps common nmap service names to NVD product names
SERVICE_ALIASES: dict[str, list[str]] = {
    "ssh": ["openssh"],
    "openssh": ["openssh"],
    "http": ["apache http server", "nginx", "httpd", "lighttpd", "iis"],
    "apache": ["apache http server", "httpd"],
    "nginx": ["nginx"],
    "mysql": ["mysql", "mariadb"],
    "mariadb": ["mariadb"],
    "postgresql": ["postgresql"],
    "ftp": ["vsftpd", "proftpd", "pure-ftpd"],
    "vsftpd": ["vsftpd"],
    "proftpd": ["proftpd"],
    "smtp": ["postfix", "exim", "sendmail"],
    "postfix": ["postfix"],
    "exim": ["exim"],
    "dns": ["bind", "dnsmasq"],
    "bind": ["bind"],
    "isc bind": ["bind"],
    "samba": ["samba"],
    "smb": ["samba"],
    "vnc": ["realvnc", "tigervnc", "tightvnc", "libvnc"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "memcached": ["memcached"],
    "elasticsearch": ["elasticsearch"],
    "rabbitmq": ["rabbitmq"],
    "docker": ["docker"],
    "openssl": ["openssl"],
    "tomcat": ["apache tomcat", "tomcat"],
    "jetty": ["jetty"],
    "iis": ["internet information services", "iis"],
}


def _normalize_service(service: str) -> str:
    """Normalize an nmap service name for index lookup."""
    return service.lower().strip().replace("_", " ")


def _normalize_product(product: str) -> str:
    """Normalize a CPE product name for index storage."""
    name = product.lower().strip().replace("_", " ")
    # Remove common suffixes
    for suffix in (" server", " daemon", " service"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def _extract_version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple of integers."""
    # Strip common prefixes/suffixes
    clean = re.sub(r"[a-zA-Z].*$", "", version.strip())
    parts = re.split(r"[.\-_]", clean)
    try:
        return tuple(int(p) for p in parts if p)
    except ValueError:
        return None


def _version_matches(service_version: str, cve_versions: list[str]) -> bool:
    """Check if a service version matches any of the CVE's affected versions.

    Uses prefix matching: if CVE lists "8.0" and service reports "8.0p1", match.
    Also does numeric tuple comparison for range-style checks.
    """
    if not cve_versions:
        # CVE applies to all versions of the product
        return True

    sv_clean = service_version.lower().strip()
    sv_tuple = _extract_version_tuple(sv_clean)

    for cv in cve_versions:
        cv_clean = cv.lower().strip()

        # Exact or prefix match
        if sv_clean.startswith(cv_clean) or cv_clean.startswith(sv_clean):
            return True

        # Numeric tuple comparison
        cv_tuple = _extract_version_tuple(cv_clean)
        if sv_tuple and cv_tuple:
            # Match if major.minor match (ignoring patch)
            min_len = min(len(sv_tuple), len(cv_tuple), 2)
            if sv_tuple[:min_len] == cv_tuple[:min_len]:
                return True

    return False


class CVEIndex:
    """In-memory index for fast service+version → CVE lookups."""

    def __init__(self) -> None:
        self._index: dict[str, list[CVERecord]] = {}
        self._total_cves: int = 0

    def load(self, cache_dir: Path) -> None:
        """Load all cached NVD pages and build the lookup index."""
        self._index.clear()
        self._total_cves = 0

        page_files = sorted(cache_dir.glob("nvd_page_*.json"))
        if not page_files:
            logger.warning("No NVD cache files found in %s", cache_dir)
            return

        for page_path in page_files:
            records = parse_cve_page(page_path)
            for record in records:
                self._total_cves += 1
                for product in record.products:
                    normalized = _normalize_product(product)
                    if normalized not in self._index:
                        self._index[normalized] = []
                    self._index[normalized].append(record)

        logger.info(
            "CVE index loaded: %d CVEs, %d product entries",
            self._total_cves, len(self._index),
        )

    def load_records(self, records: list[CVERecord]) -> None:
        """Load CVE records directly (for testing)."""
        self._index.clear()
        self._total_cves = len(records)
        for record in records:
            for product in record.products:
                normalized = _normalize_product(product)
                if normalized not in self._index:
                    self._index[normalized] = []
                self._index[normalized].append(record)

    def match(self, service: str | None, version: str | None) -> list[CVERecord]:
        """Find CVEs matching a service name and version.

        Returns matching CVERecords, deduplicated by cve_id.
        """
        if not service:
            return []

        normalized = _normalize_service(service)
        # Build list of product names to search for
        search_products: list[str] = [normalized]

        # Add aliases
        for alias_key, alias_values in SERVICE_ALIASES.items():
            if alias_key == normalized or normalized.startswith(alias_key):
                search_products.extend(alias_values)
                break

        # Also try the raw normalized name against the index
        # (handles cases where nmap reports the exact CPE product name)

        seen_ids: set[str] = set()
        matches: list[CVERecord] = []

        for product in search_products:
            product_norm = _normalize_product(product)
            candidates = self._index.get(product_norm, [])

            for cve in candidates:
                if cve.cve_id in seen_ids:
                    continue

                # Version check
                if version and cve.versions:
                    if not _version_matches(version, cve.versions):
                        continue

                seen_ids.add(cve.cve_id)
                matches.append(cve)

        return matches

    @property
    def entry_count(self) -> int:
        """Total number of CVEs in the index."""
        return self._total_cves
