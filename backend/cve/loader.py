"""NIST NVD API 2.0 feed downloader and parser."""

import json
import logging
import time
from collections.abc import Callable
from pathlib import Path

import requests

from models.internal import CVERecord

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 6.0  # seconds between requests (5 req/30s rate limit)
MAX_RETRIES = 3
RETRY_BACKOFF = 10.0  # seconds, multiplied by attempt number
REQUEST_TIMEOUT = 60


def download_nvd_feed(
    cache_dir: Path,
    progress_callback: Callable[[int, int], None] | None = None,
    api_key: str | None = None,
    force: bool = False,
) -> int:
    """Download CVE data from NVD API 2.0 into cache_dir.

    Returns total number of CVEs downloaded.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    delay = 1.0 if api_key else REQUEST_DELAY

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    # First request to get total count
    total_results = _get_total_count(headers)
    if total_results == 0:
        logger.warning("NVD API returned 0 total results")
        return 0

    logger.info("NVD feed: %d total CVEs to download", total_results)
    downloaded = 0
    start_index = 0

    while start_index < total_results:
        page_path = cache_dir / f"nvd_page_{start_index}.json"

        # Resume support: skip if page exists and is recent (< 24h)
        if not force and _page_is_fresh(page_path):
            page_count = _count_cves_in_page(page_path)
            downloaded += page_count
            start_index += RESULTS_PER_PAGE
            if progress_callback:
                progress_callback(downloaded, total_results)
            continue

        # Download page with retry
        data = _fetch_page(start_index, headers)
        if data is None:
            logger.error("Failed to download page at startIndex=%d after retries", start_index)
            start_index += RESULTS_PER_PAGE
            continue

        # Save raw JSON
        page_path.write_text(json.dumps(data), encoding="utf-8")

        page_count = len(data.get("vulnerabilities", []))
        downloaded += page_count
        start_index += RESULTS_PER_PAGE

        if progress_callback:
            progress_callback(downloaded, total_results)

        logger.info("NVD download: %d/%d CVEs", downloaded, total_results)

        # Rate limit
        if start_index < total_results:
            time.sleep(delay)

    logger.info("NVD feed download complete: %d CVEs", downloaded)
    return downloaded


def _get_total_count(headers: dict[str, str]) -> int:
    """Fetch the first page to determine totalResults."""
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"startIndex": 0, "resultsPerPage": 1},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("totalResults", 0)
    except requests.RequestException:
        logger.exception("Failed to query NVD API for total count")
        return 0


def _fetch_page(start_index: int, headers: dict[str, str]) -> dict | None:
    """Fetch a single page from the NVD API with retry logic."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(
                NVD_API_URL,
                params={"startIndex": start_index, "resultsPerPage": RESULTS_PER_PAGE},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            logger.warning(
                "NVD API request failed (attempt %d/%d, startIndex=%d)",
                attempt, MAX_RETRIES, start_index,
            )
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)
    return None


def _page_is_fresh(page_path: Path, max_age_hours: int = 24) -> bool:
    """Check if a cached page file exists and is less than max_age_hours old."""
    if not page_path.exists():
        return False
    age_seconds = time.time() - page_path.stat().st_mtime
    return age_seconds < max_age_hours * 3600


def _count_cves_in_page(page_path: Path) -> int:
    """Count CVEs in a cached page file without full parsing."""
    try:
        data = json.loads(page_path.read_text(encoding="utf-8"))
        return len(data.get("vulnerabilities", []))
    except (json.JSONDecodeError, OSError):
        return 0


def parse_cve_page(page_path: Path) -> list[CVERecord]:
    """Parse a cached NVD API page into CVERecord objects."""
    try:
        data = json.loads(page_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.exception("Failed to read CVE page: %s", page_path)
        return []

    records: list[CVERecord] = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        record = _parse_vulnerability(cve_data)
        if record:
            records.append(record)

    return records


def _parse_vulnerability(cve_data: dict) -> CVERecord | None:
    """Parse a single CVE entry from NVD API 2.0 format."""
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return None

    # Description — prefer English, truncate to 200 chars
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")[:200]
            break

    # CVSS score and severity — try v31, then v30, then v2
    cvss_score, severity = _extract_cvss(cve_data.get("metrics", {}))

    # Products and versions from CPE configurations
    products, versions = _extract_cpe_info(cve_data.get("configurations", []))

    return CVERecord(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        severity=severity,
        products=products,
        versions=versions,
    )


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Extract the best available CVSS score and severity."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if not metric_list:
            continue
        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "").upper()

        if score is not None:
            # Normalize severity
            if not severity or severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return float(score), severity

    return None, None


def _extract_cpe_info(configurations: list[dict]) -> tuple[list[str], list[str]]:
    """Extract normalized product names and version strings from CPE configurations."""
    products: set[str] = set()
    versions: set[str] = set()

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 6:
                    product = parts[4].lower().replace("_", " ").strip()
                    version = parts[5] if parts[5] != "*" else ""
                    if product:
                        products.add(product)
                    if version:
                        versions.add(version)

                # Also capture version ranges
                ver_start = cpe_match.get("versionStartIncluding", "")
                ver_end = cpe_match.get("versionEndExcluding", "") or cpe_match.get("versionEndIncluding", "")
                if ver_start:
                    versions.add(ver_start)
                if ver_end:
                    versions.add(ver_end)

    return sorted(products), sorted(versions)
