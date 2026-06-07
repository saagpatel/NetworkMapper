"""Tests for cve/loader.py — NVD API downloader and parser."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve.loader import (
    download_nvd_feed,
    parse_cve_page,
    _extract_cvss,
    _extract_cpe_info,
    _parse_vulnerability,
)


def _make_nvd_response(total: int, start: int, vulns: list[dict]) -> dict:
    return {
        "totalResults": total,
        "startIndex": start,
        "resultsPerPage": len(vulns),
        "vulnerabilities": vulns,
    }


def _make_vuln(cve_id: str, score: float = 7.0, product: str = "openssh", version: str = "8.0") -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test vulnerability {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": score, "baseSeverity": "HIGH"},
                }]
            },
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": f"cpe:2.3:a:vendor:{product}:{version}:*:*:*:*:*:*:*",
                    }]
                }]
            }],
        }
    }


def test_download_single_page(tmp_path: Path) -> None:
    total_resp = MagicMock()
    total_resp.json.return_value = {"totalResults": 2}
    total_resp.raise_for_status = MagicMock()

    page_resp = MagicMock()
    page_resp.json.return_value = _make_nvd_response(2, 0, [
        _make_vuln("CVE-2024-001"),
        _make_vuln("CVE-2024-002"),
    ])
    page_resp.raise_for_status = MagicMock()

    with patch("cve.loader.requests.get", side_effect=[total_resp, page_resp]):
        with patch("cve.loader.time.sleep"):
            count = download_nvd_feed(tmp_path)

    assert count == 2
    assert (tmp_path / "nvd_page_0.json").exists()


def test_download_progress_callback(tmp_path: Path) -> None:
    total_resp = MagicMock()
    total_resp.json.return_value = {"totalResults": 1}
    total_resp.raise_for_status = MagicMock()

    page_resp = MagicMock()
    page_resp.json.return_value = _make_nvd_response(1, 0, [_make_vuln("CVE-2024-001")])
    page_resp.raise_for_status = MagicMock()

    progress_calls: list[tuple[int, int]] = []

    with patch("cve.loader.requests.get", side_effect=[total_resp, page_resp]):
        with patch("cve.loader.time.sleep"):
            download_nvd_feed(tmp_path, progress_callback=lambda d, t: progress_calls.append((d, t)))

    assert len(progress_calls) >= 1
    assert progress_calls[-1][0] == 1  # downloaded
    assert progress_calls[-1][1] == 1  # total


def test_download_resume_skips_fresh_pages(tmp_path: Path) -> None:
    # Pre-create a fresh page file
    page_data = _make_nvd_response(1, 0, [_make_vuln("CVE-2024-001")])
    (tmp_path / "nvd_page_0.json").write_text(json.dumps(page_data))

    total_resp = MagicMock()
    total_resp.json.return_value = {"totalResults": 1}
    total_resp.raise_for_status = MagicMock()

    with patch("cve.loader.requests.get", side_effect=[total_resp]) as mock_get:
        with patch("cve.loader.time.sleep"):
            count = download_nvd_feed(tmp_path)

    # Should only call for total count, not download the page again
    assert mock_get.call_count == 1
    assert count == 1


def test_parse_cve_page(tmp_path: Path) -> None:
    page_data = _make_nvd_response(2, 0, [
        _make_vuln("CVE-2024-001", score=9.0, product="openssh", version="8.0"),
        _make_vuln("CVE-2024-002", score=5.0, product="nginx", version="1.18"),
    ])
    page_path = tmp_path / "test_page.json"
    page_path.write_text(json.dumps(page_data))

    records = parse_cve_page(page_path)
    assert len(records) == 2
    assert records[0].cve_id == "CVE-2024-001"
    assert records[0].cvss_score == 9.0
    assert "openssh" in records[0].products
    assert records[1].cve_id == "CVE-2024-002"


def test_extract_cvss_v31() -> None:
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 8.5, "baseSeverity": "HIGH"}}]}
    score, severity = _extract_cvss(metrics)
    assert score == 8.5
    assert severity == "HIGH"


def test_extract_cvss_fallback_v2() -> None:
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 6.0, "baseSeverity": ""}}]}
    score, severity = _extract_cvss(metrics)
    assert score == 6.0
    assert severity == "MEDIUM"  # auto-derived from score


def test_extract_cvss_none() -> None:
    score, severity = _extract_cvss({})
    assert score is None
    assert severity is None


def test_extract_cpe_info() -> None:
    configs = [{
        "nodes": [{
            "cpeMatch": [{
                "criteria": "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*",
            }]
        }]
    }]
    products, versions = _extract_cpe_info(configs)
    assert "openssh" in products
    assert "8.0" in versions


def test_parse_vulnerability_missing_id() -> None:
    assert _parse_vulnerability({}) is None
