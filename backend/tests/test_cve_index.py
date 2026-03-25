"""Tests for cve/index.py — in-memory CVE lookup index."""

from models.internal import CVERecord
from cve.index import CVEIndex, _version_matches, _normalize_service


def _cve(cve_id: str, product: str, version: str = "", score: float = 7.0, severity: str = "HIGH") -> CVERecord:
    return CVERecord(
        cve_id=cve_id,
        description=f"Test {cve_id}",
        cvss_score=score,
        severity=severity,
        products=[product],
        versions=[version] if version else [],
    )


def _index_with(*records: CVERecord) -> CVEIndex:
    idx = CVEIndex()
    idx.load_records(list(records))
    return idx


def test_match_exact_product() -> None:
    idx = _index_with(_cve("CVE-001", "openssh", "8.0"))
    matches = idx.match("openssh", "8.0")
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-001"


def test_match_via_alias() -> None:
    idx = _index_with(_cve("CVE-001", "openssh", "8.0"))
    matches = idx.match("ssh", "8.0")
    assert len(matches) == 1


def test_match_no_match_wrong_product() -> None:
    idx = _index_with(_cve("CVE-001", "openssh", "8.0"))
    matches = idx.match("nginx", "1.18")
    assert matches == []


def test_match_no_match_wrong_version() -> None:
    idx = _index_with(_cve("CVE-001", "openssh", "7.0"))
    matches = idx.match("openssh", "8.0")
    assert matches == []


def test_match_case_insensitive() -> None:
    idx = _index_with(_cve("CVE-001", "OpenSSH", "8.0"))
    matches = idx.match("OPENSSH", "8.0")
    assert len(matches) == 1


def test_match_no_version_constraint() -> None:
    """CVE with no version constraint matches all versions."""
    idx = _index_with(_cve("CVE-001", "openssh", ""))
    matches = idx.match("openssh", "8.0")
    assert len(matches) == 1


def test_match_multiple_cves() -> None:
    idx = _index_with(
        _cve("CVE-001", "openssh", "8.0"),
        _cve("CVE-002", "openssh", "8.0"),
    )
    matches = idx.match("openssh", "8.0")
    assert len(matches) == 2


def test_match_deduplicates() -> None:
    """Same CVE affecting multiple products should not duplicate."""
    cve = CVERecord(
        cve_id="CVE-001", description="Test", cvss_score=7.0, severity="HIGH",
        products=["openssh", "openssh"], versions=["8.0"],
    )
    idx = _index_with(cve)
    matches = idx.match("openssh", "8.0")
    assert len(matches) == 1


def test_match_none_service() -> None:
    idx = _index_with(_cve("CVE-001", "openssh", "8.0"))
    assert idx.match(None, "8.0") == []


def test_entry_count() -> None:
    idx = _index_with(
        _cve("CVE-001", "openssh"),
        _cve("CVE-002", "nginx"),
    )
    assert idx.entry_count == 2


def test_entry_count_empty() -> None:
    idx = CVEIndex()
    assert idx.entry_count == 0


# --- Version matching ---


def test_version_matches_exact() -> None:
    assert _version_matches("8.0", ["8.0"]) is True


def test_version_matches_prefix() -> None:
    assert _version_matches("8.0p1", ["8.0"]) is True


def test_version_matches_no_match() -> None:
    assert _version_matches("9.0", ["8.0"]) is False


def test_version_matches_empty_cve_versions() -> None:
    """Empty versions list means all versions affected."""
    assert _version_matches("8.0", []) is True


def test_version_matches_major_minor() -> None:
    assert _version_matches("2.4.41", ["2.4"]) is True


def test_normalize_service() -> None:
    assert _normalize_service("OpenSSH") == "openssh"
    assert _normalize_service("  Nginx  ") == "nginx"
