"""Tests for scanner/risk_engine.py — risk scoring."""

from unittest.mock import MagicMock

from models.internal import CVERecord, PortResult
from scanner.risk_engine import score_device


def _port(port: int, state: str = "open", service: str | None = None, version: str | None = None) -> PortResult:
    return PortResult(port=port, protocol="tcp", state=state, service=service, version=version)


# --- Port-based scoring (Phase 1 tests, updated for 4-tuple return) ---


def test_score_no_open_ports() -> None:
    score, flags, summary, cves = score_device("workstation", [])
    assert score == 0
    assert flags == {}
    assert cves == []
    assert "No significant risks" in summary


def test_score_critical_port_telnet() -> None:
    score, flags, summary, _ = score_device("server", [_port(23, service="telnet")])
    assert score >= 15
    assert flags[23] == "critical"
    assert "Telnet" in summary


def test_score_critical_port_ftp() -> None:
    score, flags, _, _ = score_device("server", [_port(21, service="ftp")])
    assert score >= 15
    assert flags[21] == "critical"


def test_score_multiple_critical_ports() -> None:
    score, flags, _, _ = score_device("server", [_port(21), _port(23)])
    assert score >= 30
    assert 21 in flags
    assert 23 in flags


def test_score_unexpected_port_for_printer() -> None:
    score, flags, summary, _ = score_device("printer", [_port(22, service="ssh")])
    assert score >= 10
    assert flags[22] == "unexpected"
    assert "unexpected" in summary.lower()


def test_score_unexpected_port_for_iot() -> None:
    score, flags, _, _ = score_device("iot", [_port(3389, service="rdp")])
    assert score >= 10
    assert flags[3389] == "unexpected"


def test_score_cap_at_100() -> None:
    ports = [_port(p) for p in [21, 23, 512, 513, 514, 5900, 3389, 445]]
    score, _, _, _ = score_device("iot", ports)
    assert score == 100


def test_score_closed_ports_ignored() -> None:
    score, flags, _, _ = score_device("server", [_port(23, state="closed")])
    assert score == 0
    assert flags == {}


def test_score_summary_severity_levels() -> None:
    _, _, low_summary, _ = score_device("server", [_port(21)])
    assert "Low risk" in low_summary

    _, _, med_summary, _ = score_device("server", [_port(21), _port(23)])
    assert "Medium risk" in med_summary

    _, _, high_summary, _ = score_device("server", [_port(21), _port(23), _port(512), _port(513)])
    assert "High risk" in high_summary


def test_score_no_unexpected_for_unknown_device() -> None:
    score, flags, _, _ = score_device("unknown", [_port(22), _port(80)])
    assert score == 0
    assert flags == {}


# --- CVE-based scoring (Phase 2 tests) ---


def _mock_cve_index(matches: list[CVERecord]) -> MagicMock:
    idx = MagicMock()
    idx.match.return_value = matches
    return idx


def test_score_with_cve_critical() -> None:
    cve = CVERecord(cve_id="CVE-2024-001", description="Test", cvss_score=9.5, severity="CRITICAL", products=["openssh"], versions=["8.0"])
    idx = _mock_cve_index([cve])
    port = _port(22, service="ssh", version="OpenSSH 8.0")
    score, flags, summary, cve_matches = score_device("server", [port], cve_index=idx)
    assert score >= 20
    assert len(cve_matches) == 1
    assert cve_matches[0] == (22, cve)
    assert flags[22] == "outdated"
    assert "CVE" in summary


def test_score_with_cve_high() -> None:
    cve = CVERecord(cve_id="CVE-2024-002", description="Test", cvss_score=7.5, severity="HIGH", products=["nginx"], versions=["1.18"])
    idx = _mock_cve_index([cve])
    score, _, _, _ = score_device("server", [_port(80, service="http", version="nginx 1.18")], cve_index=idx)
    assert score >= 10


def test_score_with_cve_medium() -> None:
    cve = CVERecord(cve_id="CVE-2024-003", description="Test", cvss_score=5.0, severity="MEDIUM", products=["apache"], versions=["2.4"])
    idx = _mock_cve_index([cve])
    score, _, _, _ = score_device("server", [_port(80, service="http", version="Apache 2.4")], cve_index=idx)
    assert score >= 5


def test_score_cve_no_match_without_version() -> None:
    """CVE matching requires both service and version."""
    idx = _mock_cve_index([])
    score, _, _, cve_matches = score_device("server", [_port(22, service="ssh")], cve_index=idx)
    assert cve_matches == []
    idx.match.assert_not_called()


def test_score_cve_none_index_backward_compatible() -> None:
    """When cve_index is None, no CVE scoring occurs (backward compatible)."""
    score, flags, summary, cve_matches = score_device("server", [_port(22, service="ssh", version="8.0")])
    assert cve_matches == []


def test_score_cve_combined_with_critical_port() -> None:
    """CVE score adds on top of critical port score."""
    cve = CVERecord(cve_id="CVE-2024-004", description="Test", cvss_score=9.0, severity="CRITICAL", products=["vsftpd"], versions=["3.0"])
    idx = _mock_cve_index([cve])
    port = _port(21, service="ftp", version="vsftpd 3.0.3")
    score, flags, _, _ = score_device("server", [port], cve_index=idx)
    # Critical port (15) + CVE critical (20) = 35
    assert score >= 35
    assert flags[21] == "critical"  # critical port flag takes precedence
