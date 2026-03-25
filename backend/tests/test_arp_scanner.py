"""Tests for scanner/arp_scanner.py — ARP sweep and MAC normalization."""

from unittest.mock import patch, MagicMock

from scanner.arp_scanner import normalize_mac, sweep


def test_normalize_mac_colon_format() -> None:
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_dash_format() -> None:
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_dot_format() -> None:
    assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_no_delimiter() -> None:
    assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_already_normalized() -> None:
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"


def _make_mock_response(ip: str, mac: str) -> MagicMock:
    """Create a mock scapy response packet."""
    response = MagicMock()
    response.psrc = ip
    response.hwsrc = mac
    return response


def test_sweep_returns_hosts() -> None:
    mock_answered = [
        (MagicMock(), _make_mock_response("192.168.1.1", "aa:bb:cc:dd:ee:ff")),
        (MagicMock(), _make_mock_response("192.168.1.2", "11:22:33:44:55:66")),
    ]

    with patch("scanner.arp_scanner.srp", return_value=(mock_answered, [])):
        hosts = sweep("192.168.1.0/24")

    assert len(hosts) == 2
    assert hosts[0] == {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"}
    assert hosts[1] == {"ip": "192.168.1.2", "mac": "11:22:33:44:55:66"}


def test_sweep_empty_network() -> None:
    with patch("scanner.arp_scanner.srp", return_value=([], [])):
        hosts = sweep("10.0.0.0/24")

    assert hosts == []


def test_sweep_permission_error() -> None:
    with patch("scanner.arp_scanner.srp", side_effect=PermissionError("Not root")):
        try:
            sweep("192.168.1.0/24")
            assert False, "Should have raised PermissionError"
        except PermissionError:
            pass
