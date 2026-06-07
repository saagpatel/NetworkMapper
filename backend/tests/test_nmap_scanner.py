"""Tests for scanner/nmap_scanner.py — nmap wrapper with mocked PortScanner."""

from unittest.mock import MagicMock, patch

from scanner.nmap_scanner import scan_hosts, _build_version_string
from scanner.profile import get_profile


def _mock_host(state="up", tcp_ports=None, osmatch=None, mac=None, hostnames=None):
    """Build a mock nmap host data dict."""
    host = MagicMock()
    host.state.return_value = state

    data = {"addresses": {}}
    if mac:
        data["addresses"]["mac"] = mac
    if hostnames:
        data["hostnames"] = hostnames
    else:
        data["hostnames"] = []
    if tcp_ports:
        data["tcp"] = tcp_ports
    if osmatch:
        data["osmatch"] = osmatch

    host.__getitem__ = lambda _, key: data.get(key, {})
    host.__contains__ = lambda _, key: key in data
    host.get = lambda key, default=None: data.get(key, default)
    return host


def _mock_scanner(hosts_data: dict):
    """Create a mock nmap.PortScanner with given hosts."""
    scanner = MagicMock()
    scanner.all_hosts.return_value = list(hosts_data.keys())

    def getitem(_, ip):
        return hosts_data[ip]

    scanner.__getitem__ = getitem
    return scanner


def test_scan_hosts_returns_open_ports() -> None:
    host = _mock_host(
        tcp_ports={
            80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18", "extrainfo": ""},
            443: {"state": "open", "name": "https", "product": "", "version": "", "extrainfo": ""},
            22: {"state": "closed", "name": "ssh", "product": "", "version": "", "extrainfo": ""},
        },
        mac="AA:BB:CC:DD:EE:FF",
    )

    with patch("scanner.nmap_scanner.nmap.PortScanner") as MockScanner:
        mock_instance = _mock_scanner({"192.168.1.1": host})
        MockScanner.return_value = mock_instance

        results = scan_hosts(["192.168.1.1"], get_profile("quick"))

    assert len(results) == 1
    # Only open and filtered ports are returned
    open_ports = [p for p in results[0].ports if p.state == "open"]
    assert len(open_ports) == 2
    assert results[0].mac == "AA:BB:CC:DD:EE:FF"


def test_scan_hosts_skips_down_hosts() -> None:
    host = _mock_host(state="down")

    with patch("scanner.nmap_scanner.nmap.PortScanner") as MockScanner:
        mock_instance = _mock_scanner({"192.168.1.1": host})
        MockScanner.return_value = mock_instance

        results = scan_hosts(["192.168.1.1"], get_profile("quick"))

    assert len(results) == 0


def test_scan_hosts_parses_os_guess() -> None:
    host = _mock_host(
        osmatch=[{"name": "Linux 5.4", "accuracy": "95"}],
    )

    with patch("scanner.nmap_scanner.nmap.PortScanner") as MockScanner:
        mock_instance = _mock_scanner({"192.168.1.1": host})
        MockScanner.return_value = mock_instance

        results = scan_hosts(["192.168.1.1"], get_profile("deep"))

    assert len(results) == 1
    assert results[0].os_guess == "Linux 5.4"
    assert results[0].os_accuracy == 95


def test_scan_hosts_handles_nmap_error() -> None:
    import nmap

    with patch("scanner.nmap_scanner.nmap.PortScanner") as MockScanner:
        mock_instance = MagicMock()
        mock_instance.scan.side_effect = nmap.PortScannerError("nmap not found")
        MockScanner.return_value = mock_instance

        results = scan_hosts(["192.168.1.1"], get_profile("quick"))

    assert results == []


def test_scan_hosts_empty_ip_list() -> None:
    results = scan_hosts([], get_profile("quick"))
    assert results == []


def test_scan_hosts_parses_hostname() -> None:
    host = _mock_host(hostnames=[{"name": "myserver.local", "type": "PTR"}])

    with patch("scanner.nmap_scanner.nmap.PortScanner") as MockScanner:
        mock_instance = _mock_scanner({"192.168.1.1": host})
        MockScanner.return_value = mock_instance

        results = scan_hosts(["192.168.1.1"], get_profile("quick"))

    assert results[0].hostname == "myserver.local"


def test_build_version_string() -> None:
    assert _build_version_string({"product": "OpenSSH", "version": "8.0", "extrainfo": "Ubuntu"}) == "OpenSSH 8.0 Ubuntu"
    assert _build_version_string({"product": "", "version": "", "extrainfo": ""}) is None
    assert _build_version_string({"product": "nginx", "version": "1.18", "extrainfo": ""}) == "nginx 1.18"
