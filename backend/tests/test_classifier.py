"""Tests for scanner/classifier.py — rule-based device classification."""

from models.internal import NmapHostResult, PortResult
from scanner.classifier import classify


def _host(ports: list[int] | None = None, hostname: str | None = None, mac: str = "AA:BB:CC:DD:EE:FF") -> NmapHostResult:
    """Create a minimal NmapHostResult for testing."""
    port_results = [PortResult(port=p, protocol="tcp", state="open") for p in (ports or [])]
    return NmapHostResult(ip="192.168.1.1", mac=mac, hostname=hostname, ports=port_results)


def test_classify_router_by_vendor_and_ports() -> None:
    assert classify(_host([80, 443, 53]), "Cisco Systems, Inc.") == "router"


def test_classify_router_ubiquiti() -> None:
    assert classify(_host([80, 443]), "Ubiquiti Inc") == "router"


def test_classify_router_vendor_without_ports_not_router() -> None:
    # Cisco vendor but no web/DNS ports — should NOT be classified as router
    result = classify(_host([22]), "Cisco Systems, Inc.")
    assert result != "router"


def test_classify_server_by_ports_and_hostname() -> None:
    assert classify(_host([22, 80, 443], hostname="nas-01"), None) == "server"


def test_classify_server_hostname_pi() -> None:
    assert classify(_host([22, 80, 443], hostname="raspberrypi"), None) == "server"


def test_classify_mobile_by_vendor() -> None:
    assert classify(_host([]), "Apple, Inc.") == "mobile"


def test_classify_mobile_samsung() -> None:
    assert classify(_host([]), "Samsung Electronics Co.,Ltd") == "mobile"


def test_classify_iot_by_vendor() -> None:
    assert classify(_host([]), "Espressif Inc.") == "iot"


def test_classify_iot_by_mqtt_port() -> None:
    assert classify(_host([1883]), None) == "iot"


def test_classify_iot_by_mqtt_both_ports() -> None:
    assert classify(_host([1883, 8883]), None) == "iot"


def test_classify_printer_by_vendor() -> None:
    assert classify(_host([]), "Hewlett Packard") == "printer"


def test_classify_printer_by_port_9100() -> None:
    assert classify(_host([9100]), None) == "printer"


def test_classify_workstation_by_rdp() -> None:
    assert classify(_host([3389]), None) == "workstation"


def test_classify_workstation_by_smb_ports() -> None:
    assert classify(_host([135, 139, 445]), None) == "workstation"


def test_classify_server_by_ssh_only() -> None:
    assert classify(_host([22]), None) == "server"


def test_classify_server_ssh_not_mobile() -> None:
    # SSH open, not mobile vendor → server
    assert classify(_host([22]), "Dell Inc.") == "server"


def test_classify_unknown_default() -> None:
    assert classify(_host([]), None) == "unknown"


def test_classify_unknown_no_matching_ports() -> None:
    assert classify(_host([8080, 3000]), None) == "unknown"


def test_classify_priority_router_over_server() -> None:
    # Cisco with ports 22, 80, 443 — router rule (1) beats server rule (2)
    assert classify(_host([22, 80, 443], hostname="server"), "Cisco Systems") == "router"


def test_classify_priority_mobile_over_ssh_server() -> None:
    # Apple vendor with SSH port — mobile (rule 3) beats server fallback (rule 7)
    assert classify(_host([22]), "Apple, Inc.") == "mobile"
