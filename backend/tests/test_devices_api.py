"""Tests for routes/devices.py — device API endpoints."""

from db import repository


def test_get_devices_empty(test_client) -> None:
    resp = test_client.get("/api/devices")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["data"] == []


def test_get_devices_returns_all(test_client) -> None:
    # Seed devices via repository
    db_path = test_client.app.state.db_path
    conn = repository.get_connection(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:01", ip_address="192.168.1.1",
        hostname="host1", vendor=None, device_type="router", os_guess=None,
        os_accuracy=0, scan_id=scan_id, risk_score=10,
    )
    repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:02", ip_address="192.168.1.2",
        hostname="host2", vendor=None, device_type="server", os_guess=None,
        os_accuracy=0, scan_id=scan_id, risk_score=20,
    )
    conn.close()

    resp = test_client.get("/api/devices")
    body = resp.json()
    assert len(body["data"]) == 2


def test_get_device_by_id(test_client) -> None:
    db_path = test_client.app.state.db_path
    conn = repository.get_connection(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    device_id = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.1",
        hostname="myhost", vendor="TestVendor", device_type="server",
        os_guess="Linux", os_accuracy=90, scan_id=scan_id, risk_score=15,
    )
    repository.insert_port(
        conn, device_id=device_id, scan_run_id=scan_id,
        port=22, protocol="tcp", state="open", service="ssh",
        version="OpenSSH 8.0", risk_flag=None,
    )
    conn.close()

    resp = test_client.get(f"/api/devices/{device_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["id"] == device_id
    assert body["data"]["device_type"] == "server"
    assert len(body["data"]["ports"]) == 1
    assert body["data"]["ports"][0]["port"] == 22
    assert body["data"]["cve_matches"] == []
    assert isinstance(body["data"]["risk_summary"], str)


def test_get_device_not_found(test_client) -> None:
    resp = test_client.get("/api/devices/99999")
    assert resp.status_code == 404
