"""Tests for db/repository.py — SQLite CRUD operations."""

from pathlib import Path

from db import repository


def _conn(db_path: Path):
    return repository.get_connection(db_path)


def test_create_scan_run_returns_id(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    conn.close()
    assert isinstance(scan_id, int)
    assert scan_id > 0


def test_create_scan_run_sets_running_status(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    run = repository.get_scan_run(conn, scan_id)
    conn.close()
    assert run is not None
    assert run["status"] == "running"
    assert run["target_cidr"] == "192.168.1.0/24"


def test_update_scan_run_status(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "10.0.0.0/24", "standard")
    repository.update_scan_run(conn, scan_id, status="completed", host_count=5)
    run = repository.get_scan_run(conn, scan_id)
    conn.close()
    assert run["status"] == "completed"
    assert run["host_count"] == 5


def test_update_scan_run_error(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "10.0.0.0/24", "quick")
    repository.update_scan_run(conn, scan_id, status="failed", error_msg="nmap not found")
    run = repository.get_scan_run(conn, scan_id)
    conn.close()
    assert run["status"] == "failed"
    assert run["error_msg"] == "nmap not found"


def test_get_scan_run_not_found(db_path: Path) -> None:
    conn = _conn(db_path)
    assert repository.get_scan_run(conn, 99999) is None
    conn.close()


def test_list_scan_runs_pagination(db_path: Path) -> None:
    conn = _conn(db_path)
    for i in range(5):
        repository.create_scan_run(conn, f"10.0.{i}.0/24", "quick")

    page1, cursor1 = repository.list_scan_runs(conn, limit=2)
    assert len(page1) == 2
    assert cursor1 is not None

    page2, cursor2 = repository.list_scan_runs(conn, cursor=cursor1, limit=2)
    assert len(page2) == 2
    assert cursor2 is not None

    page3, cursor3 = repository.list_scan_runs(conn, cursor=cursor2, limit=2)
    assert len(page3) == 1
    assert cursor3 is None
    conn.close()


def test_upsert_device_insert(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    device_id = repository.upsert_device(
        conn,
        mac_address="AA:BB:CC:DD:EE:FF",
        ip_address="192.168.1.10",
        hostname="testhost",
        vendor="TestVendor",
        device_type="workstation",
        os_guess="Linux",
        os_accuracy=90,
        scan_id=scan_id,
        risk_score=15,
    )
    conn.close()
    assert isinstance(device_id, int)
    assert device_id > 0


def test_upsert_device_update_preserves_first_seen(db_path: Path) -> None:
    conn = _conn(db_path)
    scan1 = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.10",
        hostname=None, vendor=None, device_type="unknown", os_guess=None,
        os_accuracy=0, scan_id=scan1, risk_score=0,
    )

    scan2 = repository.create_scan_run(conn, "192.168.1.0/24", "standard")
    device_id = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.11",
        hostname="newhost", vendor="NewVendor", device_type="server", os_guess="Linux",
        os_accuracy=85, scan_id=scan2, risk_score=10,
    )

    device = repository.get_device(conn, device_id)
    conn.close()

    assert device["first_seen_scan"] == scan1  # Preserved
    assert device["last_seen_scan"] == scan2  # Updated
    assert device["ip_address"] == "192.168.1.11"  # Updated
    assert device["device_type"] == "server"  # Updated


def test_upsert_device_not_duplicated(db_path: Path) -> None:
    conn = _conn(db_path)
    scan1 = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    scan2 = repository.create_scan_run(conn, "192.168.1.0/24", "quick")

    id1 = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.10",
        hostname=None, vendor=None, device_type="unknown", os_guess=None,
        os_accuracy=0, scan_id=scan1, risk_score=0,
    )
    id2 = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.10",
        hostname=None, vendor=None, device_type="unknown", os_guess=None,
        os_accuracy=0, scan_id=scan2, risk_score=0,
    )

    devices = repository.list_devices(conn)
    conn.close()
    assert id1 == id2
    assert len(devices) == 1


def test_insert_port_and_get(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    device_id = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.1",
        hostname=None, vendor=None, device_type="router", os_guess=None,
        os_accuracy=0, scan_id=scan_id, risk_score=0,
    )

    repository.insert_port(
        conn, device_id=device_id, scan_run_id=scan_id,
        port=80, protocol="tcp", state="open", service="http",
        version="nginx 1.18", risk_flag=None,
    )
    repository.insert_port(
        conn, device_id=device_id, scan_run_id=scan_id,
        port=443, protocol="tcp", state="open", service="https",
        version=None, risk_flag=None,
    )

    ports = repository.get_device_ports(conn, device_id, scan_id)
    conn.close()

    assert len(ports) == 2
    assert ports[0]["port"] == 80
    assert ports[0]["service"] == "http"


def test_insert_appearance(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    device_id = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.1",
        hostname=None, vendor=None, device_type="unknown", os_guess=None,
        os_accuracy=0, scan_id=scan_id, risk_score=0,
    )

    repository.insert_appearance(conn, scan_id, device_id, "192.168.1.1")

    row = conn.execute(
        "SELECT * FROM scan_device_appearances WHERE scan_run_id = ? AND device_id = ?",
        (scan_id, device_id),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row["ip_address"] == "192.168.1.1"


def test_list_devices_returns_all(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")

    for i in range(3):
        repository.upsert_device(
            conn, mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            ip_address=f"192.168.1.{10 + i}", hostname=None, vendor=None,
            device_type="unknown", os_guess=None, os_accuracy=0,
            scan_id=scan_id, risk_score=i * 10,
        )

    devices = repository.list_devices(conn)
    conn.close()
    assert len(devices) == 3
    # Ordered by risk_score DESC
    assert devices[0]["risk_score"] >= devices[1]["risk_score"]


def test_get_device_cve_matches_empty(db_path: Path) -> None:
    conn = _conn(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    device_id = repository.upsert_device(
        conn, mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.1",
        hostname=None, vendor=None, device_type="unknown", os_guess=None,
        os_accuracy=0, scan_id=scan_id, risk_score=0,
    )
    matches = repository.get_device_cve_matches(conn, device_id)
    conn.close()
    assert matches == []
