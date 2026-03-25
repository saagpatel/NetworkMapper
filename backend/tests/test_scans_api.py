"""Tests for routes/scans.py — scan API endpoints."""

from unittest.mock import patch, AsyncMock

from db import repository


def test_post_scan_creates_run(test_client) -> None:
    with patch("routes.scans.run_scan", new_callable=AsyncMock):
        resp = test_client.post(
            "/api/scans",
            json={"target_cidr": "192.168.1.0/24", "profile": "quick"},
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["success"] is True
    assert body["data"]["status"] == "running"
    assert body["data"]["target_cidr"] == "192.168.1.0/24"
    assert body["data"]["id"] > 0


def test_post_scan_cidr_not_in_whitelist(test_client) -> None:
    resp = test_client.post(
        "/api/scans",
        json={"target_cidr": "10.0.0.0/8", "profile": "quick"},
    )
    assert resp.status_code == 403


def test_post_scan_invalid_profile(test_client) -> None:
    resp = test_client.post(
        "/api/scans",
        json={"target_cidr": "192.168.1.0/24", "profile": "ultra"},
    )
    assert resp.status_code == 422


def test_get_scans_list(test_client) -> None:
    # Seed a scan run directly via repository
    db_path = test_client.app.state.db_path
    conn = repository.get_connection(db_path)
    repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    conn.close()

    resp = test_client.get("/api/scans")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert isinstance(body["data"], list)
    assert len(body["data"]) >= 1


def test_get_scan_by_id(test_client) -> None:
    db_path = test_client.app.state.db_path
    conn = repository.get_connection(db_path)
    scan_id = repository.create_scan_run(conn, "192.168.1.0/24", "quick")
    conn.close()

    resp = test_client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["id"] == scan_id


def test_get_scan_not_found(test_client) -> None:
    resp = test_client.get("/api/scans/99999")
    assert resp.status_code == 404
