"""Tests for routes/cve.py — CVE status and refresh endpoints."""

from unittest.mock import patch, AsyncMock, MagicMock


def test_cve_status_no_index(test_client) -> None:
    """Status when no CVE index is loaded."""
    resp = test_client.get("/api/cve/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["download_complete"] is False
    assert body["data"]["cve_count"] == 0
    assert body["data"]["downloading"] is False


def test_cve_status_with_index(test_client) -> None:
    """Status when CVE index is loaded."""
    mock_index = MagicMock()
    mock_index.entry_count = 150000
    test_client.app.state.cve_index = mock_index
    test_client.app.state.config.set("nvd_download_complete", "1")
    test_client.app.state.config.set("nvd_last_updated", "2025-01-01T00:00:00")

    resp = test_client.get("/api/cve/status")
    body = resp.json()
    assert body["data"]["download_complete"] is True
    assert body["data"]["cve_count"] == 150000
    assert body["data"]["last_updated"] == "2025-01-01T00:00:00"


def test_cve_refresh_returns_202(test_client) -> None:
    """POST /api/cve/refresh triggers download and returns 202."""
    with patch("routes.cve._download_and_index", new_callable=AsyncMock):
        resp = test_client.post("/api/cve/refresh")

    assert resp.status_code == 202
    body = resp.json()
    assert body["success"] is True


def test_cve_refresh_409_when_already_downloading(test_client) -> None:
    """409 if download already in progress."""
    test_client.app.state.cve_downloading = True

    resp = test_client.post("/api/cve/refresh")
    assert resp.status_code == 409
