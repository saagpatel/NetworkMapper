"""Tests for API endpoints — health check and CVE status."""


def test_health_endpoint(test_client) -> None:
    resp = test_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data


def test_cve_status_endpoint(test_client) -> None:
    resp = test_client.get("/api/cve/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["data"]["download_complete"] is False
    assert body["data"]["cve_count"] == 0
    assert body["data"]["downloading"] is False
    assert body["data"]["last_updated"] is None
    assert "request_id" in body["meta"]
    assert "timestamp" in body["meta"]
