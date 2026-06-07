"""Tests for routes/schedule.py — schedule API security and behaviour."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_get_schedule_returns_config(test_client) -> None:
    resp = test_client.get("/api/schedule")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "cron_expression" in body["data"]


def test_put_schedule_rejects_non_whitelisted_cidr(test_client) -> None:
    """Storing a scheduled CIDR that isn't in the whitelist must be rejected."""
    resp = test_client.put(
        "/api/schedule",
        json={"target_cidr": "10.0.0.0/8", "profile": "quick"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["code"] == "CIDR_NOT_WHITELISTED"


def test_put_schedule_rejects_when_whitelist_empty(test_client) -> None:
    """PUT /api/schedule must be rejected when the whitelist is empty."""
    config = test_client.app.state.config
    config.set("whitelist_cidrs", json.dumps([]))

    resp = test_client.put(
        "/api/schedule",
        json={"target_cidr": "192.168.1.0/24", "profile": "quick"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["code"] == "NO_WHITELIST_CONFIGURED"


def test_put_schedule_accepts_whitelisted_cidr(test_client) -> None:
    """Whitelisted CIDR should be accepted and stored."""
    resp = test_client.put(
        "/api/schedule",
        json={"target_cidr": "192.168.1.0/24", "profile": "quick"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["data"]["target_cidr"] == "192.168.1.0/24"


@pytest.mark.asyncio
async def test_run_scheduled_scan_aborts_when_whitelist_empty() -> None:
    """_run_scheduled_scan must abort without calling run_scan when whitelist is empty."""
    from routes.schedule import _run_scheduled_scan

    mock_config = MagicMock()
    mock_config.whitelist_cidrs = []

    app = MagicMock()
    app.state.config = mock_config

    with patch("scanner.orchestrator.run_scan", new_callable=AsyncMock) as mock_run:
        await _run_scheduled_scan(app, "192.168.1.0/24", "quick")
        mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_run_scheduled_scan_aborts_when_cidr_not_in_whitelist() -> None:
    """_run_scheduled_scan must abort without calling run_scan when CIDR removed from whitelist."""
    from routes.schedule import _run_scheduled_scan

    mock_config = MagicMock()
    mock_config.whitelist_cidrs = ["10.0.0.0/8"]

    app = MagicMock()
    app.state.config = mock_config

    with patch("scanner.orchestrator.run_scan", new_callable=AsyncMock) as mock_run:
        await _run_scheduled_scan(app, "192.168.1.0/24", "quick")
        mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_run_scheduled_scan_proceeds_when_cidr_whitelisted() -> None:
    """_run_scheduled_scan must call run_scan when the CIDR is in the whitelist."""
    from routes.schedule import _run_scheduled_scan

    mock_config = MagicMock()
    mock_config.whitelist_cidrs = ["192.168.1.0/24"]

    app = MagicMock()
    app.state.config = mock_config
    app.state.db_path = ":memory:"
    app.state.oui_resolver = MagicMock()
    app.state.cve_index = None

    with patch("scanner.orchestrator.run_scan", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = 1
        await _run_scheduled_scan(app, "192.168.1.0/24", "quick")
        mock_run.assert_called_once()
