"""Tests for scanner/orchestrator.py — scan pipeline coordination."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from db import repository
from models.internal import NmapHostResult, PortResult
from models.schemas import ScanProgressEvent
from scanner.orchestrator import run_scan


@pytest.fixture()
def mock_oui() -> MagicMock:
    resolver = MagicMock()
    resolver.lookup.return_value = "TestVendor"
    return resolver


def _make_arp_results() -> list[dict[str, str]]:
    return [
        {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"},
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:02"},
    ]


def _make_nmap_results() -> list[NmapHostResult]:
    return [
        NmapHostResult(
            ip="192.168.1.1",
            mac="AA:BB:CC:DD:EE:01",
            hostname="router.local",
            ports=[PortResult(port=80, protocol="tcp", state="open", service="http")],
        ),
        NmapHostResult(
            ip="192.168.1.2",
            mac="AA:BB:CC:DD:EE:02",
            hostname=None,
            ports=[PortResult(port=22, protocol="tcp", state="open", service="ssh")],
        ),
    ]


@pytest.mark.asyncio
async def test_run_scan_full_pipeline(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with (
        patch("scanner.orchestrator.arp_scanner.sweep", return_value=_make_arp_results()),
        patch("scanner.orchestrator.scan_hosts", return_value=_make_nmap_results()),
    ):
        scan_id = await run_scan("192.168.1.0/24", "quick", str(db_path), mock_oui, queue)

    assert scan_id > 0

    # Verify scan completed
    conn = repository.get_connection(db_path)
    run = repository.get_scan_run(conn, scan_id)
    assert run["status"] == "completed"
    assert run["host_count"] == 2

    # Verify devices persisted
    devices = repository.list_devices(conn)
    assert len(devices) == 2

    conn.close()


@pytest.mark.asyncio
async def test_run_scan_emits_events(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with (
        patch("scanner.orchestrator.arp_scanner.sweep", return_value=_make_arp_results()),
        patch("scanner.orchestrator.scan_hosts", return_value=_make_nmap_results()),
    ):
        await run_scan("192.168.1.0/24", "quick", str(db_path), mock_oui, queue)

    events: list[ScanProgressEvent] = []
    while not queue.empty():
        events.append(queue.get_nowait())

    event_types = [e.type for e in events]
    assert "arp_complete" in event_types
    assert "host_scanned" in event_types
    assert "classification_done" in event_types
    assert "complete" in event_types


@pytest.mark.asyncio
async def test_run_scan_arp_complete_has_count(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with (
        patch("scanner.orchestrator.arp_scanner.sweep", return_value=_make_arp_results()),
        patch("scanner.orchestrator.scan_hosts", return_value=_make_nmap_results()),
    ):
        await run_scan("192.168.1.0/24", "quick", str(db_path), mock_oui, queue)

    arp_event = queue.get_nowait()
    assert arp_event.type == "arp_complete"
    assert arp_event.hosts_found == 2


@pytest.mark.asyncio
async def test_run_scan_no_hosts(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with patch("scanner.orchestrator.arp_scanner.sweep", return_value=[]):
        scan_id = await run_scan("10.0.0.0/24", "quick", str(db_path), mock_oui, queue)

    conn = repository.get_connection(db_path)
    run = repository.get_scan_run(conn, scan_id)
    conn.close()

    assert run["status"] == "completed"
    assert run["host_count"] == 0


@pytest.mark.asyncio
async def test_run_scan_error_sets_failed(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with patch("scanner.orchestrator.arp_scanner.sweep", side_effect=RuntimeError("Network error")):
        with pytest.raises(RuntimeError):
            await run_scan("192.168.1.0/24", "quick", str(db_path), mock_oui, queue)

    conn = repository.get_connection(db_path)
    # Find the scan run that was created
    runs, _ = repository.list_scan_runs(conn)
    conn.close()

    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert "Network error" in runs[0]["error_msg"]


@pytest.mark.asyncio
async def test_run_scan_error_emits_error_event(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with patch("scanner.orchestrator.arp_scanner.sweep", side_effect=RuntimeError("fail")):
        with pytest.raises(RuntimeError):
            await run_scan("192.168.1.0/24", "quick", str(db_path), mock_oui, queue)

    events: list[ScanProgressEvent] = []
    while not queue.empty():
        events.append(queue.get_nowait())

    assert any(e.type == "error" for e in events)


@pytest.mark.asyncio
async def test_run_scan_persists_ports(db_path: Path, mock_oui: MagicMock) -> None:
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()

    with (
        patch("scanner.orchestrator.arp_scanner.sweep", return_value=_make_arp_results()),
        patch("scanner.orchestrator.scan_hosts", return_value=_make_nmap_results()),
    ):
        scan_id = await run_scan("192.168.1.0/24", "quick", str(db_path), mock_oui, queue)

    conn = repository.get_connection(db_path)
    devices = repository.list_devices(conn)

    total_ports = 0
    for device in devices:
        ports = repository.get_device_ports(conn, device["id"], scan_id)
        total_ports += len(ports)

    conn.close()
    assert total_ports == 2  # One port per host in our mock data
