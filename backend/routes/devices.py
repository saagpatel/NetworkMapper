"""Device routes — GET /api/devices, GET /api/devices/{id}."""

import logging

from fastapi import APIRouter, HTTPException, Request

from db import repository
from models.schemas import (
    DeviceDetailResponse,
    DeviceResponse,
    SuccessResponse,
)
from scanner.risk_engine import score_device
from models.internal import PortResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=SuccessResponse[list[DeviceResponse]])
async def list_devices(request: Request) -> SuccessResponse[list[DeviceResponse]]:
    """List all known devices."""
    conn = repository.get_connection(request.app.state.db_path)
    try:
        devices = repository.list_devices(conn)
    finally:
        conn.close()

    return SuccessResponse(data=[DeviceResponse(**d) for d in devices])


@router.get("/{device_id}", response_model=SuccessResponse[DeviceDetailResponse])
async def get_device(device_id: int, request: Request) -> SuccessResponse[DeviceDetailResponse]:
    """Get full device detail including ports and CVE matches."""
    conn = repository.get_connection(request.app.state.db_path)
    try:
        device = repository.get_device(conn, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")

        ports = repository.get_device_ports(conn, device_id)
        cve_matches = repository.get_device_cve_matches(conn, device_id)
    finally:
        conn.close()

    # Regenerate risk summary from current port data
    port_results = [
        PortResult(
            port=p["port"],
            protocol=p["protocol"],
            state=p["state"],
            service=p.get("service"),
            version=p.get("version"),
        )
        for p in ports
    ]
    _, _, risk_summary, _ = score_device(device["device_type"] or "unknown", port_results)

    return SuccessResponse(
        data=DeviceDetailResponse(
            **device,
            ports=ports,
            cve_matches=cve_matches,
            risk_summary=risk_summary,
        )
    )
