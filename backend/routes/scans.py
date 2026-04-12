"""Scan routes — POST /api/scans, GET /api/scans/{id}, SSE progress stream."""

import asyncio
import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from db import repository
from models.schemas import (
    ErrorDetail,
    ErrorResponse,
    ScanProgressEvent,
    ScanRequest,
    ScanRunResponse,
    SuccessResponse,
)
from scanner.orchestrator import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=SuccessResponse[ScanRunResponse], status_code=201)
async def start_scan(body: ScanRequest, request: Request) -> SuccessResponse[ScanRunResponse]:
    """Start a new scan. Validates target against whitelist before proceeding."""
    config = request.app.state.config
    whitelist = config.whitelist_cidrs

    if not whitelist:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "NO_WHITELIST_CONFIGURED",
                "message": "No scan targets configured. Add CIDRs to the whitelist first.",
            },
        )
    if body.target_cidr not in whitelist:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "CIDR_NOT_WHITELISTED",
                "message": f"Target {body.target_cidr} is not in the whitelist. "
                           f"Allowed: {whitelist}",
            },
        )

    db_path = request.app.state.db_path
    conn = repository.get_connection(db_path)
    try:
        scan_id = repository.create_scan_run(conn, body.target_cidr, body.profile)
        scan_run = repository.get_scan_run(conn, scan_id)
    finally:
        conn.close()

    # Create progress queue and store for SSE consumers
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()
    request.app.state.scan_queues[scan_id] = queue

    # Fire orchestrator as background task
    task = asyncio.create_task(
        _run_scan_task(
            scan_id=scan_id,
            target_cidr=body.target_cidr,
            profile=body.profile,
            db_path=db_path,
            oui_resolver=request.app.state.oui_resolver,
            queue=queue,
            app_state=request.app.state,
            cve_index=getattr(request.app.state, "cve_index", None),
        )
    )
    # Store task reference to prevent GC
    request.app.state.scan_tasks = getattr(request.app.state, "scan_tasks", {})
    request.app.state.scan_tasks[scan_id] = task

    return SuccessResponse(data=ScanRunResponse(**scan_run))


async def _run_scan_task(
    scan_id: int,
    target_cidr: str,
    profile: str,
    db_path: str,
    oui_resolver: object,
    queue: asyncio.Queue[ScanProgressEvent],
    app_state: object,
    cve_index: object | None = None,
) -> None:
    """Wrapper that runs the scan and cleans up the queue after completion."""
    try:
        await run_scan(target_cidr, profile, db_path, oui_resolver, queue, cve_index=cve_index)
    except Exception:
        logger.exception("Background scan task %d failed", scan_id)
    finally:
        # Schedule queue cleanup after 60s grace period for late SSE clients
        await asyncio.sleep(60)
        app_state.scan_queues.pop(scan_id, None)  # type: ignore[union-attr]
        app_state.scan_tasks.pop(scan_id, None)  # type: ignore[union-attr]


@router.get("", response_model=SuccessResponse[list[ScanRunResponse]])
async def list_scans(
    request: Request, cursor: int | None = None, limit: int = 20
) -> SuccessResponse[list[ScanRunResponse]]:
    """List all scan runs with cursor-based pagination."""
    conn = repository.get_connection(request.app.state.db_path)
    try:
        runs, next_cursor = repository.list_scan_runs(conn, cursor, limit)
    finally:
        conn.close()

    data = [ScanRunResponse(**r) for r in runs]
    response = SuccessResponse(data=data)
    if next_cursor is not None:
        response.meta.next_cursor = next_cursor  # type: ignore[attr-defined]
    return response


@router.get("/{scan_id}", response_model=SuccessResponse[ScanRunResponse])
async def get_scan(scan_id: int, request: Request) -> SuccessResponse[ScanRunResponse]:
    """Get a single scan run by ID."""
    conn = repository.get_connection(request.app.state.db_path)
    try:
        scan_run = repository.get_scan_run(conn, scan_id)
    finally:
        conn.close()

    if scan_run is None:
        raise HTTPException(status_code=404, detail="Scan run not found")

    return SuccessResponse(data=ScanRunResponse(**scan_run))


@router.get("/{scan_id}/delta", response_model=SuccessResponse[dict])
async def get_scan_delta(scan_id: int, request: Request) -> SuccessResponse[dict]:
    """Get device delta between this scan and the previous one."""
    conn = repository.get_connection(request.app.state.db_path)
    try:
        scan_run = repository.get_scan_run(conn, scan_id)
        if scan_run is None:
            raise HTTPException(status_code=404, detail="Scan run not found")

        # Get devices in this scan
        current_devices = conn.execute(
            """SELECT d.*, sda.ip_address as scan_ip
               FROM scan_device_appearances sda
               JOIN devices d ON d.id = sda.device_id
               WHERE sda.scan_run_id = ?""",
            (scan_id,),
        ).fetchall()
        current_macs = {r["mac_address"] for r in current_devices}

        # Find previous scan
        prev_scan = conn.execute(
            "SELECT id FROM scan_runs WHERE id < ? ORDER BY id DESC LIMIT 1",
            (scan_id,),
        ).fetchone()

        new_devices = []
        disappeared_devices = []

        if prev_scan:
            prev_devices = conn.execute(
                """SELECT d.*, sda.ip_address as scan_ip
                   FROM scan_device_appearances sda
                   JOIN devices d ON d.id = sda.device_id
                   WHERE sda.scan_run_id = ?""",
                (prev_scan["id"],),
            ).fetchall()
            prev_macs = {r["mac_address"] for r in prev_devices}

            new_macs = current_macs - prev_macs
            gone_macs = prev_macs - current_macs

            new_devices = [dict(r) for r in current_devices if r["mac_address"] in new_macs]
            disappeared_devices = [dict(r) for r in prev_devices if r["mac_address"] in gone_macs]
        else:
            # First scan — all devices are new
            new_devices = [dict(r) for r in current_devices]
    finally:
        conn.close()

    return SuccessResponse(data={
        "scan_run_id": scan_id,
        "new_devices": new_devices,
        "disappeared_devices": disappeared_devices,
        "changed_devices": [],
    })


@router.get("/{scan_id}/stream")
async def scan_stream(scan_id: int, request: Request) -> StreamingResponse:
    """SSE endpoint for real-time scan progress events."""
    queue = request.app.state.scan_queues.get(scan_id)

    if queue is None:
        # Scan already finished or never existed — return final status
        conn = repository.get_connection(request.app.state.db_path)
        try:
            scan_run = repository.get_scan_run(conn, scan_id)
        finally:
            conn.close()

        if scan_run is None:
            raise HTTPException(status_code=404, detail="Scan run not found")

        async def finished_stream():
            event = ScanProgressEvent(
                type="complete" if scan_run["status"] == "completed" else "error",
                message=f"Scan already {scan_run['status']}",
            )
            yield f"data: {event.model_dump_json()}\n\n"

        return StreamingResponse(
            finished_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )

    async def event_stream():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {event.model_dump_json()}\n\n"
                    if event.type in ("complete", "error"):
                        break
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            # Client disconnected
            logger.debug("SSE client disconnected for scan %d", scan_id)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
