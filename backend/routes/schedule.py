"""Schedule routes — GET/PUT /api/schedule with APScheduler wiring."""

import asyncio
import logging

from fastapi import APIRouter, Request

from models.schemas import ScheduleConfig, SuccessResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/schedule", tags=["schedule"])


@router.get("", response_model=SuccessResponse[ScheduleConfig])
async def get_schedule(request: Request) -> SuccessResponse[ScheduleConfig]:
    """Return the current schedule configuration."""
    config = request.app.state.config
    return SuccessResponse(data=ScheduleConfig(
        cron_expression=config.schedule_cron,
        target_cidr=config.get("schedule_target_cidr"),
        profile=config.get("schedule_profile") or "quick",
    ))


@router.put("", response_model=SuccessResponse[ScheduleConfig])
async def update_schedule(body: ScheduleConfig, request: Request) -> SuccessResponse[ScheduleConfig]:
    """Update the schedule configuration and reload the scheduler job."""
    config = request.app.state.config

    if body.cron_expression is not None:
        config.set("schedule_cron", body.cron_expression or "")
    if body.target_cidr is not None:
        config.set("schedule_target_cidr", body.target_cidr)
    if body.profile is not None:
        config.set("schedule_profile", body.profile)

    # Reload the scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler:
        _reload_scheduler_job(request.app)

    logger.info("Schedule updated: cron=%s target=%s profile=%s",
                body.cron_expression, body.target_cidr, body.profile)

    return SuccessResponse(data=ScheduleConfig(
        cron_expression=config.schedule_cron,
        target_cidr=config.get("schedule_target_cidr"),
        profile=config.get("schedule_profile") or "quick",
    ))


def setup_scheduler(app: object) -> None:
    """Initialize APScheduler and register the scan job if configured."""
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        logger.warning("APScheduler not available — scheduled scans disabled")
        return

    scheduler = AsyncIOScheduler()
    app.state.scheduler = scheduler  # type: ignore[union-attr]
    scheduler.start()

    _reload_scheduler_job(app)
    logger.info("APScheduler started")


def _reload_scheduler_job(app: object) -> None:
    """Remove existing scan job and re-add it based on current config."""
    scheduler = app.state.scheduler  # type: ignore[union-attr]
    config = app.state.config  # type: ignore[union-attr]

    # Remove existing job
    existing = scheduler.get_job("scheduled_scan")
    if existing:
        scheduler.remove_job("scheduled_scan")

    cron_expr = config.schedule_cron
    if not cron_expr:
        logger.info("No schedule configured — scheduled scanning disabled")
        return

    target_cidr = config.get("schedule_target_cidr")
    profile = config.get("schedule_profile") or "quick"

    if not target_cidr:
        logger.warning("Schedule has cron but no target CIDR — skipping")
        return

    try:
        from apscheduler.triggers.cron import CronTrigger

        parts = cron_expr.split()
        if len(parts) != 5:
            logger.error("Invalid cron expression: %s", cron_expr)
            return

        trigger = CronTrigger(
            minute=parts[0], hour=parts[1], day=parts[2],
            month=parts[3], day_of_week=parts[4],
        )

        scheduler.add_job(
            _run_scheduled_scan,
            trigger=trigger,
            id="scheduled_scan",
            args=[app, target_cidr, profile],
            replace_existing=True,
        )
        logger.info("Scheduled scan registered: %s → %s (%s)", cron_expr, target_cidr, profile)
    except Exception:
        logger.exception("Failed to register scheduled scan job")


async def _run_scheduled_scan(app: object, target_cidr: str, profile: str) -> None:
    """Execute a scheduled scan."""
    from models.schemas import ScanProgressEvent
    from scanner.orchestrator import run_scan

    logger.info("Scheduled scan starting: %s with profile %s", target_cidr, profile)

    # Create a dummy queue (no SSE consumer for scheduled scans)
    queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()
    cve_index = getattr(app.state, "cve_index", None)  # type: ignore[union-attr]

    try:
        scan_id = await run_scan(
            target_cidr, profile,
            app.state.db_path,  # type: ignore[union-attr]
            app.state.oui_resolver,  # type: ignore[union-attr]
            queue,
            cve_index=cve_index,
        )
        logger.info("Scheduled scan completed: scan_id=%d", scan_id)
    except Exception:
        logger.exception("Scheduled scan failed")
