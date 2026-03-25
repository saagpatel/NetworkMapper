"""FastAPI application — entry point, lifespan, router mounting."""

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from fastapi import FastAPI

from pathlib import Path

from config import AppConfig, get_data_dir, get_db_path
from db.schema import init_db
from oui.resolver import OUIResolver
from routes.config import router as config_router
from routes.cve import router as cve_router
from routes.devices import router as devices_router
from routes.scans import router as scans_router
from routes.schedule import router as schedule_router, setup_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan — startup and shutdown logic."""
    # Startup
    data_dir = get_data_dir()
    logger.info("Data directory: %s", data_dir)

    db_path = get_db_path()
    init_db(db_path)

    app.state.db_path = str(db_path)
    app.state.config = AppConfig(db_path)
    logger.info("Config loaded — whitelist: %s", app.state.config.whitelist_cidrs)

    app.state.oui_resolver = OUIResolver(data_dir)
    logger.info("OUI resolver loaded: %d entries", app.state.oui_resolver.entry_count)

    app.state.scan_queues: dict = {}

    # CVE index — load from cache if available
    app.state.cve_index = None
    app.state.cve_downloading = False
    app.state.cve_download_progress = None
    if app.state.config.nvd_download_complete:
        from cve.index import CVEIndex

        cache_dir = data_dir / "nvd_cache"
        if cache_dir.exists():
            cve_index = CVEIndex()
            cve_index.load(cache_dir)
            app.state.cve_index = cve_index
            logger.info("CVE index loaded: %d entries", cve_index.entry_count)
        else:
            logger.warning("NVD cache directory not found — CVE matching disabled")
    else:
        logger.info("NVD feed not downloaded — CVE matching disabled until POST /api/cve/refresh")

    # APScheduler
    setup_scheduler(app)

    yield

    # Shutdown
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler:
        scheduler.shutdown(wait=False)
    logger.info("Shutting down NetMapper")


app = FastAPI(title="NetMapper", version="0.1.0", lifespan=lifespan)

app.include_router(config_router)
app.include_router(cve_router)
app.include_router(scans_router)
app.include_router(devices_router)
app.include_router(schedule_router)


@app.get("/health")
async def health() -> dict[str, object]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": datetime.now(UTC).isoformat(),
    }


# Static file serving — MUST be after all API routes
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    from starlette.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
