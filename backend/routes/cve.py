"""CVE routes — NVD feed status and refresh trigger."""

import asyncio
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from config import AppConfig, get_data_dir
from cve.index import CVEIndex
from cve.loader import download_nvd_feed
from models.schemas import CVEIndexStatus, SuccessResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cve", tags=["cve"])


@router.get("/status", response_model=SuccessResponse[CVEIndexStatus])
async def get_cve_status(request: Request) -> SuccessResponse[CVEIndexStatus]:
    """Return the current state of the NVD CVE index."""
    config = request.app.state.config
    cve_index: CVEIndex | None = getattr(request.app.state, "cve_index", None)
    downloading: bool = getattr(request.app.state, "cve_downloading", False)
    download_progress: float | None = getattr(request.app.state, "cve_download_progress", None)

    status = CVEIndexStatus(
        download_complete=config.nvd_download_complete,
        last_updated=config.nvd_last_updated,
        cve_count=cve_index.entry_count if cve_index else 0,
        downloading=downloading,
        download_progress=download_progress,
    )
    return SuccessResponse(data=status)


@router.post("/refresh", status_code=202)
async def refresh_cve_feed(request: Request) -> JSONResponse:
    """Trigger NVD feed re-download in background."""
    if getattr(request.app.state, "cve_downloading", False):
        return JSONResponse(
            status_code=409,
            content={"success": False, "error": {"code": "ALREADY_DOWNLOADING",
                     "message": "CVE feed download already in progress"}},
        )

    request.app.state.cve_downloading = True
    request.app.state.cve_download_progress = 0.0

    asyncio.create_task(
        _download_and_index(request.app.state)
    )

    return JSONResponse(
        status_code=202,
        content={"success": True, "data": {"message": "CVE feed download started"}},
    )


async def _download_and_index(app_state: object) -> None:
    """Background task: download NVD feed and rebuild index."""
    try:
        data_dir = get_data_dir()
        cache_dir = data_dir / "nvd_cache"

        def on_progress(downloaded: int, total: int) -> None:
            if total > 0:
                app_state.cve_download_progress = round(downloaded / total * 100, 1)  # type: ignore[union-attr]

        total = await asyncio.to_thread(
            download_nvd_feed, cache_dir, on_progress
        )

        if total > 0:
            # Rebuild index
            index = CVEIndex()
            await asyncio.to_thread(index.load, cache_dir)
            app_state.cve_index = index  # type: ignore[union-attr]

            # Update config
            config: AppConfig = app_state.config  # type: ignore[union-attr]
            config.set("nvd_download_complete", "1")
            config.set("nvd_last_updated", datetime.now(UTC).isoformat())

            logger.info("CVE feed refresh complete: %d CVEs indexed", index.entry_count)
        else:
            logger.error("CVE feed download returned 0 CVEs")

    except Exception:
        logger.exception("CVE feed refresh failed")
    finally:
        app_state.cve_downloading = False  # type: ignore[union-attr]
        app_state.cve_download_progress = None  # type: ignore[union-attr]
