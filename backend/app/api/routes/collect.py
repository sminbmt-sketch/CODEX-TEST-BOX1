import asyncio
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability
from app.db.session import SessionLocal, get_db
from app.schemas import CollectionJobStatus, CollectionResult
from app.services.news_sources import collect_rss_feeds
from app.services.vulnerability_sources import collect_cisa_kev, collect_nvd_recent_feed, collect_nvd_year_feed, collect_recent_nvd, update_epss_scores

router = APIRouter(prefix="/collect", tags=["collect"])

NVD_YEAR_JOB: dict[str, object] = {
    "job_id": "nvd-year",
    "status": "idle",
    "source": "NVD CVE yearly feeds",
    "fetched": 0,
    "created_or_updated": 0,
}


def _job_status() -> CollectionJobStatus:
    return CollectionJobStatus.model_validate(NVD_YEAR_JOB)


async def _run_nvd_year_job(start: int, end: int) -> None:
    NVD_YEAR_JOB.update(
        {
            "status": "running",
            "source": f"NVD CVE {start}" if start == end else f"NVD CVE {start}-{end}",
            "start_year": start,
            "end_year": end,
            "current_year": None,
            "fetched": 0,
            "created_or_updated": 0,
            "error": None,
            "started_at": datetime.now(),
            "finished_at": None,
        }
    )
    db = SessionLocal()
    try:
        for feed_year in range(start, end + 1):
            NVD_YEAR_JOB["current_year"] = feed_year
            fetched, changed = await collect_nvd_year_feed(db, year=feed_year)
            NVD_YEAR_JOB["fetched"] = int(NVD_YEAR_JOB.get("fetched") or 0) + fetched
            NVD_YEAR_JOB["created_or_updated"] = int(NVD_YEAR_JOB.get("created_or_updated") or 0) + changed
        NVD_YEAR_JOB["status"] = "completed"
    except Exception as exc:
        NVD_YEAR_JOB["status"] = "failed"
        NVD_YEAR_JOB["error"] = str(exc)
    finally:
        NVD_YEAR_JOB["finished_at"] = datetime.now()
        db.close()


def _run_nvd_year_job_sync(start: int, end: int) -> None:
    asyncio.run(_run_nvd_year_job(start, end))


@router.post("/nvd", response_model=CollectionResult)
async def run_nvd_collection(
    days: int = Query(default=14, ge=1, le=120),
    limit: int = Query(default=100, ge=1, le=2000),
    db: Session = Depends(get_db),
) -> CollectionResult:
    try:
        fetched, changed = await collect_recent_nvd(db, days=days, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"NVD collection failed: {exc}") from exc
    return CollectionResult(source="NVD", fetched=fetched, created_or_updated=changed)


@router.post("/nvd/year", response_model=CollectionJobStatus)
async def run_nvd_year_collection(
    background_tasks: BackgroundTasks,
    year: int | None = Query(default=None, ge=2002, le=datetime.now().year),
    start_year: int | None = Query(default=None, ge=2002, le=datetime.now().year),
    end_year: int | None = Query(default=None, ge=2002, le=datetime.now().year),
) -> CollectionJobStatus:
    start = start_year or year or datetime.now().year
    end = end_year or year or start
    if start > end:
        raise HTTPException(status_code=400, detail="start_year must be less than or equal to end_year")
    if NVD_YEAR_JOB.get("status") == "running":
        raise HTTPException(status_code=409, detail="NVD year feed job is already running")
    background_tasks.add_task(_run_nvd_year_job_sync, start, end)
    NVD_YEAR_JOB.update(
        {
            "status": "queued",
            "source": f"NVD CVE {start}" if start == end else f"NVD CVE {start}-{end}",
            "start_year": start,
            "end_year": end,
            "current_year": None,
            "fetched": 0,
            "created_or_updated": 0,
            "error": None,
            "started_at": datetime.now(),
            "finished_at": None,
        }
    )
    return _job_status()


@router.post("/nvd/recent-feed", response_model=CollectionResult)
async def run_nvd_recent_feed_collection(db: Session = Depends(get_db)) -> CollectionResult:
    try:
        fetched, changed = await collect_nvd_recent_feed(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"NVD recent feed collection failed: {exc}") from exc
    return CollectionResult(source="NVD CVE Recent", fetched=fetched, created_or_updated=changed)


@router.get("/nvd/year/status", response_model=CollectionJobStatus)
async def get_nvd_year_collection_status() -> CollectionJobStatus:
    return _job_status()


@router.post("/cisa-kev", response_model=CollectionResult)
async def run_cisa_kev_collection(db: Session = Depends(get_db)) -> CollectionResult:
    try:
        fetched, changed = await collect_cisa_kev(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"CISA KEV collection failed: {exc}") from exc
    return CollectionResult(source="CISA KEV", fetched=fetched, created_or_updated=changed)


@router.post("/epss", response_model=CollectionResult)
async def run_epss_update(
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
) -> CollectionResult:
    cve_ids = list(db.scalars(select(Vulnerability.cve_id).limit(limit)).all())
    try:
        fetched, changed = await update_epss_scores(db, cve_ids)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"EPSS update failed: {exc}") from exc
    return CollectionResult(source="FIRST EPSS", fetched=fetched, created_or_updated=changed)


@router.post("/news", response_model=CollectionResult)
async def run_news_collection(
    days: int = Query(default=7, ge=1, le=365),
    db: Session = Depends(get_db),
) -> CollectionResult:
    try:
        fetched, changed = await collect_rss_feeds(db, days=days)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"News collection failed: {exc}") from exc
    return CollectionResult(source="RSS feeds", fetched=fetched, created_or_updated=changed)
