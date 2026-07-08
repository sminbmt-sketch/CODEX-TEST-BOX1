import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
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

EPSS_JOB: dict[str, object] = {
    "job_id": "epss",
    "status": "idle",
    "source": "FIRST EPSS",
    "fetched": 0,
    "created_or_updated": 0,
}


def _job_status() -> CollectionJobStatus:
    return CollectionJobStatus.model_validate(NVD_YEAR_JOB)


def _epss_job_status() -> CollectionJobStatus:
    return CollectionJobStatus.model_validate(EPSS_JOB)


def _epss_target_cve_ids(db: Session, mode: str, days: int, retry_days: int, limit: int | None) -> list[str]:
    query = select(Vulnerability.cve_id)
    checked_cutoff = datetime.now(timezone.utc) - timedelta(days=retry_days)
    update_cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    missing_retryable = and_(
        Vulnerability.epss_score.is_(None),
        or_(Vulnerability.epss_checked_at.is_(None), Vulnerability.epss_checked_at < checked_cutoff),
    )
    stale_retryable = or_(
        missing_retryable,
        and_(
            Vulnerability.epss_score.is_not(None),
            or_(Vulnerability.epss_updated_at.is_(None), Vulnerability.epss_updated_at < update_cutoff),
        ),
    )
    if mode == "missing":
        query = query.where(missing_retryable)
    elif mode == "recent":
        query = query.where(Vulnerability.published_at >= update_cutoff).where(stale_retryable)
    elif mode == "stale":
        query = query.where(stale_retryable)
    elif mode != "all":
        raise ValueError("mode must be one of: missing, recent, stale, all")
    if mode == "stale":
        query = query.order_by(
            Vulnerability.epss_score.is_(None),
            Vulnerability.epss_updated_at.asc().nullsfirst(),
            Vulnerability.published_at.desc().nullslast(),
            Vulnerability.cvss_score.desc().nullslast(),
        )
    else:
        query = query.order_by(
            Vulnerability.epss_score.is_not(None),
            Vulnerability.published_at.desc().nullslast(),
            Vulnerability.cvss_score.desc().nullslast(),
        )
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query).all())


async def _run_epss_job(mode: str, days: int, retry_days: int, limit: int | None, batch_size: int) -> None:
    EPSS_JOB.update(
        {
            "status": "running",
            "source": "FIRST EPSS",
            "mode": mode,
            "retry_days": retry_days,
            "current_batch": 0,
            "total_batches": 0,
            "fetched": 0,
            "created_or_updated": 0,
            "error": None,
            "started_at": datetime.now(),
            "finished_at": None,
        }
    )
    db = SessionLocal()
    try:
        cve_ids = _epss_target_cve_ids(db, mode=mode, days=days, retry_days=retry_days, limit=limit)
        total_batches = (len(cve_ids) + batch_size - 1) // batch_size
        EPSS_JOB["total_batches"] = total_batches
        for batch_number, index in enumerate(range(0, len(cve_ids), batch_size), start=1):
            EPSS_JOB["current_batch"] = batch_number
            fetched, changed = await update_epss_scores(db, cve_ids[index : index + batch_size])
            EPSS_JOB["fetched"] = int(EPSS_JOB.get("fetched") or 0) + fetched
            EPSS_JOB["created_or_updated"] = int(EPSS_JOB.get("created_or_updated") or 0) + changed
        EPSS_JOB["status"] = "completed"
    except Exception as exc:
        EPSS_JOB["status"] = "failed"
        EPSS_JOB["error"] = str(exc)
    finally:
        EPSS_JOB["finished_at"] = datetime.now()
        db.close()


def _run_epss_job_sync(mode: str, days: int, retry_days: int, limit: int | None, batch_size: int) -> None:
    asyncio.run(_run_epss_job(mode, days, retry_days, limit, batch_size))


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
    mode: str = Query(default="missing", pattern="^(missing|recent|stale|all)$"),
    days: int = Query(default=30, ge=1, le=365),
    retry_days: int = Query(default=1, ge=1, le=30),
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
) -> CollectionResult:
    cve_ids = _epss_target_cve_ids(db, mode=mode, days=days, retry_days=retry_days, limit=limit)
    try:
        fetched, changed = await update_epss_scores(db, cve_ids)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"EPSS update failed: {exc}") from exc
    return CollectionResult(source=f"FIRST EPSS ({mode})", fetched=fetched, created_or_updated=changed)


@router.post("/epss/job", response_model=CollectionJobStatus)
async def run_epss_update_job(
    background_tasks: BackgroundTasks,
    mode: str = Query(default="missing", pattern="^(missing|recent|stale|all)$"),
    days: int = Query(default=30, ge=1, le=365),
    retry_days: int = Query(default=1, ge=1, le=30),
    limit: int | None = Query(default=None, ge=1, le=100000),
    batch_size: int = Query(default=100, ge=1, le=500),
) -> CollectionJobStatus:
    if EPSS_JOB.get("status") == "running":
        raise HTTPException(status_code=409, detail="EPSS update job is already running")
    EPSS_JOB.update(
        {
            "status": "queued",
            "source": "FIRST EPSS",
            "mode": mode,
            "retry_days": retry_days,
            "current_batch": None,
            "total_batches": None,
            "fetched": 0,
            "created_or_updated": 0,
            "error": None,
            "started_at": datetime.now(),
            "finished_at": None,
        }
    )
    background_tasks.add_task(_run_epss_job_sync, mode, days, retry_days, limit, batch_size)
    return _epss_job_status()


@router.get("/epss/status", response_model=CollectionJobStatus)
async def get_epss_update_status() -> CollectionJobStatus:
    return _epss_job_status()


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
