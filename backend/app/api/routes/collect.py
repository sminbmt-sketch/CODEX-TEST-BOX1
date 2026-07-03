from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability
from app.db.session import get_db
from app.schemas import CollectionResult
from app.services.news_sources import collect_rss_feeds
from app.services.vulnerability_sources import collect_cisa_kev, collect_recent_nvd, update_epss_scores

router = APIRouter(prefix="/collect", tags=["collect"])


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
async def run_news_collection(db: Session = Depends(get_db)) -> CollectionResult:
    try:
        fetched, changed = await collect_rss_feeds(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"News collection failed: {exc}") from exc
    return CollectionResult(source="RSS feeds", fetched=fetched, created_or_updated=changed)
