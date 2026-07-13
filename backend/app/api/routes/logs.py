from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Article, Vulnerability
from app.db.session import get_db
from app.schemas import SummaryLogItem

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/summary-failures", response_model=list[SummaryLogItem])
def list_summary_failures(
    limit: int = Query(default=50, ge=1, le=500),
    target: str = Query(default="all", pattern="^(all|cves|news)$"),
    db: Session = Depends(get_db),
) -> list[SummaryLogItem]:
    items: list[SummaryLogItem] = []
    if target in {"all", "cves"}:
        vulnerabilities = db.scalars(
            select(Vulnerability)
            .where(Vulnerability.summary_status == "fallback")
            .order_by(Vulnerability.published_at.desc().nullslast(), Vulnerability.created_at.desc())
            .limit(limit)
        ).all()
        items.extend(
            SummaryLogItem(
                target="cve",
                item_id=item.id,
                title=item.cve_id,
                status=item.summary_status,
                error=item.summary_error,
                error_detail=item.summary_error_detail,
                published_at=item.published_at,
                source_url=item.source_url,
                summary_preview=(item.summary or item.description or "")[:240],
            )
            for item in vulnerabilities
        )
    if target in {"all", "news"}:
        articles = db.scalars(
            select(Article)
            .where(Article.summary_status == "fallback")
            .order_by(Article.published_at.desc().nullslast(), Article.created_at.desc())
            .limit(limit)
        ).all()
        items.extend(
            SummaryLogItem(
                target="news",
                item_id=item.id,
                title=item.title,
                status=item.summary_status,
                error=item.summary_error,
                error_detail=item.summary_error_detail,
                published_at=item.published_at,
                source_url=item.url,
                summary_preview=(item.summary or item.raw_excerpt or "")[:240],
            )
            for item in articles
        )
    return sorted(items, key=lambda item: item.published_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)[:limit]
