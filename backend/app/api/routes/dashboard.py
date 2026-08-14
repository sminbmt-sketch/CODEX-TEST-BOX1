from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Article, Detection, EndpointSnapshot, Vulnerability
from app.db.session import get_db
from app.schemas import ArticleOut, DashboardSummary, HotTopicItem, VulnerabilityOut
from app.services.hot_topics import current_hot_topics, refresh_hot_topic_snapshot

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db)) -> DashboardSummary:
    vulnerability_count = db.scalar(select(func.count(Vulnerability.id))) or 0
    kev_count = db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.kev.is_(True))) or 0
    article_count = db.scalar(select(func.count(Article.id))) or 0
    endpoint_count = db.scalar(select(func.count(EndpointSnapshot.id))) or 0
    detection_count = db.scalar(select(func.count(Detection.id))) or 0

    top_risks = db.scalars(
        select(Vulnerability)
        .order_by(Vulnerability.published_at.desc().nullslast(), Vulnerability.kev.desc(), Vulnerability.cvss_score.desc().nullslast())
        .limit(10)
    ).all()
    latest_articles = db.scalars(
        select(Article)
        .options(selectinload(Article.source))
        .order_by(Article.published_at.desc().nullslast(), Article.created_at.desc())
        .limit(10)
    ).all()
    hot_topics, hot_topic_brief, hot_topic_source, hot_topic_updated_at = current_hot_topics(db)

    return DashboardSummary(
        vulnerability_count=vulnerability_count,
        kev_count=kev_count,
        article_count=article_count,
        endpoint_count=endpoint_count,
        detection_count=detection_count,
        top_risks=[VulnerabilityOut.model_validate(item) for item in top_risks],
        latest_articles=[ArticleOut.model_validate(item) for item in latest_articles],
        hot_topics=[HotTopicItem.model_validate(item) for item in hot_topics],
        hot_topic_brief=hot_topic_brief,
        hot_topic_source=hot_topic_source,
        hot_topic_updated_at=hot_topic_updated_at,
    )


@router.post("/hot-topics/refresh", response_model=DashboardSummary)
async def refresh_hot_topics(db: Session = Depends(get_db)) -> DashboardSummary:
    await refresh_hot_topic_snapshot(db)
    return summary(db)
