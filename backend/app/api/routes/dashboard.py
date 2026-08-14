from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import re

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Article, Detection, EndpointSnapshot, Vulnerability
from app.db.session import get_db
from app.schemas import ArticleOut, DashboardSummary, HotTopicItem, VulnerabilityOut

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

TOPIC_TOKEN_RE = re.compile(r"[가-힣A-Za-z][가-힣A-Za-z0-9+._-]{1,}")
TOPIC_STOPWORDS = {
    "cve",
    "보안",
    "취약점",
    "공격",
    "업데이트",
    "발견",
    "사용자",
    "시스템",
    "뉴스",
    "기사",
    "최신",
    "통해",
    "대상",
    "관련",
    "기반",
    "가능",
    "주의",
    "권고",
    "관리자",
    "security",
    "vulnerability",
    "vulnerabilities",
    "attack",
    "attacks",
    "update",
    "updates",
    "user",
    "users",
    "system",
    "systems",
    "new",
    "via",
    "using",
    "after",
    "from",
    "with",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "code",
    "critical",
    "data",
    "flaw",
    "flaws",
    "has",
    "have",
    "the",
    "for",
    "in",
    "into",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "to",
    "that",
    "this",
    "was",
    "been",
    "were",
    "will",
    "lets",
    "let",
    "could",
    "can",
    "may",
    "remote",
    "warns",
    "warning",
    "zero-day",
    "해당",
    "대한",
    "있는",
    "없는",
    "있어",
    "위해",
    "경우",
    "것으로",
    "것은",
    "것이",
    "하는",
    "했다",
    "합니다",
    "했습니다",
    "입니다",
    "됩니다",
    "있습니다",
    "보안뉴스",
    "기자",
    "원문",
    "링크",
    "확인",
    "필요합니다",
}
SHORT_ALLOWED_TOPICS = {"ai", "os", "ip", "iot", "apt"}


def _topic_key(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("cve-"):
        return "cve"
    return text


def _topic_display(value: str) -> str:
    return value.upper() if value.isascii() and len(value) <= 4 else value


def _build_hot_topics(db: Session, days: int = 30, limit: int = 10) -> tuple[list[HotTopicItem], str | None]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    articles = db.scalars(
        select(Article)
        .options(selectinload(Article.source))
        .where((Article.published_at >= cutoff) | (Article.published_at.is_(None) & (Article.created_at >= cutoff)))
        .order_by(Article.published_at.desc().nullslast(), Article.created_at.desc())
        .limit(1000)
    ).all()
    counts: Counter[str] = Counter()
    article_ids: dict[str, set[int]] = defaultdict(set)
    views: Counter[str] = Counter()
    top_article: dict[str, Article] = {}
    display_values: dict[str, Counter[str]] = defaultdict(Counter)

    for article in articles:
        text = " ".join(value for value in (article.title, article.summary, article.raw_excerpt) if value)
        seen_in_article: set[str] = set()
        for match in TOPIC_TOKEN_RE.finditer(text):
            raw = match.group(0).strip("._-")
            if len(raw) < 2:
                continue
            key = _topic_key(raw)
            if raw.isascii() and len(key) <= 2 and key not in SHORT_ALLOWED_TOPICS:
                continue
            if key in TOPIC_STOPWORDS or key.isdigit() or len(key) > 40:
                continue
            counts[key] += 1
            seen_in_article.add(key)
            display_values[key][raw] += 1
        for key in seen_in_article:
            article_ids[key].add(article.id)
            article_views = int(article.view_count or 0)
            views[key] += article_views
            current = top_article.get(key)
            if current is None or article_views > int(current.view_count or 0):
                top_article[key] = article

    ranked = sorted(counts.keys(), key=lambda key: (counts[key], len(article_ids[key]), views[key]), reverse=True)[:limit]
    topics: list[HotTopicItem] = []
    for key in ranked:
        display = display_values[key].most_common(1)[0][0] if display_values[key] else key
        article = top_article.get(key)
        topics.append(
            HotTopicItem(
                keyword=_topic_display(display),
                count=counts[key],
                article_count=len(article_ids[key]),
                total_views=views[key],
                top_article_title=article.title if article else None,
                top_article_url=article.url if article else None,
            )
        )
    brief = None
    if topics:
        brief = "최근 30일 반복 노출 키워드: " + ", ".join(item.keyword for item in topics[:5])
    return topics, brief


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
    hot_topics, hot_topic_brief = _build_hot_topics(db)

    return DashboardSummary(
        vulnerability_count=vulnerability_count,
        kev_count=kev_count,
        article_count=article_count,
        endpoint_count=endpoint_count,
        detection_count=detection_count,
        top_risks=[VulnerabilityOut.model_validate(item) for item in top_risks],
        latest_articles=[ArticleOut.model_validate(item) for item in latest_articles],
        hot_topics=hot_topics,
        hot_topic_brief=hot_topic_brief,
    )
