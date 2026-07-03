import httpx
import re
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.db.models import Article, Vulnerability

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
HANGUL_RE = re.compile(r"[가-힣]")


class SummaryService:
    async def summarize(self, title: str, body: str, source_urls: list[str]) -> str | None:
        if settings.llm_provider == "disabled":
            return None

        payload = {
            "model": settings.llm_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a Korean security analyst. Always answer in Korean only. "
                        "Summarize the security issue in 2-4 concise Korean sentences. "
                        "Use only the provided text. Mention uncertainty. "
                        "Do not invent affected products or CVEs. "
                        "Do not include chain-of-thought, hidden reasoning, or <think> blocks."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "아래 내용을 한국어로만 요약하세요.\n\n"
                        f"Title: {title}\n\nBody:\n{body[:8000]}\n\nSources:\n" + "\n".join(source_urls)
                    ),
                },
            ],
            "temperature": 0.2,
            "max_tokens": settings.llm_max_tokens,
        }
        headers = {"Content-Type": "application/json"}
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"

        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            response = await client.post(
                f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return THINK_BLOCK_RE.sub("", content).strip()


def _vulnerability_body(vulnerability: Vulnerability) -> str:
    parts = [
        f"CVE: {vulnerability.cve_id}",
        f"Title: {vulnerability.title or vulnerability.cve_id}",
    ]
    if vulnerability.description:
        parts.append(f"Description: {vulnerability.description}")
    if vulnerability.vendor or vulnerability.product:
        parts.append(f"Product: {' / '.join(value for value in (vulnerability.vendor, vulnerability.product) if value)}")
    if vulnerability.cvss_severity or vulnerability.cvss_score:
        parts.append(f"CVSS: {vulnerability.cvss_severity or '-'} {vulnerability.cvss_score or '-'}")
    if vulnerability.epss_score is not None:
        parts.append(f"EPSS: {round(vulnerability.epss_score * 100, 2)}%")
    if vulnerability.kev:
        parts.append("CISA KEV: known exploited vulnerability")
    return "\n".join(parts)


def _compact(value: str | None, limit: int = 700) -> str:
    if not value:
        return ""
    text = " ".join(value.split())
    return text[:limit]


def _has_korean_text(value: str | None) -> bool:
    if not value:
        return False
    return len(HANGUL_RE.findall(value)) >= 12


def _fallback_article_summary(article: Article) -> str:
    source_name = article.source.name if article.source else "수집원"
    excerpt = _compact(article.raw_excerpt, 450)
    if excerpt and _has_korean_text(excerpt):
        return f"{source_name}에서 수집된 보안 이슈입니다. 핵심 제목은 '{article.title}'이며, 원문 요약 근거는 다음과 같습니다: {excerpt}"
    if excerpt:
        return f"{source_name}에서 수집된 영문 보안 이슈입니다. 핵심 제목은 '{article.title}'이며, 상세 내용은 원문 링크 확인이 필요합니다."
    return f"{source_name}에서 수집된 보안 이슈입니다. 현재 확보된 근거는 제목과 원문 링크이며, 상세 판단은 원문 확인이 필요합니다."


def _fallback_vulnerability_summary(vulnerability: Vulnerability) -> str:
    parts = [f"{vulnerability.cve_id}는"]
    if vulnerability.vendor or vulnerability.product:
        parts.append(f"{' / '.join(value for value in (vulnerability.vendor, vulnerability.product) if value)} 관련 취약점입니다.")
    else:
        parts.append("제품 식별 정보가 제한적인 취약점입니다.")
    if vulnerability.cvss_severity or vulnerability.cvss_score:
        parts.append(f"CVSS는 {vulnerability.cvss_severity or '-'} {vulnerability.cvss_score or '-'}입니다.")
    if vulnerability.epss_score is not None:
        parts.append(f"EPSS는 {round(vulnerability.epss_score * 100, 2)}%입니다.")
    if vulnerability.kev:
        parts.append("CISA KEV에 포함되어 실제 악용 이력이 있는 항목으로 우선 확인이 필요합니다.")
    if vulnerability.description and _has_korean_text(vulnerability.description):
        parts.append(f"설명: {_compact(vulnerability.description, 450)}")
    elif vulnerability.description:
        parts.append("영문 원문 설명이 제공된 항목으로, 상세 영향은 원문 링크 확인이 필요합니다.")
    return " ".join(parts)


def _usable_summary(summary: str | None, required_terms: list[str] | None = None) -> str | None:
    if not summary:
        return None
    cleaned = summary.strip()
    if not _has_korean_text(cleaned):
        return None
    lowered = cleaned.lower()
    if required_terms and not any(term.lower() in lowered for term in required_terms):
        return None
    return cleaned


async def summarize_recent_articles(db: Session, limit: int = 20) -> tuple[int, int]:
    rows = db.scalars(
        select(Article)
        .options(selectinload(Article.source))
        .order_by(Article.published_at.desc().nullslast(), Article.created_at.desc())
        .limit(limit)
    ).all()
    changed = 0
    service = SummaryService()
    for article in rows:
        body = article.raw_excerpt or article.title
        summary = None
        if settings.llm_provider != "disabled":
            try:
                summary = await service.summarize(article.title, body, [article.url])
            except Exception:
                summary = None
        article.summary = _usable_summary(summary) or _fallback_article_summary(article)
        changed += 1
    db.commit()
    return len(rows), changed


async def summarize_recent_vulnerabilities(db: Session, limit: int = 20) -> tuple[int, int]:
    rows = db.scalars(
        select(Vulnerability)
        .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_score.desc().nullslast(), Vulnerability.epss_score.desc().nullslast())
        .limit(limit)
    ).all()
    changed = 0
    service = SummaryService()
    for vulnerability in rows:
        summary = None
        if settings.llm_provider != "disabled":
            try:
                summary = await service.summarize(
                    vulnerability.title or vulnerability.cve_id,
                    _vulnerability_body(vulnerability),
                    [vulnerability.source_url] if vulnerability.source_url else [],
                )
            except Exception:
                summary = None
        required_terms = [vulnerability.cve_id]
        if vulnerability.product:
            required_terms.append(vulnerability.product)
        vulnerability.summary = _usable_summary(summary, required_terms=required_terms) or _fallback_vulnerability_summary(vulnerability)
        changed += 1
    db.commit()
    return len(rows), changed


def build_trend_report(db: Session, limit: int = 10) -> dict:
    articles = db.scalars(
        select(Article)
        .options(selectinload(Article.source))
        .order_by(Article.published_at.desc().nullslast(), Article.created_at.desc())
        .limit(limit)
    ).all()
    vulnerabilities = db.scalars(
        select(Vulnerability)
        .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_score.desc().nullslast(), Vulnerability.epss_score.desc().nullslast())
        .limit(limit)
    ).all()

    news_items = [
        {
            "title": article.title,
            "summary": article.summary or _fallback_article_summary(article),
            "source": article.source.name if article.source else None,
            "url": article.url,
            "published_at": article.published_at,
        }
        for article in articles
    ]
    vulnerability_items = [
        {
            "title": vulnerability.title or vulnerability.cve_id,
            "summary": vulnerability.summary or _fallback_vulnerability_summary(vulnerability),
            "cve_id": vulnerability.cve_id,
            "url": vulnerability.source_url,
            "kev": vulnerability.kev,
            "cvss_score": vulnerability.cvss_score,
            "epss_score": vulnerability.epss_score,
        }
        for vulnerability in vulnerabilities
    ]
    themes = []
    if any(item["kev"] for item in vulnerability_items):
        themes.append("CISA KEV 기반으로 실제 악용 이력이 있는 취약점 우선 점검이 필요합니다.")
    if news_items:
        themes.append("최근 보안 뉴스와 취약점 공지의 원문 링크를 함께 확인해야 합니다.")
    if vulnerability_items:
        themes.append("Tanium 영향 분석 결과와 CVE 우선순위를 함께 보며 패치 대상을 좁히는 단계입니다.")

    return {
        "themes": themes,
        "news": news_items,
        "vulnerabilities": vulnerability_items,
    }
