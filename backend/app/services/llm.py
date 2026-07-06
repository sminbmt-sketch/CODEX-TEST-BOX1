from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import httpx
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.db.models import Article, LlmSetting, Vulnerability

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
HANGUL_RE = re.compile(r"[가-힣]")
SUMMARY_RECENT_DAYS = 7
DEFAULT_LLM_BASE_URLS = {
    "ollama": "http://localhost:11434/v1",
    "openai": "https://api.openai.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "anthropic": "https://api.anthropic.com/v1",
}
DEFAULT_LLM_MODELS = {
    "ollama": "qwen2.5:1.5b",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-3.5-flash",
    "anthropic": "claude-3-5-haiku-latest",
}


@dataclass(frozen=True)
class LlmRuntimeConfig:
    provider: str
    base_url: str
    model: str
    api_key: str | None
    timeout_seconds: int
    max_tokens: int


def default_base_url(provider: str) -> str:
    return DEFAULT_LLM_BASE_URLS.get(provider, settings.llm_base_url)


def default_model(provider: str) -> str:
    return DEFAULT_LLM_MODELS.get(provider, settings.llm_model)


def get_llm_setting(db: Session) -> LlmSetting | None:
    return db.scalar(select(LlmSetting).order_by(LlmSetting.id.asc()).limit(1))


def sanitize_llm_error(exc: Exception) -> str:
    message = str(exc)
    if isinstance(exc, httpx.HTTPStatusError):
        message = f"{exc.response.status_code} {exc.response.reason_phrase}"
        try:
            detail = exc.response.json().get("error", {}).get("message")
        except ValueError:
            detail = None
        if detail:
            message = f"{message}: {detail}"
    parts = urlsplit(message)
    if parts.query:
        safe_query = urlencode((key, "REDACTED" if key.lower() in {"key", "api_key", "apikey"} else value) for key, value in parse_qsl(parts.query, keep_blank_values=True))
        message = urlunsplit((parts.scheme, parts.netloc, parts.path, safe_query, parts.fragment))
    return re.sub(r"key=[^\\s&]+", "key=REDACTED", message)


def resolve_llm_config(db: Session | None = None) -> LlmRuntimeConfig:
    row = get_llm_setting(db) if db is not None else None
    provider = row.provider if row else settings.llm_provider
    provider = provider or "disabled"
    return LlmRuntimeConfig(
        provider=provider,
        base_url=(row.base_url if row and row.base_url else default_base_url(provider)),
        model=(row.model if row and row.model else default_model(provider)),
        api_key=(row.api_key if row else settings.llm_api_key),
        timeout_seconds=(row.timeout_seconds if row else settings.llm_timeout_seconds),
        max_tokens=(row.max_tokens if row else settings.llm_max_tokens),
    )


class SummaryService:
    def __init__(self, config: LlmRuntimeConfig):
        self.config = config

    async def summarize(self, title: str, body: str, source_urls: list[str]) -> str | None:
        if self.config.provider == "disabled":
            return None

        system_prompt = (
            "You are a Korean security analyst. Always answer in Korean only. "
            "First translate the meaningful English source text into Korean, then summarize the translated content. "
            "Write a 1-5 line Korean summary focused on security impact and action. "
            "Use only the provided text and mention uncertainty when evidence is limited. "
            "Do not invent affected products or CVEs. "
            "Do not include chain-of-thought, hidden reasoning, or <think> blocks."
        )
        user_prompt = (
            "아래 영문 내용을 먼저 한국어로 번역한 뒤, 번역한 내용을 기반으로 핵심 보안 이슈를 1~5줄로 요약하세요.\n\n"
            f"Title: {title}\n\nBody:\n{body[:8000]}\n\nSources:\n" + "\n".join(source_urls)
        )
        if self.config.provider in {"ollama", "openai"}:
            return await self._chat_completions(system_prompt, user_prompt)
        if self.config.provider == "gemini":
            return await self._gemini(system_prompt, user_prompt)
        if self.config.provider == "anthropic":
            return await self._anthropic(system_prompt, user_prompt)
        return None

    async def _chat_completions(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            "temperature": 0.2,
            "max_tokens": self.config.max_tokens,
        }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.post(
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return THINK_BLOCK_RE.sub("", content).strip()

    async def _gemini(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": self.config.max_tokens},
        }
        url = f"{self.config.base_url.rstrip('/')}/models/{self.config.model}:generateContent"
        params = {"key": self.config.api_key} if self.config.api_key else None
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()
            parts = data["candidates"][0]["content"]["parts"]
            content = "\n".join(part.get("text", "") for part in parts)
            return THINK_BLOCK_RE.sub("", content).strip()

    async def _anthropic(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.config.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": 0.2,
            "max_tokens": self.config.max_tokens,
        }
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.config.api_key:
            headers["x-api-key"] = self.config.api_key
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.post(f"{self.config.base_url.rstrip('/')}/messages", json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            content = "\n".join(part.get("text", "") for part in data.get("content", []) if part.get("type") == "text")
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


def _limit_summary_lines(value: str, max_lines: int = 5) -> str:
    lines = [line.strip(" -\t") for line in value.splitlines() if line.strip()]
    if not lines:
        lines = [value.strip()]
    return "\n".join(lines[:max_lines]).strip()


def _fallback_article_summary(article: Article) -> str:
    excerpt = _compact(article.raw_excerpt, 700)
    if excerpt:
        return excerpt
    return article.title


def _fallback_vulnerability_summary(vulnerability: Vulnerability) -> str:
    if vulnerability.description:
        return _compact(vulnerability.description, 700)
    return vulnerability.title or vulnerability.cve_id


def _usable_summary(summary: str | None, required_terms: list[str] | None = None) -> str | None:
    if not summary:
        return None
    cleaned = summary.strip()
    if not _has_korean_text(cleaned):
        return None
    lowered = cleaned.lower()
    if required_terms and not any(term.lower() in lowered for term in required_terms):
        return None
    return _limit_summary_lines(cleaned)


def _recent_cutoff() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=SUMMARY_RECENT_DAYS)


async def summarize_recent_articles(db: Session, limit: int | None = 20) -> tuple[int, int]:
    cutoff = _recent_cutoff()
    query = (
        select(Article)
        .options(selectinload(Article.source))
        .where(or_(Article.published_at >= cutoff, Article.published_at.is_(None) & (Article.created_at >= cutoff)))
        .order_by(Article.summary.is_not(None), Article.published_at.desc().nullslast(), Article.created_at.desc())
    )
    if limit is not None:
        query = query.limit(limit)
    rows = db.scalars(query).all()
    changed = 0
    llm_config = resolve_llm_config(db)
    service = SummaryService(llm_config)
    for article in rows:
        body = article.raw_excerpt or article.title
        summary = None
        if llm_config.provider != "disabled":
            try:
                summary = await service.summarize(article.title, body, [article.url])
            except Exception:
                summary = None
        article.summary = _usable_summary(summary) or _fallback_article_summary(article)
        changed += 1
    db.commit()
    return len(rows), changed


async def summarize_recent_vulnerabilities(db: Session, limit: int | None = 20) -> tuple[int, int]:
    cutoff = _recent_cutoff()
    query = (
        select(Vulnerability)
        .where(Vulnerability.published_at >= cutoff)
        .order_by(
            Vulnerability.summary.is_not(None),
            Vulnerability.kev.desc(),
            Vulnerability.cvss_score.desc().nullslast(),
            Vulnerability.epss_score.desc().nullslast(),
        )
    )
    if limit is not None:
        query = query.limit(limit)
    rows = db.scalars(query).all()
    changed = 0
    llm_config = resolve_llm_config(db)
    service = SummaryService(llm_config)
    for vulnerability in rows:
        summary = None
        if llm_config.provider != "disabled":
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
