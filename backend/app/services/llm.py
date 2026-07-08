from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import json
import httpx
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.db.models import Article, LlmSetting, Vulnerability

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
HANGUL_RE = re.compile(r"[가-힣]")
SUMMARY_LABEL_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?\s*(?:\[?\s*)?(?:보안\s*)?(?:이슈\s*)?요약(?:\s*\]|\s*:|\s*：|\s*-)?(?:\*\*)?\s*",
    re.IGNORECASE,
)
JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
SUMMARY_SCHEMA_EXAMPLE = {
    "content": {
        "source_type": "news",
        "title": "source title",
        "risk": "low | medium | high | critical | unknown",
        "summary": "한국어 1~5줄 보안 요약",
        "body": "원문 일부 또는 핵심 본문",
        "source_url": "https://example.com/source",
        "published_at": None,
    },
    "entities": {
        "attacker": [],
        "victim": [],
        "software": [],
        "version": [],
        "vulnerability": [],
        "cve": [],
    },
    "iocs": {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": [],
        "file": [],
        "process": [],
        "commandline": [],
    },
}
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
    "gemini": "gemini-3.1-flash-lite",
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

    async def summarize(self, title: str, body: str, source_urls: list[str], source_type: str = "news") -> str | None:
        if self.config.provider == "disabled":
            return None

        system_prompt = (
            "You are a Korean security analyst. Analyze only the provided source text. "
            "Return valid JSON only, with no markdown, no code fences, and no explanatory prose. "
            "The content.summary value must be Korean, 1-5 lines, and focused on security impact and recommended action. "
            "Do not add labels such as '요약:' or '[보안 요약]' inside any value. "
            "Do not invent affected products, CVEs, entities, or IOCs. Use empty arrays when evidence is absent. "
            "IOC fields must include only values explicitly present in the source text. "
            "Do not include chain-of-thought, hidden reasoning, or <think> blocks."
        )
        schema = json.dumps(SUMMARY_SCHEMA_EXAMPLE, ensure_ascii=False, indent=2)
        user_prompt = (
            "아래 보안 뉴스/CVE 원문을 분석해서 지정된 JSON 스키마만 출력하세요.\n"
            "응답은 반드시 valid JSON이어야 하며 markdown, 설명, 코드블록을 포함하지 마세요.\n"
            "원문에 없는 정보는 추측하지 말고 빈 배열 또는 null로 두세요.\n"
            "content.summary는 반드시 한국어 1~5줄로 작성하세요.\n"
            "IOC는 원문에 명시된 값만 포함하세요.\n\n"
            f"지정 JSON 스키마:\n{schema}\n\n"
            f"source_type: {source_type}\n"
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


def _canonicalize_summary(value: str) -> str:
    lines = []
    for line in THINK_BLOCK_RE.sub("", value).replace("**", "").splitlines():
        cleaned = SUMMARY_LABEL_RE.sub("", line).strip()
        if cleaned:
            lines.append(cleaned)
    return "\n".join(lines).strip()


def _extract_json_summary(value: str) -> str | None:
    text = THINK_BLOCK_RE.sub("", value).strip()
    match = JSON_BLOCK_RE.search(text)
    if match:
        text = match.group(1).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    content = payload.get("content") if isinstance(payload, dict) else None
    summary = content.get("summary") if isinstance(content, dict) else None
    if isinstance(summary, str):
        return summary
    if isinstance(summary, list):
        return "\n".join(str(item) for item in summary if item)
    return None


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
    extracted = _extract_json_summary(summary)
    stripped = THINK_BLOCK_RE.sub("", summary).strip()
    if extracted is None and stripped.startswith(("{", "[")):
        return None
    cleaned = _canonicalize_summary(extracted or summary)
    if not _has_korean_text(cleaned):
        return None
    lowered = cleaned.lower()
    if required_terms and not any(term.lower() in lowered for term in required_terms):
        return None
    return _limit_summary_lines(cleaned)


def _recent_cutoff(days: int = SUMMARY_RECENT_DAYS) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


async def _summarize_article_rows(db: Session, rows: list[Article]) -> tuple[int, int]:
    changed = 0
    llm_config = resolve_llm_config(db)
    service = SummaryService(llm_config)
    for article in rows:
        body = article.raw_excerpt or article.title
        summary = None
        if llm_config.provider != "disabled":
            try:
                summary = await service.summarize(article.title, body, [article.url], source_type="news")
            except Exception:
                summary = None
        usable_summary = _usable_summary(summary)
        article.summary = usable_summary or _fallback_article_summary(article)
        article.summary_status = "llm" if usable_summary else "fallback"
        changed += 1
    db.commit()
    return len(rows), changed


async def _summarize_vulnerability_rows(db: Session, rows: list[Vulnerability]) -> tuple[int, int]:
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
                    source_type="cve",
                )
            except Exception:
                summary = None
        required_terms = [vulnerability.cve_id]
        if vulnerability.product:
            required_terms.append(vulnerability.product)
        usable_summary = _usable_summary(summary, required_terms=required_terms)
        vulnerability.summary = usable_summary or _fallback_vulnerability_summary(vulnerability)
        vulnerability.summary_status = "llm" if usable_summary else "fallback"
        changed += 1
    db.commit()
    return len(rows), changed


async def summarize_recent_articles(db: Session, limit: int | None = 20, days: int = SUMMARY_RECENT_DAYS, include_existing: bool = False) -> tuple[int, int]:
    cutoff = _recent_cutoff(days)
    query = (
        select(Article)
        .options(selectinload(Article.source))
        .where(or_(Article.published_at >= cutoff, Article.published_at.is_(None) & (Article.created_at >= cutoff)))
        .order_by(Article.summary.is_not(None), Article.published_at.desc().nullslast(), Article.created_at.desc())
    )
    if not include_existing:
        query = query.where(or_(Article.summary_status.is_(None), Article.summary_status != "llm"))
    if limit is not None:
        query = query.limit(limit)
    rows = db.scalars(query).all()
    return await _summarize_article_rows(db, rows)


async def summarize_articles_by_ids(db: Session, ids: list[int]) -> tuple[int, int]:
    if not ids:
        return 0, 0
    rows = db.scalars(select(Article).options(selectinload(Article.source)).where(Article.id.in_(ids))).all()
    return await _summarize_article_rows(db, rows)


async def summarize_recent_vulnerabilities(db: Session, limit: int | None = 20, days: int = SUMMARY_RECENT_DAYS, include_existing: bool = False) -> tuple[int, int]:
    cutoff = _recent_cutoff(days)
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
    if not include_existing:
        query = query.where(or_(Vulnerability.summary_status.is_(None), Vulnerability.summary_status != "llm"))
    if limit is not None:
        query = query.limit(limit)
    rows = db.scalars(query).all()
    return await _summarize_vulnerability_rows(db, rows)


async def summarize_vulnerabilities_by_ids(db: Session, ids: list[int]) -> tuple[int, int]:
    if not ids:
        return 0, 0
    rows = db.scalars(select(Vulnerability).where(Vulnerability.id.in_(ids))).all()
    return await _summarize_vulnerability_rows(db, rows)


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
