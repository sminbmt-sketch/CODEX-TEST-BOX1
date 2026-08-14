from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Article, HotTopicSetting, HotTopicSnapshot
from app.services.llm import JSON_BLOCK_RE, SummaryService, llm_error_detail, resolve_llm_config


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
    "cvss",
    "data",
    "exploit",
    "exploited",
    "exploitable",
    "exploits",
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


def normalize_keyword(value: str) -> str:
    text = value.strip().strip("._-").lower()
    if text.startswith("cve-"):
        return "cve"
    return text


def display_keyword(value: str) -> str:
    return value.upper() if value.isascii() and len(value) <= 4 else value


def normalize_excluded_keywords(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values or []:
        for part in re.split(r"[\n,]", value):
            key = normalize_keyword(part)
            if not key or key in seen:
                continue
            seen.add(key)
            normalized.append(key)
    return normalized


def get_hot_topic_setting(db: Session) -> HotTopicSetting:
    row = db.scalar(select(HotTopicSetting).order_by(HotTopicSetting.id.asc()).limit(1))
    if row is None:
        row = HotTopicSetting(excluded_keywords=[], llm_enabled=True)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def hot_topic_setting_out(row: HotTopicSetting) -> dict[str, Any]:
    return {
        "excluded_keywords": normalize_excluded_keywords(row.excluded_keywords if isinstance(row.excluded_keywords, list) else []),
        "llm_enabled": bool(row.llm_enabled),
        "updated_at": row.updated_at,
    }


def build_candidate_topics(db: Session, days: int = 30, limit: int = 30, excluded_keywords: list[str] | None = None) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    excluded = set(TOPIC_STOPWORDS) | set(normalize_excluded_keywords(excluded_keywords))
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
            key = normalize_keyword(raw)
            if raw.isascii() and len(key) <= 2 and key not in SHORT_ALLOWED_TOPICS:
                continue
            if key in excluded or key.isdigit() or len(key) > 40:
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
    topics: list[dict[str, Any]] = []
    for key in ranked:
        display = display_values[key].most_common(1)[0][0] if display_values[key] else key
        article = top_article.get(key)
        topics.append(
            {
                "keyword": display_keyword(display),
                "key": key,
                "aliases": [display_keyword(display)],
                "count": counts[key],
                "article_count": len(article_ids[key]),
                "total_views": views[key],
                "top_article_title": article.title if article else None,
                "top_article_url": article.url if article else None,
                "description": None,
            }
        )
    return topics


def _fallback_brief(topics: list[dict[str, Any]], days: int) -> str | None:
    if not topics:
        return None
    return f"최근 {days}일 반복 노출 키워드: " + ", ".join(str(item["keyword"]) for item in topics[:5])


def _extract_json(value: str) -> dict[str, Any]:
    text = value.strip()
    match = JSON_BLOCK_RE.search(text)
    if match:
        text = match.group(1).strip()
    return json.loads(text)


def _merge_topic_rows(candidates: list[dict[str, Any]], llm_topics: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    by_key = {str(item["key"]): item for item in candidates}
    used: set[str] = set()
    merged: list[dict[str, Any]] = []
    for llm_topic in llm_topics:
        aliases = [normalize_keyword(str(value)) for value in llm_topic.get("aliases", []) if str(value).strip()]
        keyword_key = normalize_keyword(str(llm_topic.get("keyword", "")))
        keys = [key for key in [keyword_key, *aliases] if key in by_key and key not in used]
        if not keys:
            continue
        rows = [by_key[key] for key in keys]
        used.update(keys)
        top = max(rows, key=lambda row: int(row.get("total_views") or 0))
        candidate_keywords = {normalize_keyword(str(alias)) for row in rows for alias in row.get("aliases", [])}
        candidate_keywords.update(str(row["key"]) for row in rows)
        llm_keyword = str(llm_topic.get("keyword") or "").strip()
        llm_keyword_key = normalize_keyword(llm_keyword)
        has_blocked_token = any(normalize_keyword(match.group(0)) in TOPIC_STOPWORDS for match in TOPIC_TOKEN_RE.finditer(llm_keyword))
        keyword = llm_keyword if llm_keyword_key in candidate_keywords and not has_blocked_token else str(top["keyword"])
        merged.append(
            {
                "keyword": display_keyword(keyword),
                "aliases": sorted({str(alias) for row in rows for alias in row.get("aliases", [])}),
                "count": sum(int(row.get("count") or 0) for row in rows),
                "article_count": sum(int(row.get("article_count") or 0) for row in rows),
                "total_views": sum(int(row.get("total_views") or 0) for row in rows),
                "top_article_title": top.get("top_article_title"),
                "top_article_url": top.get("top_article_url"),
                "description": str(llm_topic.get("description_ko") or llm_topic.get("description") or "").strip() or None,
            }
        )
        if len(merged) >= limit:
            break
    for row in candidates:
        if len(merged) >= limit:
            break
        if row["key"] not in used:
            merged.append({key: value for key, value in row.items() if key != "key"})
    return merged


async def _llm_merge_topics(db: Session, candidates: list[dict[str, Any]], days: int, limit: int) -> tuple[list[dict[str, Any]], str]:
    config = resolve_llm_config(db)
    if config.provider == "disabled":
        raise RuntimeError("LLM provider disabled")
    payload = [
        {
            "keyword": item["keyword"],
            "count": item["count"],
            "article_count": item["article_count"],
            "total_views": item["total_views"],
            "top_article_title": item["top_article_title"],
        }
        for item in candidates[:30]
    ]
    system_prompt = (
        "You are a Korean security operations analyst. Return valid JSON only. "
        "Merge only equivalent Korean/English aliases, product aliases, or acronym variants. "
        "Do not group unrelated keywords into broad categories. Do not create new category labels. "
        "Representative keyword must be one of the provided candidate keyword values. "
        "Remove generic words and explain the trend in Korean. "
        f"Respect max_tokens={config.max_tokens}; keep output compact."
    )
    user_prompt = (
        f"최근 {days}일 HOT Topic 후보입니다. 같은 의미의 키워드를 병합하고 운영 관점의 짧은 한국어 설명을 작성하세요.\n"
        "응답 스키마: {\"brief_ko\":\"한국어 1문장\", \"topics\":[{\"keyword\":\"대표 키워드\", \"aliases\":[\"후보 keyword 값\"], \"description_ko\":\"한국어 1문장\"}]}\n"
        "aliases에는 반드시 아래 후보 keyword 중 실제 병합에 사용한 값을 넣으세요. 없는 키워드는 만들지 마세요.\n\n"
        + json.dumps(payload, ensure_ascii=False)
    )
    content = await SummaryService(config).complete(system_prompt, user_prompt)
    if not content:
        raise RuntimeError("LLM returned empty response")
    data = _extract_json(content)
    topics = _merge_topic_rows(candidates, data.get("topics", []), limit)
    brief = str(data.get("brief_ko") or _fallback_brief(topics, days) or "").strip()
    return topics, brief


async def refresh_hot_topic_snapshot(db: Session, days: int = 30, limit: int = 10) -> HotTopicSnapshot:
    setting = get_hot_topic_setting(db)
    excluded = normalize_excluded_keywords(setting.excluded_keywords if isinstance(setting.excluded_keywords, list) else [])
    candidates = build_candidate_topics(db, days=days, limit=30, excluded_keywords=excluded)
    source = "rules"
    error = None
    topics = [{key: value for key, value in item.items() if key != "key"} for item in candidates[:limit]]
    brief = _fallback_brief(topics, days)
    if candidates and setting.llm_enabled:
        try:
            topics, brief = await _llm_merge_topics(db, candidates, days, limit)
            source = "llm"
        except Exception as exc:
            config = resolve_llm_config(db)
            error = llm_error_detail(config, exc)
    snapshot = HotTopicSnapshot(
        period_days=days,
        source=source,
        topics=topics,
        candidate_topics=[{key: value for key, value in item.items() if key != "key"} for item in candidates],
        brief=brief,
        error=error,
    )
    db.add(snapshot)
    db.add(setting)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def current_hot_topics(db: Session, days: int = 30, limit: int = 10) -> tuple[list[dict[str, Any]], str | None, str, datetime | None]:
    setting = get_hot_topic_setting(db)
    snapshot = db.scalar(select(HotTopicSnapshot).where(HotTopicSnapshot.period_days == days).order_by(HotTopicSnapshot.created_at.desc()).limit(1))
    if snapshot is not None and (setting.updated_at is None or snapshot.created_at >= setting.updated_at):
        topics = snapshot.topics if isinstance(snapshot.topics, list) else []
        return topics[:limit], snapshot.brief, snapshot.source, snapshot.created_at
    excluded = normalize_excluded_keywords(setting.excluded_keywords if isinstance(setting.excluded_keywords, list) else [])
    topics = [{key: value for key, value in item.items() if key != "key"} for item in build_candidate_topics(db, days=days, limit=limit, excluded_keywords=excluded)]
    return topics, _fallback_brief(topics, days), "rules", None
