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
    "def",
    "con",
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
AUTO_EXCLUDE_MAX_PER_RUN = 12
HOT_TOPIC_LLM_CANDIDATE_LIMIT = 16
HOT_TOPIC_LLM_TOPIC_LIMIT = 6
AUTO_EXCLUDE_ALLOWED_KEYS = {
    "access",
    "agent",
    "attackers",
    "campaign",
    "cybersecurity",
    "exposed",
    "hackers",
    "malware",
    "malicious",
    "more",
    "released",
    "researchers",
    "said",
    "says",
    "score",
    "server",
    "software",
    "targeting",
    "than",
    "threat",
    "tracked",
    "used",
    "개최",
    "강화",
    "글로벌",
    "기술",
    "기업",
    "데이터",
    "대응",
    "미리보기",
    "사이버",
    "사이버보안",
    "솔루션",
    "시대",
    "위한",
    "위협",
    "유출",
    "인증",
    "즉시",
    "콘퍼런스",
    "해킹",
}
AUTO_EXCLUDE_PROTECTED_KEYS = {
    "7-zip",
    "ai",
    "android",
    "apache",
    "api",
    "chrome",
    "claude",
    "def",
    "defcon",
    "github",
    "ios",
    "isec",
    "linux",
    "microsoft",
    "nginx",
    "openai",
    "oracle",
    "sharepoint",
    "ssl",
    "tls",
    "vpn",
    "windows",
    "zoom",
    "데프콘",
}


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
        row = HotTopicSetting(excluded_keywords=[], llm_enabled=True, auto_exclude_enabled=True)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def hot_topic_setting_out(row: HotTopicSetting) -> dict[str, Any]:
    return {
        "excluded_keywords": normalize_excluded_keywords(row.excluded_keywords if isinstance(row.excluded_keywords, list) else []),
        "llm_enabled": bool(row.llm_enabled),
        "auto_exclude_enabled": bool(row.auto_exclude_enabled),
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


def _fallback_topic_description(topic: dict[str, Any]) -> str | None:
    title = str(topic.get("top_article_title") or "").strip()
    if not title:
        return None
    return f"관련 주요 기사: {title}"


def _ensure_topic_descriptions(topics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for topic in topics:
        item = dict(topic)
        if not str(item.get("description") or "").strip():
            item["description"] = _fallback_topic_description(item)
        output.append(item)
    return output


def _extract_json(value: str) -> dict[str, Any]:
    text = value.strip()
    match = JSON_BLOCK_RE.search(text)
    if match:
        text = match.group(1).strip()
    return json.loads(text)


def _validated_llm_excludes(candidates: list[dict[str, Any]], values: list[Any]) -> list[str]:
    allowed = {str(item["key"]) for item in candidates}
    allowed.update(normalize_keyword(str(alias)) for item in candidates for alias in item.get("aliases", []))
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = normalize_keyword(str(value))
        if not key or key in seen or key not in allowed or key in SHORT_ALLOWED_TOPICS:
            continue
        if key in AUTO_EXCLUDE_PROTECTED_KEYS:
            continue
        if key not in AUTO_EXCLUDE_ALLOWED_KEYS:
            continue
        if len(key) < 2 or key.isdigit() or len(key) > 40:
            continue
        seen.add(key)
        result.append(key)
        if len(result) >= AUTO_EXCLUDE_MAX_PER_RUN:
            break
    return result


def _merge_topic_rows(candidates: list[dict[str, Any]], llm_topics: list[dict[str, Any]], limit: int, excluded_keys: set[str] | None = None) -> list[dict[str, Any]]:
    excluded_keys = excluded_keys or set()
    by_key = {str(item["key"]): item for item in candidates}
    used: set[str] = set()
    merged: list[dict[str, Any]] = []
    for llm_topic in llm_topics:
        aliases = [normalize_keyword(str(value)) for value in llm_topic.get("aliases", []) if str(value).strip()]
        keyword_key = normalize_keyword(str(llm_topic.get("keyword", "")))
        keys = [key for key in [keyword_key, *aliases] if key in by_key and key not in used and key not in excluded_keys]
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
        if row["key"] not in used and row["key"] not in excluded_keys:
            merged.append({key: value for key, value in row.items() if key != "key"})
    return merged


async def _llm_merge_topics(db: Session, candidates: list[dict[str, Any]], days: int, limit: int) -> tuple[list[dict[str, Any]], str, list[str]]:
    config = resolve_llm_config(db)
    if config.provider == "disabled":
        raise RuntimeError("LLM provider disabled")
    payload = [
        {
            "keyword": item["keyword"],
            "count": item["count"],
            "article_count": item["article_count"],
            "top_article_title": str(item["top_article_title"] or "")[:80],
        }
        for item in candidates[:HOT_TOPIC_LLM_CANDIDATE_LIMIT]
    ]
    system_prompt = (
        "You are a Korean security operations analyst. Return valid JSON only. "
        "Merge only equivalent Korean/English aliases, product aliases, or acronym variants. "
        "Do not group unrelated keywords into broad categories. Do not create new category labels. "
        "Representative keyword must be one of the provided candidate keyword values. "
        "Evaluate which candidate keywords are too generic for a HOT Topic and return them in excluded_keywords. "
        "Do not exclude specific products, vendors, malware family names, actor names, protocols, or concrete technologies. "
        "Keep all Korean text very short to avoid truncation. "
        f"Respect max_tokens={config.max_tokens}; keep output compact."
    )
    user_prompt = (
        f"최근 {days}일 HOT Topic 후보입니다. JSON만 출력하세요.\n"
        f"topics는 최대 {min(limit, HOT_TOPIC_LLM_TOPIC_LIMIT)}개만 작성하세요. description_ko는 35자 이내 한국어 한 문장입니다.\n"
        "excluded_keywords는 일반 단어만 최대 8개입니다. 제품/벤더/기술명은 제외하지 마세요.\n"
        "스키마: {\"brief_ko\":\"60자 이내\", \"excluded_keywords\":[\"후보 keyword\"], \"topics\":[{\"keyword\":\"후보 keyword\", \"aliases\":[\"후보 keyword\"], \"description_ko\":\"35자 이내\"}]}\n"
        "keyword와 aliases는 반드시 후보 keyword 중에서만 고르세요.\n"
        + json.dumps(payload, ensure_ascii=False)
    )
    content = await SummaryService(config).complete(system_prompt, user_prompt)
    if not content:
        raise RuntimeError("LLM returned empty response")
    data = _extract_json(content)
    excluded_keywords = _validated_llm_excludes(candidates, data.get("excluded_keywords", []))
    topics = _merge_topic_rows(candidates, data.get("topics", []), limit, excluded_keys=set(excluded_keywords))
    brief = str(data.get("brief_ko") or _fallback_brief(topics, days) or "").strip()
    return topics, brief, excluded_keywords


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
            topics, brief, auto_excludes = await _llm_merge_topics(db, candidates, days, limit)
            if setting.auto_exclude_enabled and auto_excludes:
                merged_excludes = normalize_excluded_keywords([*(excluded or []), *auto_excludes])
                setting.excluded_keywords = merged_excludes
                topics = [item for item in topics if normalize_keyword(str(item.get("keyword", ""))) not in set(auto_excludes)]
                candidates = [item for item in candidates if item["key"] not in set(auto_excludes)]
                brief = _fallback_brief(topics, days) if not topics else brief
            source = "llm"
        except Exception as exc:
            config = resolve_llm_config(db)
            error = llm_error_detail(config, exc)
    snapshot = HotTopicSnapshot(
        period_days=days,
        source=source,
        topics=_ensure_topic_descriptions(topics),
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
    if snapshot is not None and (setting.updated_at is None or snapshot.created_at + timedelta(seconds=5) >= setting.updated_at):
        topics = snapshot.topics if isinstance(snapshot.topics, list) else []
        return _ensure_topic_descriptions(topics[:limit]), snapshot.brief, snapshot.source, snapshot.created_at
    excluded = normalize_excluded_keywords(setting.excluded_keywords if isinstance(setting.excluded_keywords, list) else [])
    topics = [{key: value for key, value in item.items() if key != "key"} for item in build_candidate_topics(db, days=days, limit=limit, excluded_keywords=excluded)]
    return _ensure_topic_descriptions(topics), _fallback_brief(topics, days), "rules", None
