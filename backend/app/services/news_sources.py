from datetime import datetime
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Article, Source

DEFAULT_NEWS_FEEDS = [
    ("CISA News", "https://www.cisa.gov/news.xml"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
]


def _ensure_source(db: Session, name: str, url: str) -> Source:
    source = db.scalar(select(Source).where(Source.name == name))
    if source:
        return source
    source = Source(
        name=name,
        kind="news",
        url=url,
        license_note="Store metadata, source URL, and generated summaries only.",
        trust_score=0.7,
    )
    db.add(source)
    db.flush()
    return source


def _item_text(item: ElementTree.Element, tag: str) -> str | None:
    node = item.find(tag)
    return node.text.strip() if node is not None and node.text else None


def _parse_published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


async def collect_rss_feeds(db: Session, feeds: list[tuple[str, str]] | None = None) -> tuple[int, int]:
    feeds = feeds or DEFAULT_NEWS_FEEDS
    fetched = 0
    changed = 0

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for name, url in feeds:
            source = _ensure_source(db, name, url)
            response = await client.get(url)
            response.raise_for_status()
            root = ElementTree.fromstring(response.content)
            channel = root.find("channel")
            if channel is None:
                continue

            for item in channel.findall("item")[:50]:
                title = _item_text(item, "title")
                link = _item_text(item, "link")
                description = _item_text(item, "description")
                published = _parse_published(_item_text(item, "pubDate"))
                if not title or not link:
                    continue
                fetched += 1
                article = db.scalar(select(Article).where(Article.url == link))
                if article is None:
                    article = Article(url=link)
                    db.add(article)
                article.source_id = source.id
                article.title = title
                article.raw_excerpt = description[:1000] if description else None
                article.published_at = published
                article.tags = []
                changed += 1

    db.commit()
    return fetched, changed
