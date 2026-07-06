from datetime import datetime
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Article, Source

DEFAULT_NEWS_FEEDS = [
    ("CISA News", "https://www.cisa.gov/news.xml", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    ("Boannews Incident RSS", "http://www.boannews.com/media/news_rss.xml?kind=1", "incident"),
    ("KISA Security Info RSS", "https://knvd.krcert.or.kr/rss/securityInfo.do", "advisory"),
    ("KISA Vulnerability Notice RSS", "https://knvd.krcert.or.kr/rss/securityNotice.do", "vulnerability"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "news"),
]

DEFAULT_HTML_SOURCES = [
    ("Boannews Security News", "https://www.boannews.com/media/t_list.asp", "news"),
    ("KISA Security Notices", "https://krcert.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133", "advisory"),
    ("KISA Vulnerability Info", "https://knvd.krcert.or.kr/securityNotice.do", "vulnerability"),
]

HTML_DECLARATION_RE = re.compile(r"<\?[^>]*\?>|<!doctype[^>]*>", re.IGNORECASE)
XML_DECLARATION_RE = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)


class LinkListParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attrs_dict = {key.lower(): value for key, value in attrs}
        href = attrs_dict.get("href")
        if href:
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self._current_href:
            return
        title = " ".join(" ".join(self._current_text).split())
        href = self._current_href
        self._current_href = None
        self._current_text = []
        if not title or len(title) < 8:
            return
        if href.startswith(("javascript:", "#", "mailto:")):
            return
        self.links.append((unescape(title), urljoin(self.base_url, href)))


def _ensure_source(db: Session, name: str, kind: str, url: str) -> Source:
    source = db.scalar(select(Source).where(Source.name == name))
    if source:
        if source.kind != kind:
            source.kind = kind
        if source.url is None:
            source.url = url
        return source
    source = Source(
        name=name,
        kind=kind,
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


def _rss_text(response: httpx.Response) -> str:
    encoding = response.encoding or "utf-8"
    if "boannews.com" in str(response.url):
        encoding = "euc-kr"
    return XML_DECLARATION_RE.sub("", response.content.decode(encoding, errors="replace"))


def _parse_published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def _same_site(base_url: str, target_url: str) -> bool:
    base = urlparse(base_url)
    target = urlparse(target_url)
    return bool(target.scheme in {"http", "https"} and target.netloc and target.netloc == base.netloc)


def _configured_sources(db: Session, defaults: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    for name, url, kind in defaults:
        _ensure_source(db, name, kind, url)
    db.flush()
    names = [name for name, _, _ in defaults]
    rows = db.scalars(select(Source).where(Source.name.in_(names), Source.enabled.is_(True))).all()
    return [(row.name, row.url or "", row.kind) for row in rows if row.url]


async def collect_rss_feeds(db: Session, feeds: list[tuple[str, str, str]] | None = None) -> tuple[int, int]:
    feeds = feeds or _configured_sources(db, DEFAULT_NEWS_FEEDS)
    html_sources = _configured_sources(db, DEFAULT_HTML_SOURCES)
    fetched = 0
    changed = 0

    headers = {"User-Agent": "SecureWatch/0.1 (+security-trend-dashboard)"}
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
        for name, url, kind in feeds:
            source = _ensure_source(db, name, kind, url)
            try:
                response = await client.get(url)
                response.raise_for_status()
                root = ElementTree.fromstring(_rss_text(response))
            except Exception:
                continue
            channel = root.find("channel")
            if channel is None:
                continue

            for item in channel.findall("item")[:50]:
                title = _item_text(item, "title")
                link = _item_text(item, "link")
                description = _item_text(item, "description")
                published = _parse_published(
                    _item_text(item, "pubDate") or _item_text(item, "{http://purl.org/dc/elements/1.1/}date")
                )
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

        for name, url, kind in html_sources:
            source = _ensure_source(db, name, kind, url)
            try:
                response = await client.get(url)
                response.raise_for_status()
            except Exception:
                continue
            parser = LinkListParser(url)
            parser.feed(HTML_DECLARATION_RE.sub("", response.text))
            seen: set[str] = set()
            for title, link in parser.links:
                if link in seen or not _same_site(url, link):
                    continue
                seen.add(link)
                fetched += 1
                article = db.scalar(select(Article).where(Article.url == link))
                if article is None:
                    article = Article(url=link)
                    db.add(article)
                article.source_id = source.id
                article.title = title[:500]
                article.raw_excerpt = None
                article.tags = []
                changed += 1
                if len(seen) >= 50:
                    break

    db.commit()
    return fetched, changed
