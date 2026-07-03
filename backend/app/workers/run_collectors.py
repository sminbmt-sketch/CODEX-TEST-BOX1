import asyncio

from app.db.session import SessionLocal, create_db
from app.services.news_sources import collect_rss_feeds
from app.services.vulnerability_sources import collect_cisa_kev, collect_recent_nvd


async def main() -> None:
    create_db()
    db = SessionLocal()
    try:
        await collect_cisa_kev(db)
        await collect_recent_nvd(db, days=14, limit=200)
        await collect_rss_feeds(db)
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
