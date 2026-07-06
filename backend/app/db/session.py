from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def create_db() -> None:
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_schema()


def _ensure_schema() -> None:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    if "vulnerabilities" not in table_names:
        return

    vulnerability_columns = {column["name"] for column in inspector.get_columns("vulnerabilities")}
    article_columns = {column["name"] for column in inspector.get_columns("articles")} if "articles" in table_names else set()
    endpoint_columns = {column["name"] for column in inspector.get_columns("endpoint_snapshots")} if "endpoint_snapshots" in table_names else set()
    with engine.begin() as connection:
        if "summary" not in vulnerability_columns:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN summary TEXT"))
        if "summary_status" not in vulnerability_columns:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN summary_status VARCHAR(32)"))
        if "summary_status" not in article_columns:
            connection.execute(text("ALTER TABLE articles ADD COLUMN summary_status VARCHAR(32)"))
        if "mac_address" not in endpoint_columns:
            connection.execute(text("ALTER TABLE endpoint_snapshots ADD COLUMN mac_address VARCHAR(64)"))
        if "platform" not in endpoint_columns:
            connection.execute(text("ALTER TABLE endpoint_snapshots ADD COLUMN platform VARCHAR(255)"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
