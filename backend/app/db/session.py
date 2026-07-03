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
    if "vulnerabilities" not in inspector.get_table_names():
        return

    vulnerability_columns = {column["name"] for column in inspector.get_columns("vulnerabilities")}
    with engine.begin() as connection:
        if "summary" not in vulnerability_columns:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN summary TEXT"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
