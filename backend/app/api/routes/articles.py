from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Article
from app.db.session import get_db
from app.schemas import ArticleOut

router = APIRouter(prefix="/articles", tags=["articles"])


@router.get("", response_model=list[ArticleOut])
def list_articles(
    q: str | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ArticleOut]:
    query = select(Article).options(selectinload(Article.source))
    if q:
        query = query.where(Article.title.ilike(f"%{q}%") | Article.raw_excerpt.ilike(f"%{q}%"))
    rows = db.scalars(query.order_by(Article.published_at.desc().nullslast(), Article.created_at.desc()).offset(offset).limit(limit)).all()
    return [ArticleOut.model_validate(row) for row in rows]
