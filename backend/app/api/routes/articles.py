from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Article
from app.db.session import get_db
from app.schemas import ArticleOut

router = APIRouter(prefix="/articles", tags=["articles"])


def apply_article_filters(query, q: str | None = None):
    if q:
        like = f"%{q}%"
        query = query.where(Article.title.ilike(like) | Article.summary.ilike(like) | Article.raw_excerpt.ilike(like))
    return query


@router.get("/count", response_model=int)
def count_articles(
    q: str | None = None,
    db: Session = Depends(get_db),
) -> int:
    query = apply_article_filters(select(func.count(Article.id)), q=q)
    return db.scalar(query) or 0


@router.get("", response_model=list[ArticleOut])
def list_articles(
    q: str | None = None,
    sort: str = Query(default="date", pattern="^(date|name)$"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ArticleOut]:
    query = apply_article_filters(select(Article).options(selectinload(Article.source)), q=q)
    if sort == "name":
        order_by = (Article.title.asc(), Article.published_at.desc().nullslast())
    else:
        order_by = (Article.published_at.desc().nullslast(), Article.created_at.desc())
    rows = db.scalars(query.order_by(*order_by).offset(offset).limit(limit)).all()
    return [ArticleOut.model_validate(row) for row in rows]
