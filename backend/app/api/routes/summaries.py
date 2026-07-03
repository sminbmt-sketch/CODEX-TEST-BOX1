from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas import SummaryRunResult, TrendReport
from app.services.llm import build_trend_report, summarize_recent_articles

router = APIRouter(prefix="/summaries", tags=["summaries"])


@router.post("/articles", response_model=SummaryRunResult)
async def summarize_articles(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> SummaryRunResult:
    try:
        fetched, summarized = await summarize_recent_articles(db, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Article summarization failed: {exc}") from exc
    return SummaryRunResult(target="articles", fetched=fetched, summarized=summarized)


@router.get("/trends", response_model=TrendReport)
def trend_report(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
) -> TrendReport:
    return TrendReport.model_validate(build_trend_report(db, limit=limit))
