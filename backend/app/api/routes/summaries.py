from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas import SummaryRunResult, SummarySelectionRequest, TrendReport
from app.services.llm import build_trend_report, summarize_articles_by_ids, summarize_recent_articles, summarize_recent_vulnerabilities, summarize_vulnerabilities_by_ids

router = APIRouter(prefix="/summaries", tags=["summaries"])


@router.post("/articles", response_model=SummaryRunResult)
async def summarize_articles(
    limit: int = Query(default=20, ge=1, le=100),
    days: int = Query(default=7, ge=1, le=365),
    include_existing: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> SummaryRunResult:
    try:
        fetched, summarized = await summarize_recent_articles(db, limit=limit, days=days, include_existing=include_existing)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Article summarization failed: {exc}") from exc
    return SummaryRunResult(target="articles", fetched=fetched, summarized=summarized)


@router.post("/vulnerabilities", response_model=SummaryRunResult)
async def summarize_vulnerabilities(
    limit: int = Query(default=20, ge=1, le=100),
    days: int = Query(default=7, ge=1, le=365),
    include_existing: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> SummaryRunResult:
    try:
        fetched, summarized = await summarize_recent_vulnerabilities(db, limit=limit, days=days, include_existing=include_existing)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Vulnerability summarization failed: {exc}") from exc
    return SummaryRunResult(target="vulnerabilities", fetched=fetched, summarized=summarized)


@router.post("/articles/selected", response_model=SummaryRunResult)
async def summarize_selected_articles(
    payload: SummarySelectionRequest,
    db: Session = Depends(get_db),
) -> SummaryRunResult:
    try:
        fetched, summarized = await summarize_articles_by_ids(db, payload.ids)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Selected article summarization failed: {exc}") from exc
    return SummaryRunResult(target="articles", fetched=fetched, summarized=summarized)


@router.post("/vulnerabilities/selected", response_model=SummaryRunResult)
async def summarize_selected_vulnerabilities(
    payload: SummarySelectionRequest,
    db: Session = Depends(get_db),
) -> SummaryRunResult:
    try:
        fetched, summarized = await summarize_vulnerabilities_by_ids(db, payload.ids)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Selected vulnerability summarization failed: {exc}") from exc
    return SummaryRunResult(target="vulnerabilities", fetched=fetched, summarized=summarized)


@router.post("/all", response_model=list[SummaryRunResult])
async def summarize_all(
    limit: int | None = Query(default=None, ge=1, le=5000),
    days: int = Query(default=7, ge=1, le=365),
    include_existing: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> list[SummaryRunResult]:
    try:
        article_fetched, article_summarized = await summarize_recent_articles(db, limit=limit, days=days, include_existing=include_existing)
        vulnerability_fetched, vulnerability_summarized = await summarize_recent_vulnerabilities(db, limit=limit, days=days, include_existing=include_existing)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Summarization failed: {exc}") from exc
    return [
        SummaryRunResult(target="articles", fetched=article_fetched, summarized=article_summarized),
        SummaryRunResult(target="vulnerabilities", fetched=vulnerability_fetched, summarized=vulnerability_summarized),
    ]


@router.get("/trends", response_model=TrendReport)
def trend_report(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
) -> TrendReport:
    return TrendReport.model_validate(build_trend_report(db, limit=limit))
