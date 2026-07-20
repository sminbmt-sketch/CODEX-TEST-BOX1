from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import InvestigationRun, NewsIntelligence
from app.db.session import get_db
from app.schemas import IntelligenceOut, InvestigationRequest, InvestigationRunOut
from app.services.investigation import TANIUM_CAPABILITIES, build_intelligence, run_inventory_investigation

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("/tanium-capabilities")
def tanium_capabilities() -> dict:
    return TANIUM_CAPABILITIES


@router.get("/intelligence", response_model=list[IntelligenceOut])
def list_intelligence(
    source_type: str | None = Query(default=None, pattern="^(news|cve)$"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[IntelligenceOut]:
    query = select(NewsIntelligence).order_by(NewsIntelligence.updated_at.desc().nullslast(), NewsIntelligence.created_at.desc())
    if source_type:
        query = query.where(NewsIntelligence.source_type == source_type)
    rows = db.scalars(query.limit(limit)).all()
    return [IntelligenceOut.model_validate(row) for row in rows]


@router.post("/intelligence", response_model=IntelligenceOut)
async def create_intelligence(payload: InvestigationRequest, db: Session = Depends(get_db)) -> IntelligenceOut:
    try:
        row = await build_intelligence(db, payload.source_type, payload.item_id, refresh=payload.refresh_intelligence)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Intelligence extraction failed: {exc}") from exc
    return IntelligenceOut.model_validate(row)


@router.post("/run", response_model=InvestigationRunOut)
async def run_investigation(payload: InvestigationRequest, db: Session = Depends(get_db)) -> InvestigationRunOut:
    try:
        intelligence = await build_intelligence(db, payload.source_type, payload.item_id, refresh=payload.refresh_intelligence)
        run = await run_inventory_investigation(db, intelligence)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Investigation failed: {exc}") from exc
    return InvestigationRunOut.model_validate(run)


@router.get("/runs", response_model=list[InvestigationRunOut])
def list_runs(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)) -> list[InvestigationRunOut]:
    rows = db.scalars(select(InvestigationRun).order_by(InvestigationRun.created_at.desc()).limit(limit)).all()
    return [InvestigationRunOut.model_validate(row) for row in rows]
