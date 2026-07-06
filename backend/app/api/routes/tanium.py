from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Detection, EndpointSnapshot, Vulnerability
from app.db.session import get_db
from app.schemas import DetectionOut, EndpointSnapshotOut, ImpactAnalysisResult, TaniumStatus
from app.services.impact import analyze_basic_software_matches, analyze_recent_vulnerabilities
from app.services.tanium_client import TaniumConfigurationError, TaniumGatewayClient
from app.services.tanium_inventory import sync_endpoint_inventory

router = APIRouter(prefix="/tanium", tags=["tanium"])


@router.get("/status", response_model=TaniumStatus)
def status() -> TaniumStatus:
    client = TaniumGatewayClient()
    if client.configured:
        return TaniumStatus(configured=True, gateway_url=client.gateway_url, message="Tanium Gateway is configured.")
    return TaniumStatus(configured=False, gateway_url=client.gateway_url, message="Tanium URL or API token is missing.")


@router.post("/test")
async def test_connection() -> dict:
    client = TaniumGatewayClient()
    try:
        return await client.test_connection()
    except TaniumConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Tanium Gateway test failed: {exc}") from exc


@router.get("/endpoints")
async def endpoint_ids(first: int = Query(default=50, ge=1, le=500)) -> dict:
    client = TaniumGatewayClient()
    try:
        return await client.get_endpoint_ids(first=first)
    except TaniumConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Tanium endpoint query failed: {exc}") from exc


@router.get("/inventory", response_model=list[EndpointSnapshotOut])
def list_inventory(
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[EndpointSnapshotOut]:
    rows = db.scalars(
        select(EndpointSnapshot)
        .order_by(EndpointSnapshot.hostname.asc().nullslast(), EndpointSnapshot.last_seen_at.desc().nullslast())
        .limit(limit)
    ).all()
    return [EndpointSnapshotOut.model_validate(row) for row in rows]


@router.post("/sync-endpoints", response_model=ImpactAnalysisResult)
async def sync_endpoints(
    first: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> ImpactAnalysisResult:
    try:
        fetched, changed = await sync_endpoint_inventory(db, first=first)
    except TaniumConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Tanium endpoint inventory sync failed: {exc}") from exc
    return ImpactAnalysisResult(endpoints_fetched=fetched, endpoints_created_or_updated=changed)


@router.post("/analyze-impact", response_model=ImpactAnalysisResult)
async def analyze_impact(
    cve_id: str | None = None,
    vulnerability_limit: int = Query(default=50, ge=1, le=500),
    endpoint_limit: int = Query(default=100, ge=1, le=500),
    refresh_endpoints: bool = True,
    db: Session = Depends(get_db),
) -> ImpactAnalysisResult:
    fetched = 0
    changed = 0
    if refresh_endpoints:
        try:
            fetched, changed = await sync_endpoint_inventory(db, first=endpoint_limit)
        except TaniumConfigurationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Tanium endpoint inventory sync failed: {exc}") from exc

    if cve_id:
        vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper()))
        if vulnerability is None:
            raise HTTPException(status_code=404, detail="CVE not found")
        detections = analyze_basic_software_matches(db, vulnerability.id)
    else:
        detections = analyze_recent_vulnerabilities(db, limit=vulnerability_limit)

    return ImpactAnalysisResult(
        endpoints_fetched=fetched,
        endpoints_created_or_updated=changed,
        detections_created=detections,
    )


@router.get("/detections", response_model=list[DetectionOut])
def list_detections(
    limit: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[DetectionOut]:
    rows = db.scalars(
        select(Detection)
        .options(selectinload(Detection.vulnerability), selectinload(Detection.endpoint))
        .order_by(Detection.created_at.desc())
        .limit(limit)
    ).all()
    return [DetectionOut.model_validate(row) for row in rows]
