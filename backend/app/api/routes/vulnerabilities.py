from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability
from app.db.session import get_db
from app.schemas import VulnerabilityOut

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    q: str | None = None,
    kev: bool | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[VulnerabilityOut]:
    query = select(Vulnerability)
    if q:
        query = query.where(
            Vulnerability.cve_id.ilike(f"%{q}%")
            | Vulnerability.description.ilike(f"%{q}%")
            | Vulnerability.vendor.ilike(f"%{q}%")
            | Vulnerability.product.ilike(f"%{q}%")
        )
    if kev is not None:
        query = query.where(Vulnerability.kev.is_(kev))
    if severity:
        query = query.where(Vulnerability.cvss_severity == severity.upper())

    rows = db.scalars(
        query.order_by(Vulnerability.kev.desc(), Vulnerability.cvss_score.desc().nullslast(), Vulnerability.published_at.desc().nullslast()).limit(limit)
    ).all()
    return [VulnerabilityOut.model_validate(row) for row in rows]


@router.get("/{cve_id}", response_model=VulnerabilityOut)
def get_vulnerability(cve_id: str, db: Session = Depends(get_db)) -> VulnerabilityOut:
    vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper()))
    if vulnerability is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="CVE not found")
    return VulnerabilityOut.model_validate(vulnerability)
