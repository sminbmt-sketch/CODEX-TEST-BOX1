from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Vulnerability
from app.db.session import get_db
from app.schemas import VulnerabilityOut

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


def apply_vulnerability_filters(query, q: str | None = None, kev: bool | None = None, severity: str | None = None):
    if q:
        like = f"%{q}%"
        query = query.where(
            Vulnerability.cve_id.ilike(like)
            | Vulnerability.title.ilike(like)
            | Vulnerability.description.ilike(like)
            | Vulnerability.vendor.ilike(like)
            | Vulnerability.product.ilike(like)
        )
    if kev is not None:
        query = query.where(Vulnerability.kev.is_(kev))
    if severity:
        query = query.where(Vulnerability.cvss_severity == severity.upper())
    return query


@router.get("/count", response_model=int)
def count_vulnerabilities(
    q: str | None = None,
    kev: bool | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
) -> int:
    query = apply_vulnerability_filters(select(func.count(Vulnerability.id)), q=q, kev=kev, severity=severity)
    return db.scalar(query) or 0


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    q: str | None = None,
    kev: bool | None = None,
    severity: str | None = None,
    sort: str = Query(default="date", pattern="^(date|name)$"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[VulnerabilityOut]:
    query = apply_vulnerability_filters(select(Vulnerability), q=q, kev=kev, severity=severity)
    if sort == "name":
        order_by = (Vulnerability.cve_id.asc(), Vulnerability.published_at.desc().nullslast())
    else:
        order_by = (Vulnerability.published_at.desc().nullslast(), Vulnerability.kev.desc(), Vulnerability.cvss_score.desc().nullslast())

    rows = db.scalars(query.order_by(*order_by).offset(offset).limit(limit)).all()
    return [VulnerabilityOut.model_validate(row) for row in rows]


@router.get("/{cve_id}", response_model=VulnerabilityOut)
def get_vulnerability(cve_id: str, db: Session = Depends(get_db)) -> VulnerabilityOut:
    vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper()))
    if vulnerability is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="CVE not found")
    return VulnerabilityOut.model_validate(vulnerability)
