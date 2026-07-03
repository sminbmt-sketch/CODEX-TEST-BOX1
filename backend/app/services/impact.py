from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import Detection, EndpointSnapshot, Vulnerability


OS_PRODUCTS = {"windows", "macos", "mac os", "linux", "ubuntu", "debian", "red hat", "rhel", "centos"}


def analyze_basic_software_matches(db: Session, vulnerability_id: int) -> int:
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        return 0
    if not vulnerability.product and not vulnerability.vendor:
        return 0

    db.execute(delete(Detection).where(Detection.vulnerability_id == vulnerability.id))
    db.flush()

    endpoints = db.scalars(select(EndpointSnapshot)).all()
    created = 0
    product = vulnerability.product.lower() if vulnerability.product else None
    vendor = vulnerability.vendor.lower() if vulnerability.vendor else None

    for endpoint in endpoints:
        software = endpoint.software or []
        text = str(software).lower()
        os_text = " ".join(value for value in (endpoint.os_name, endpoint.os_version) if value).lower()
        product_is_os = bool(product and product in OS_PRODUCTS)
        if product_is_os and product not in os_text:
            continue
        if product_is_os:
            match_reason = "Matched product text against endpoint OS inventory."
            confidence = 0.7
        else:
            match_reason = "Matched product text against endpoint software inventory." if product else "Matched vendor text against endpoint software inventory."
            confidence = 0.65 if product else 0.45
        if product and product not in text:
            if not product_is_os:
                continue
        if product and vendor and vendor not in text:
            if not product_is_os:
                continue
        if not product and vendor and vendor not in text:
            continue
        detection = Detection(
            vulnerability_id=vulnerability.id,
            endpoint_snapshot_id=endpoint.id,
            match_reason=match_reason,
            confidence=confidence,
            status="open",
        )
        db.add(detection)
        created += 1
    db.commit()
    return created


def analyze_recent_vulnerabilities(db: Session, limit: int = 50) -> int:
    vulnerabilities = db.scalars(
        select(Vulnerability)
        .order_by(Vulnerability.kev.desc(), Vulnerability.cvss_score.desc().nullslast(), Vulnerability.published_at.desc().nullslast())
        .limit(limit)
    ).all()
    return sum(analyze_basic_software_matches(db, vulnerability.id) for vulnerability in vulnerabilities)
