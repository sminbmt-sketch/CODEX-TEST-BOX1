from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Detection, EndpointSnapshot, Vulnerability


def analyze_basic_software_matches(db: Session, vulnerability_id: int) -> int:
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        return 0
    if not vulnerability.product and not vulnerability.vendor:
        return 0

    endpoints = db.scalars(select(EndpointSnapshot)).all()
    created = 0
    needles = [value.lower() for value in (vulnerability.vendor, vulnerability.product) if value]

    for endpoint in endpoints:
        software = endpoint.software or []
        text = str(software).lower()
        if not any(needle in text for needle in needles):
            continue
        detection = Detection(
            vulnerability_id=vulnerability.id,
            endpoint_snapshot_id=endpoint.id,
            match_reason="Matched vendor/product text against endpoint software inventory.",
            confidence=0.6,
            status="open",
        )
        db.add(detection)
        created += 1
    db.commit()
    return created
