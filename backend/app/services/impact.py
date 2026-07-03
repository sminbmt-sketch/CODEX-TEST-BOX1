import re

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import Detection, EndpointSnapshot, Vulnerability


OS_PRODUCTS = {"windows", "macos", "mac os", "linux", "ubuntu", "debian", "red hat", "rhel", "centos"}


def _norm(value: object) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).split())


def _tokens(value: object) -> list[str]:
    return [token for token in _norm(value).split() if len(token) > 1 and token not in {"the", "and", "for"}]


def _version_parts(value: object) -> list[int | str]:
    parts = []
    for token in re.findall(r"\d+|[a-z]+", str(value or "").lower()):
        parts.append(int(token) if token.isdigit() else token)
    return parts


def _compare_versions(left: object, right: object) -> int | None:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    if not left_parts or not right_parts:
        return None
    max_len = max(len(left_parts), len(right_parts))
    left_parts.extend([0] * (max_len - len(left_parts)))
    right_parts.extend([0] * (max_len - len(right_parts)))
    for left_item, right_item in zip(left_parts, right_parts, strict=True):
        if type(left_item) is not type(right_item):
            left_item = str(left_item)
            right_item = str(right_item)
        if left_item < right_item:
            return -1
        if left_item > right_item:
            return 1
    return 0


def _version_in_range(installed: object, affected: dict) -> bool | None:
    exact = affected.get("version")
    has_range = any(
        affected.get(key)
        for key in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        )
    )
    if exact and not has_range:
        compared = _compare_versions(installed, exact)
        return compared == 0 if compared is not None else _norm(installed) == _norm(exact)

    if not has_range:
        return None

    start_including = affected.get("version_start_including")
    if start_including:
        compared = _compare_versions(installed, start_including)
        if compared is None or compared < 0:
            return False
    start_excluding = affected.get("version_start_excluding")
    if start_excluding:
        compared = _compare_versions(installed, start_excluding)
        if compared is None or compared <= 0:
            return False
    end_including = affected.get("version_end_including")
    if end_including:
        compared = _compare_versions(installed, end_including)
        if compared is None or compared > 0:
            return False
    end_excluding = affected.get("version_end_excluding")
    if end_excluding:
        compared = _compare_versions(installed, end_excluding)
        if compared is None or compared >= 0:
            return False
    return True


def _name_matches(name: object, affected: dict) -> bool:
    text = _norm(name)
    vendor_tokens = _tokens(affected.get("vendor"))
    product_tokens = _tokens(affected.get("product"))
    if not product_tokens:
        return False
    if not all(token in text for token in product_tokens):
        return False
    if vendor_tokens and not all(token in text for token in vendor_tokens):
        return False
    return True


def _analyze_cpe_matches(db: Session, vulnerability: Vulnerability) -> int | None:
    affected_versions = vulnerability.affected_versions
    if not isinstance(affected_versions, list) or not affected_versions:
        return None

    db.execute(delete(Detection).where(Detection.vulnerability_id == vulnerability.id))
    db.flush()
    created = 0
    endpoints = db.scalars(select(EndpointSnapshot)).all()

    for endpoint in endpoints:
        for affected in affected_versions:
            if not isinstance(affected, dict):
                continue
            part = affected.get("part")
            if part == "o":
                name = " ".join(value for value in (endpoint.os_name, endpoint.os_version) if value)
                if not _name_matches(name, affected):
                    continue
                version_match = _version_in_range(endpoint.os_version or endpoint.os_name, affected)
                if version_match is False:
                    continue
                db.add(
                    Detection(
                        vulnerability_id=vulnerability.id,
                        endpoint_snapshot_id=endpoint.id,
                        match_reason="Matched NVD CPE against endpoint OS inventory.",
                        confidence=0.85 if version_match else 0.7,
                        status="open",
                    )
                )
                created += 1
                break

            if part != "a":
                continue
            for app in endpoint.software or []:
                if not isinstance(app, dict) or not _name_matches(app.get("name"), affected):
                    continue
                version_match = _version_in_range(app.get("version"), affected)
                if version_match is False:
                    continue
                db.add(
                    Detection(
                        vulnerability_id=vulnerability.id,
                        endpoint_snapshot_id=endpoint.id,
                        match_reason="Matched NVD CPE against endpoint software inventory.",
                        confidence=0.9 if version_match else 0.7,
                        status="open",
                    )
                )
                created += 1
                break

    db.commit()
    return created


def analyze_basic_software_matches(db: Session, vulnerability_id: int) -> int:
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        return 0
    cpe_matches = _analyze_cpe_matches(db, vulnerability)
    if cpe_matches is not None:
        return cpe_matches
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
