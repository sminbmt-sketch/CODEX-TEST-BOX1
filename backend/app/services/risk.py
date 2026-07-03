from app.db.models import Vulnerability


def vulnerability_risk_score(vulnerability: Vulnerability) -> float:
    score = 0.0
    if vulnerability.kev:
        score += 50.0
    if vulnerability.cvss_score is not None:
        score += min(vulnerability.cvss_score, 10.0) * 4.0
    if vulnerability.epss_score is not None:
        score += min(max(vulnerability.epss_score, 0.0), 1.0) * 30.0
    if vulnerability.cvss_severity == "CRITICAL":
        score += 10.0
    elif vulnerability.cvss_severity == "HIGH":
        score += 5.0
    return round(min(score, 100.0), 2)
