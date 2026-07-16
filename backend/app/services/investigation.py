from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import Article, EndpointSnapshot, InvestigationRun, NewsIntelligence, Vulnerability
from app.services.llm import SummaryService, resolve_llm_config, sanitize_llm_error


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.IGNORECASE)
PROCESS_RE = re.compile(r"\b[a-z0-9_.-]+\.(?:exe|dll|ps1|sh|bat|cmd|jar|py)\b", re.IGNORECASE)
STOPWORDS = {
    "security",
    "vulnerability",
    "attack",
    "attacker",
    "malware",
    "ransomware",
    "microsoft",
    "google",
    "critical",
    "remote",
    "code",
    "execution",
}

TANIUM_CAPABILITIES = {
    "mode": "read_only_inventory_investigation",
    "allowed_scopes": ["software", "processes", "operating_system", "hostname", "ip_address"],
    "blocked_actions": ["mutation", "process_kill", "file_delete", "package_deploy", "endpoint_control"],
    "input_schema": {
        "software": ["product/vendor/application names to search in installedApplications"],
        "processes": ["process names or executable/script names to search in Running Processes sensor values"],
        "os": ["operating system/platform keywords"],
        "cve": ["CVE IDs for correlation and reporting"],
        "ioc": {
            "ip": ["IP indicators; compared with endpoint IP only in phase 1"],
            "domain": ["Domain indicators; retained in report unless network telemetry is added"],
            "hash": ["Hash indicators; retained in report unless file telemetry is added"],
            "file": ["File indicators; compared with process/software names when possible"],
        },
    },
    "execution_policy": "LLM may propose query keywords. Backend validates and executes only local Tanium inventory matching.",
}


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = value.strip()
        key = text.lower()
        if len(text) < 2 or key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result[:50]


def _tokens(text: str) -> list[str]:
    values = re.findall(r"[A-Za-z][A-Za-z0-9_.+-]{2,}", text)
    return _unique([value for value in values if value.lower() not in STOPWORDS])[:20]


def _source_payload(db: Session, source_type: str, item_id: int) -> tuple[str, str, str | None, Article | Vulnerability]:
    if source_type == "news":
        article = db.get(Article, item_id)
        if article is None:
            raise ValueError("News item not found")
        body = "\n".join(value for value in (article.title, article.summary, article.raw_excerpt) if value)
        return article.title, body, article.url, article
    vulnerability = db.get(Vulnerability, item_id)
    if vulnerability is None:
        raise ValueError("CVE item not found")
    title = vulnerability.title or vulnerability.cve_id
    body = "\n".join(
        value
        for value in (
            vulnerability.cve_id,
            vulnerability.title,
            vulnerability.summary,
            vulnerability.description,
            vulnerability.vendor,
            vulnerability.product,
        )
        if value
    )
    return title, body, vulnerability.source_url, vulnerability


def _rules_intelligence(source_type: str, title: str, body: str, source_url: str | None) -> dict[str, Any]:
    text = f"{title}\n{body}"
    files = _unique(PROCESS_RE.findall(text))
    cves = _unique([value.upper() for value in CVE_RE.findall(text)])
    software = _tokens(text) if source_type == "cve" else []
    return {
        "content": {
            "source_type": source_type,
            "title": title,
            "risk": "unknown",
            "summary": body[:600],
            "source_url": source_url,
        },
        "investigation_keywords": {
            "software": software,
            "processes": files,
            "os": [],
            "cve": cves,
            "ioc": {
                "ip": _unique(IP_RE.findall(text)),
                "domain": _unique([value for value in DOMAIN_RE.findall(text) if "nvd.nist.gov" not in value.lower()]),
                "hash": _unique(HASH_RE.findall(text)),
                "file": files,
            },
        },
        "recommended_actions": ["Tanium Inventory에서 software/process 키워드 기반 영향 단말을 확인합니다."],
    }


def _extract_json(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE | re.DOTALL).strip()
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


async def build_intelligence(db: Session, source_type: str, item_id: int, refresh: bool = False) -> NewsIntelligence:
    existing = db.scalar(
        select(NewsIntelligence).where(
            NewsIntelligence.source_type == source_type,
            NewsIntelligence.article_id == (item_id if source_type == "news" else None),
            NewsIntelligence.vulnerability_id == (item_id if source_type == "cve" else None),
        )
    )
    if existing is not None and not refresh:
        return existing

    title, body, source_url, source = _source_payload(db, source_type, item_id)
    payload = _rules_intelligence(source_type, title, body, source_url)
    method = "rules"
    error = None
    llm_config = resolve_llm_config(db)
    if llm_config.provider != "disabled":
        prompt = (
            "Return valid JSON only. Extract endpoint investigation keywords for Tanium inventory matching. "
            "Use this exact structure: {\"content\":{\"source_type\":\"news|cve\",\"title\":\"\",\"risk\":\"low|medium|high|critical|unknown\",\"summary\":\"Korean summary\",\"source_url\":\"\"},"
            "\"investigation_keywords\":{\"software\":[],\"processes\":[],\"os\":[],\"cve\":[],\"ioc\":{\"ip\":[],\"domain\":[],\"hash\":[],\"file\":[]}},"
            "\"recommended_actions\":[]}."
            "Do not invent indicators. Focus on software, process, OS, CVE, file, domain, IP, hash useful for endpoint investigation.\n\n"
            f"Title: {title}\nSource URL: {source_url or ''}\nBody:\n{body[:6000]}"
        )
        try:
            raw = await SummaryService(llm_config).summarize("Tanium investigation keyword extraction", prompt, [source_url] if source_url else [], source_type="news")
            parsed = _extract_json(raw)
            if parsed and isinstance(parsed.get("investigation_keywords"), dict):
                payload = parsed
                method = "llm"
        except Exception as exc:
            error = sanitize_llm_error(exc)

    row = existing or NewsIntelligence(source_type=source_type)
    row.article_id = source.id if source_type == "news" else None
    row.vulnerability_id = source.id if source_type == "cve" else None
    row.title = title
    row.source_url = source_url
    row.status = "ready"
    row.intelligence = payload
    row.extraction_method = method
    row.error = error
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _keyword_groups(payload: dict[str, Any]) -> dict[str, list[str]]:
    keywords = payload.get("investigation_keywords") if isinstance(payload, dict) else {}
    if not isinstance(keywords, dict):
        keywords = {}
    ioc = keywords.get("ioc") if isinstance(keywords.get("ioc"), dict) else {}
    return {
        "software": _unique([str(value) for value in keywords.get("software", []) if value]),
        "processes": _unique([str(value) for value in [*keywords.get("processes", []), *ioc.get("file", [])] if value]),
        "os": _unique([str(value) for value in keywords.get("os", []) if value]),
        "cve": _unique([str(value).upper() for value in keywords.get("cve", []) if value]),
        "ip": _unique([str(value) for value in ioc.get("ip", []) if value]),
        "domain": _unique([str(value) for value in ioc.get("domain", []) if value]),
        "hash": _unique([str(value) for value in ioc.get("hash", []) if value]),
    }


def _contains(text: str, keyword: str) -> bool:
    return keyword.lower() in text.lower()


def _endpoint_text(endpoint: EndpointSnapshot) -> dict[str, str]:
    software = " ".join(f"{item.get('name', '')} {item.get('version', '')}" for item in endpoint.software or [] if isinstance(item, dict))
    processes = " ".join(" ".join(str(value) for value in item.get("values", [])) for item in endpoint.processes or [] if isinstance(item, dict))
    os_text = " ".join(value for value in (endpoint.os_name, endpoint.os_version, endpoint.platform) if value)
    return {
        "software": software,
        "processes": processes,
        "os": os_text,
        "ip": endpoint.ip_address or "",
        "identity": " ".join(value for value in (endpoint.hostname, endpoint.tanium_endpoint_id, endpoint.ip_address) if value),
    }


def run_inventory_investigation(db: Session, intelligence: NewsIntelligence) -> InvestigationRun:
    payload = intelligence.intelligence if isinstance(intelligence.intelligence, dict) else {}
    groups = _keyword_groups(payload)
    endpoints = db.scalars(select(EndpointSnapshot).order_by(EndpointSnapshot.hostname.asc().nullslast())).all()
    matches: list[dict[str, Any]] = []
    for endpoint in endpoints:
        texts = _endpoint_text(endpoint)
        evidence: list[dict[str, str]] = []
        for scope in ("software", "processes", "os", "ip"):
            for keyword in groups[scope]:
                if _contains(texts[scope], keyword):
                    evidence.append({"scope": scope, "keyword": keyword})
        if evidence:
            matches.append(
                {
                    "endpoint": {
                        "id": endpoint.id,
                        "hostname": endpoint.hostname,
                        "ip_address": endpoint.ip_address,
                        "os": " ".join(value for value in (endpoint.os_name, endpoint.os_version) if value),
                        "platform": endpoint.platform,
                    },
                    "evidence": evidence[:20],
                    "confidence": min(0.95, 0.45 + len(evidence) * 0.1),
                }
            )
    result = {
        "matched_endpoint_count": len(matches),
        "matches": matches[:200],
        "unmatched_indicators": {
            "domain": groups["domain"],
            "hash": groups["hash"],
            "cve": groups["cve"],
        },
        "capabilities": TANIUM_CAPABILITIES,
    }
    summary = f"{len(matches)}개 단말에서 software/process/os/ip 기준 조사 키워드가 매칭되었습니다."
    run = InvestigationRun(
        intelligence_id=intelligence.id,
        source_type=intelligence.source_type,
        source_title=intelligence.title,
        status="completed",
        query_plan=groups,
        results=result,
        summary=summary,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run
