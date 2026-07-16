from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import Article, EndpointSnapshot, InvestigationRun, NewsIntelligence, Vulnerability
from app.services.llm import SummaryService, resolve_llm_config, sanitize_llm_error


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.IGNORECASE)
PROCESS_RE = re.compile(r"\b[a-z0-9_.-]+\.(?:exe|dll|ps1|sh|bat|cmd|jar|py)\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,4}\b")
PRODUCT_BEFORE_VERSION_RE = re.compile(
    r"([A-Z][A-Za-z0-9+()./' -]{2,120})\s+before\s+(?:versions?\s+)?([0-9][0-9A-Za-z./-]*(?:\s*,\s*[0-9][0-9A-Za-z./-]*)*(?:\s*,?\s*and\s*[0-9][0-9A-Za-z./-]*)?)",
    re.IGNORECASE,
)
OS_KEYWORDS = ("Windows", "macOS", "Mac OS", "Linux", "Ubuntu", "Debian", "Android", "iOS", "ChromeOS")
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

class _ArticleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg", "nav", "footer"}:
            self._skip_depth += 1
        if tag in {"p", "br", "div", "article", "section", "li", "h1", "h2", "h3"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg", "nav", "footer"} and self._skip_depth:
            self._skip_depth -= 1
        if tag in {"p", "div", "article", "section", "li", "h1", "h2", "h3"}:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = re.sub(r"\s+", " ", data).strip()
        if text:
            self._chunks.append(text)

    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "\n".join(self._chunks)).strip()


NEWS_INTELLIGENCE_SCHEMA = {
    "content": {
        "source_type": "news|cve",
        "title": "원문 제목",
        "risk": "low|medium|high|critical|unknown",
        "summary": "한국어 조사 요약",
        "source_url": "원문 URL",
        "source_fetch": "fetched_url|fallback_local",
    },
    "investigation_keywords": {
        "software": ["product/vendor/application names to search in installedApplications"],
        "versions": ["affected version strings explicitly stated in the source"],
        "affected_products": [{"name": "product name", "platform": "Windows|Linux|macOS|unknown", "affected_versions": ["version strings"]}],
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
    "recommended_actions": ["조사자가 확인해야 하는 대응 방향"],
}

TANIUM_CAPABILITIES = {
    "mode": "read_only_tanium_investigation",
    "principle": "News Intelligence JSON은 조사 키워드 추출용 정의이고, Tanium 조사는 백엔드가 허용한 read-only API만 실행합니다.",
    "news_intelligence_schema": NEWS_INTELLIGENCE_SCHEMA,
    "tanium_api_definition": {
        "gateway": "Tanium Gateway GraphQL",
        "allowed_operations": [
            {
                "name": "Endpoint Inventory",
                "purpose": "Host Name, IP, OS, Platform, 설치 소프트웨어 목록 조회",
                "method": "query",
                "graphql_operation": "SecureWatchEndpointInventory",
                "fields": ["endpoints.id", "endpoints.name", "ipAddress", "os", "installedApplications", "services"],
            },
            {
                "name": "Running Processes Sensor",
                "purpose": "단말별 실행 프로세스 센서 결과 조회",
                "method": "query",
                "graphql_operation": "SecureWatchEndpointProcessReadings",
                "sensor": "Running Processes",
                "fields": ["endpoints.id", "sensorReadings.columns.name", "sensorReadings.columns.values"],
            },
        ],
        "query_inputs": {
            "software": "installedApplications.name/version에서 부분 일치 검색",
            "processes": "Running Processes sensor values에서 부분 일치 검색",
            "os": "os.name/generation/platform에서 부분 일치 검색",
            "ip": "endpoint ipAddress에서 부분 일치 검색",
        },
        "blocked_operations": ["mutation", "process_kill", "file_delete", "package_deploy", "endpoint_control"],
    },
    "execution_policy": "LLM은 조사 후보 키워드만 제안합니다. Tanium API 실행은 backend allowlist와 read-only query로 제한됩니다.",
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


def _clean_product_name(value: str) -> str:
    text = re.sub(r"\s+", " ", value).strip(" .,:;()[]")
    text = re.sub(r"^(?:the|and|or|a|an)\s+", "", text, flags=re.IGNORECASE)
    prefixes = [
        "the flaw affects ",
        "flaw affects ",
        "affecting ",
        "affects ",
        "in ",
    ]
    lowered = text.lower()
    for prefix in prefixes:
        if prefix in lowered:
            index = lowered.rfind(prefix)
            text = text[index + len(prefix) :].strip(" .,:;()[]")
            lowered = text.lower()
    return text


def _version_values(value: str) -> list[str]:
    return _unique(VERSION_RE.findall(value))


def _split_product_candidates(value: str) -> list[str]:
    text = _clean_product_name(value)
    parts = re.split(r"\s*,\s*|\s+ and \s+|\s+ or \s+", text)
    cleaned = [_clean_product_name(part) for part in parts]
    os_values = {value.lower() for value in OS_KEYWORDS}
    return _unique(
        [
            part
            for part in cleaned
            if len(part) > 2
            and not part.lower().startswith(("version", "versions", "for "))
            and part.lower() not in os_values
        ]
    )


def _extract_affected_products(text: str) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    for match in PRODUCT_BEFORE_VERSION_RE.finditer(text):
        versions = _version_values(match.group(2))
        if not versions:
            continue
        for name in _split_product_candidates(match.group(1)):
            platform = "unknown"
            for os_name in OS_KEYWORDS:
                if os_name.lower() in name.lower():
                    platform = "macOS" if os_name.lower() == "mac os" else os_name
                    break
            products.append({"name": name, "platform": platform, "affected_versions": versions})
    return products[:30]


def _software_from_affected_products(products: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    os_values = {value.lower() for value in OS_KEYWORDS}
    for product in products:
        name = str(product.get("name") or "")
        if not name or name.lower() in os_values or name.lower().startswith("for "):
            continue
        names.append(name)
        normalized = re.sub(r"\s+for\s+(Windows|Linux|macOS|Mac OS|Android|iOS)\b", "", name, flags=re.IGNORECASE).strip()
        if normalized and normalized != name and normalized.lower() not in os_values:
            names.append(normalized)
        if "zoom" in name.lower():
            names.append("Zoom")
    return _unique(names)


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


async def _fetch_source_text(source_url: str | None) -> tuple[str | None, str | None]:
    if not source_url or not source_url.startswith(("http://", "https://")):
        return None, "missing_source_url"
    headers = {"User-Agent": "SecureWatch/0.1 (+security-investigation)"}
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=headers) as client:
            response = await client.get(source_url)
            response.raise_for_status()
    except Exception as exc:
        return None, f"source_fetch_failed: {sanitize_llm_error(exc)}"
    content_type = response.headers.get("content-type", "")
    if "html" not in content_type and "<html" not in response.text[:500].lower():
        text = response.text
    else:
        parser = _ArticleTextParser()
        parser.feed(response.text)
        text = parser.text()
    text = re.sub(r"[ \t]{2,}", " ", text).strip()
    if len(text) < 120:
        return None, "source_fetch_too_short"
    return text[:12000], None


def _rules_intelligence(source_type: str, title: str, body: str, source_url: str | None) -> dict[str, Any]:
    text = f"{title}\n{body}"
    files = _unique(PROCESS_RE.findall(text))
    cves = _unique([value.upper() for value in CVE_RE.findall(text)])
    affected_products = _extract_affected_products(text)
    software = _software_from_affected_products(affected_products)
    if source_type == "cve":
        software = _unique([*software, *_tokens(text)])
    versions = _unique([version for product in affected_products for version in product.get("affected_versions", [])])
    os_values = _unique(
        [
            str(product.get("platform"))
            for product in affected_products
            if product.get("platform") and product.get("platform") != "unknown"
        ]
    )
    if not os_values and source_type == "cve":
        os_values = _unique([os_name for os_name in OS_KEYWORDS if re.search(rf"\b{re.escape(os_name)}\b", text, re.IGNORECASE)])
    return {
        "content": {
            "source_type": source_type,
            "title": title,
            "risk": "unknown",
            "summary": body[:600],
            "source_url": source_url,
            "source_fetch": "fallback_local",
        },
        "investigation_keywords": {
            "software": software,
            "versions": versions,
            "affected_products": affected_products,
            "processes": files,
            "os": os_values,
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

    title, local_body, source_url, source = _source_payload(db, source_type, item_id)
    fetched_body, fetch_error = await _fetch_source_text(source_url)
    body = fetched_body or local_body
    payload = _rules_intelligence(source_type, title, body, source_url)
    payload["content"]["source_fetch"] = "fetched_url" if fetched_body else "fallback_local"
    method = "rules"
    error = fetch_error
    llm_config = resolve_llm_config(db)
    if llm_config.provider != "disabled":
        schema = json.dumps(NEWS_INTELLIGENCE_SCHEMA, ensure_ascii=False)
        prompt = (
            "Return valid JSON only. This is not a summary rewrite task. "
            "Analyze the source URL content again and extract endpoint investigation data for Tanium. "
            "Use the exact JSON structure below and keep values compact enough for the configured max_tokens. "
            "Do not invent indicators. Include only software, process, OS, CVE, file, domain, IP, and hash values that are useful for endpoint investigation. "
            "If source text does not contain endpoint-investigation evidence, use empty arrays.\n\n"
            f"Configured max_tokens: {llm_config.max_tokens}\n"
            f"Required JSON schema: {schema}\n\n"
            f"Source type: {source_type}\nTitle: {title}\nSource URL: {source_url or ''}\n"
            f"Source fetch status: {'fetched_url' if fetched_body else 'fallback_local'}\n"
            f"Source text:\n{body[:9000]}"
        )
        try:
            raw = await SummaryService(llm_config).summarize("Tanium investigation keyword extraction", prompt, [source_url] if source_url else [], source_type="news")
            parsed = _extract_json(raw)
            if parsed and isinstance(parsed.get("investigation_keywords"), dict):
                payload = parsed
                payload.setdefault("content", {})
                if isinstance(payload["content"], dict):
                    payload["content"].setdefault("source_url", source_url)
                    payload["content"]["source_fetch"] = "fetched_url" if fetched_body else "fallback_local"
                method = "llm"
        except Exception as exc:
            llm_error = sanitize_llm_error(exc)
            error = f"{fetch_error}; {llm_error}" if fetch_error else llm_error

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
    def list_values(key: str) -> list[Any]:
        value = keywords.get(key)
        return value if isinstance(value, list) else []

    affected_products = keywords.get("affected_products") if isinstance(keywords.get("affected_products"), list) else []
    affected_names = [str(item.get("name")) for item in affected_products if isinstance(item, dict) and item.get("name")]
    affected_versions = [
        str(version)
        for item in affected_products
        if isinstance(item, dict)
        for version in (item.get("affected_versions") or [])
        if version
    ]
    return {
        "software": _unique([str(value) for value in [*list_values("software"), *affected_names] if value]),
        "versions": _unique([str(value) for value in [*list_values("versions"), *affected_versions] if value]),
        "processes": _unique([str(value) for value in [*list_values("processes"), *ioc.get("file", [])] if value]),
        "os": _unique([str(value) for value in list_values("os") if value]),
        "cve": _unique([str(value).upper() for value in list_values("cve") if value]),
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
        "affected_versions": groups["versions"],
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
