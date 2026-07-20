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
IP_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![A-Za-z0-9-])"
)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.IGNORECASE)
PROCESS_RE = re.compile(r"\b[a-z0-9_.-]+\.(?:exe|dll|ps1|sh|bat|cmd|jar|py)\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,4}\b")
PRODUCT_BEFORE_VERSION_RE = re.compile(
    r"([A-Z][A-Za-z0-9+()./' -]{2,120})\s+before\s+(?:versions?\s+)?([0-9][0-9A-Za-z./-]*(?:\s*,\s*[0-9][0-9A-Za-z./-]*)*(?:\s*,?\s*and\s*[0-9][0-9A-Za-z./-]*)?)",
    re.IGNORECASE,
)
PRODUCT_FIXED_VERSION_RE = re.compile(
    r"([A-Z0-9][A-Za-z0-9+()./' -]{1,80})\s+version\s+([0-9][0-9A-Za-z./-]*)\s+(?:was\s+)?(?:released|published|issued).{0,180}?\bfix(?:es|ed)?\b",
    re.IGNORECASE,
)
UPDATE_TO_VERSION_RE = re.compile(r"\bupdate\s+to\s+version\s+([0-9][0-9A-Za-z./-]*)\b", re.IGNORECASE)
OS_KEYWORDS = ("Windows", "macOS", "Mac OS", "Linux", "Ubuntu", "Debian", "Android", "iOS", "ChromeOS")
GENERIC_SOFTWARE_TERMS = {"windows", "linux", "android", "ios", "macos", "mac os", "meeting", "remote", "client", "plugin", "sdk"}
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
        "services": ["service names to search in endpoint service inventory"],
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

COMPACT_NEWS_INTELLIGENCE_SCHEMA = {
    "content": {"risk": "low|medium|high|critical|unknown", "summary": "한국어 120자 이하"},
    "investigation_keywords": {
        "software": [],
        "versions": [],
        "affected_products": [{"name": "", "platform": "unknown", "affected_versions": []}],
        "processes": [],
        "services": [],
        "os": [],
        "cve": [],
        "ioc": {"ip": [], "domain": [], "hash": [], "file": []},
    },
    "recommended_actions": [],
}

INVESTIGATION_JUDGEMENT_SCHEMA = {
    "summary_ko": "한국어 조사 결과 요약",
    "endpoint_assessments": [
        {
            "endpoint_id": 0,
            "classification": "confirmed|potential|environment_candidate|not_affected|insufficient_data",
            "reason": "Tanium 증거 기반 한국어 판단 근거",
            "confidence": 0.0,
            "evidence_refs": ["software: nginx 1.28.0", "process: nginx"],
        }
    ],
    "unmatched_reason": "후보 단말이 없거나 증거가 부족한 이유",
    "recommended_actions": ["조사자 후속 조치"],
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
            "version": "installedApplications.version을 affected_products.affected_versions와 비교",
            "processes": "Running Processes sensor values에서 부분 일치 검색",
            "services": "services.name/displayName에서 부분 일치 검색",
            "os": "os.name/generation/platform에서 부분 일치 검색",
            "ip": "endpoint ipAddress에서 부분 일치 검색",
        },
        "blocked_operations": ["mutation", "process_kill", "file_delete", "package_deploy", "endpoint_control"],
    },
    "execution_policy": "LLM은 조사 계획과 증거 기반 판정을 수행합니다. Tanium API 실행은 backend allowlist와 read-only query로 제한됩니다.",
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


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_ips(text: str) -> list[str]:
    values: list[str] = []
    for match in IP_RE.finditer(text):
        before = text[max(0, match.start() - 48) : match.start()].lower()
        after = text[match.end() : match.end() + 24].lower()
        if re.search(r"\b(?:version|versions|v|release|released|nginx plus)\b", before) or re.search(r"\b(?:version|versions)\b", after):
            continue
        values.append(match.group(0))
    return _unique(values)


def _tokens(text: str) -> list[str]:
    values = re.findall(r"[A-Za-z][A-Za-z0-9_.+-]{2,}", text)
    return _unique([value for value in values if value.lower() not in STOPWORDS])[:20]


def _focus_source_text(title: str, body: str, max_chars: int = 6000) -> str:
    title_terms = [term.lower() for term in _tokens(title) if len(term) >= 4]
    priority_patterns = re.compile(
        r"\b(?:CVE-\d{4}-\d{4,7}|vulnerab|exploit|affect|affected|impact|patch|patched|fix|fixed|before|version|versions|update|upgrade|RCE|remote code execution|denial-of-service|DoS)\b",
        re.IGNORECASE,
    )
    lines = [re.sub(r"\s+", " ", line).strip() for line in body.splitlines()]
    selected: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if len(line) < 18:
            continue
        lowered = line.lower()
        if not priority_patterns.search(line) and not any(term in lowered for term in title_terms):
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        selected.append(line)
        if sum(len(value) for value in selected) >= max_chars:
            break
    if selected:
        return "\n".join(selected)[:max_chars]
    return body[:max_chars]


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
    for match in PRODUCT_FIXED_VERSION_RE.finditer(text):
        versions = _version_values(match.group(2))
        if not versions:
            continue
        for name in _split_product_candidates(match.group(1)):
            products.append({"name": name, "platform": "unknown", "affected_versions": versions})
    known_platforms = _unique([str(product["platform"]) for product in products if product.get("platform") and product.get("platform") != "unknown"])
    if len(known_platforms) == 1:
        for product in products:
            if product.get("platform") == "unknown":
                product["platform"] = known_platforms[0]
    return products[:30]


def _add_known_product_hints(text: str, products: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lowered = text.lower()
    names = {_normalize_product(str(product.get("name") or "")) for product in products if isinstance(product, dict)}
    if "nginx" in lowered and not any("nginx" in name for name in names):
        nginx_versions: list[str] = []
        nginx_plus_versions: list[str] = []
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
            if "nginx" not in sentence.lower():
                continue
            versions = _version_values(sentence)
            if not versions:
                continue
            if "plus" in sentence.lower():
                nginx_plus_versions.extend(versions)
            else:
                nginx_versions.extend(versions)
        versions = _unique([*nginx_versions, *nginx_plus_versions])
        if versions:
            products.append({"name": "NGINX", "platform": "unknown", "affected_versions": _unique(nginx_versions) or versions})
            products.append({"name": "NGINX Plus", "platform": "unknown", "affected_versions": _unique(nginx_plus_versions) or versions})
        else:
            products.append({"name": "NGINX", "platform": "unknown", "affected_versions": []})
            products.append({"name": "NGINX Plus", "platform": "unknown", "affected_versions": []})
    return products[:30]


def _software_from_affected_products(products: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    os_values = {value.lower() for value in OS_KEYWORDS}
    for product in products:
        name = str(product.get("name") or "")
        lowered = name.lower()
        if not name or lowered in os_values or lowered in GENERIC_SOFTWARE_TERMS or lowered.startswith("for "):
            continue
        names.append(name)
        normalized = re.sub(r"\s+for\s+(Windows|Linux|macOS|Mac OS|Android|iOS)\b", "", name, flags=re.IGNORECASE).strip()
        if normalized and normalized != name and normalized.lower() not in os_values and normalized.lower() not in GENERIC_SOFTWARE_TERMS:
            names.append(normalized)
        if _normalize_product(name).startswith("zoom workplace"):
            names.append("Zoom")
    return _unique(names)


def _relevant_cves(text: str, product_names: list[str]) -> list[str]:
    all_cves = _unique([value.upper() for value in CVE_RE.findall(text)])
    if not all_cves or not product_names:
        return all_cves
    product_terms = [term for name in product_names for term in _product_terms(name)]
    if not product_terms:
        return all_cves
    relevant: list[str] = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        sentence_cves = [value.upper() for value in CVE_RE.findall(sentence)]
        if not sentence_cves:
            continue
        normalized = _normalize_product(sentence)
        if any(term in normalized for term in product_terms):
            relevant.extend(sentence_cves)
    return _unique(relevant)


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
    affected_products = _add_known_product_hints(text, _extract_affected_products(text))
    if not affected_products and "7-zip" in text.lower():
        versions = _unique(UPDATE_TO_VERSION_RE.findall(text))
        affected_products = [{"name": "7-Zip", "platform": "unknown", "affected_versions": versions}] if versions else []
    software = _software_from_affected_products(affected_products)
    cves = _unique([value.upper() for value in CVE_RE.findall(text)]) if source_type == "cve" else _relevant_cves(text, software)
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
            "services": [],
            "os": os_values,
            "cve": cves,
            "ioc": {
                "ip": _extract_ips(text),
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
    candidates = [cleaned]
    block = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.IGNORECASE | re.DOTALL)
    if block:
        candidates.insert(0, block.group(1).strip())
    first = cleaned.find("{")
    last = cleaned.rfind("}")
    if first >= 0 and last > first:
        candidates.append(cleaned[first : last + 1])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _string_values(values: Any, source_text: str | None = None) -> list[str]:
    if isinstance(values, str):
        candidates = [values]
    elif isinstance(values, list):
        candidates = [str(value) for value in values if value is not None]
    else:
        candidates = []
    result: list[str] = []
    for value in candidates:
        text = re.sub(r"\s+", " ", value).strip()
        if not text:
            continue
        if source_text and text.lower() not in source_text.lower():
            continue
        result.append(text)
    return _unique(result)


def _normalize_affected_products(values: Any) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    for item in _as_list(values):
        if isinstance(item, str):
            name = item.strip()
            if name:
                products.append({"name": name, "platform": "unknown", "affected_versions": []})
            continue
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("product") or "").strip()
        if not name:
            continue
        platform = str(item.get("platform") or "unknown").strip() or "unknown"
        versions = _string_values(item.get("affected_versions") or item.get("versions") or [])
        products.append({"name": name, "platform": platform, "affected_versions": versions})
    return products[:30]


def _normalize_intelligence_payload(
    payload: dict[str, Any],
    fallback: dict[str, Any],
    *,
    source_type: str,
    title: str,
    source_url: str | None,
    source_fetch: str,
    source_text: str,
) -> dict[str, Any]:
    content = _as_dict(payload.get("content"))
    keywords = _as_dict(payload.get("investigation_keywords"))
    if not keywords:
        entities = _as_dict(payload.get("entities"))
        summary_iocs = _as_dict(payload.get("iocs"))
        keywords = {
            "software": entities.get("software"),
            "versions": entities.get("version"),
            "affected_products": [
                {"name": name, "platform": "unknown", "affected_versions": _string_values(entities.get("version"))}
                for name in _string_values(entities.get("software"))
            ],
            "processes": summary_iocs.get("process") or summary_iocs.get("file"),
            "services": [],
            "os": [],
            "cve": entities.get("cve"),
            "ioc": summary_iocs,
        }
    fallback_keywords = _as_dict(fallback.get("investigation_keywords"))
    fallback_ioc = _as_dict(fallback_keywords.get("ioc"))
    ioc = _as_dict(keywords.get("ioc"))

    allowed_ips = set(_extract_ips(source_text))
    ip_values = [value for value in _string_values(ioc.get("ip")) if value in allowed_ips]
    affected_products = _normalize_affected_products(keywords.get("affected_products"))
    if not affected_products:
        affected_products = _normalize_affected_products(fallback_keywords.get("affected_products"))
    software = _string_values(keywords.get("software"), source_text)
    if not software:
        software = _string_values(fallback_keywords.get("software"))
    versions = _string_values(keywords.get("versions"), source_text)
    if not versions:
        versions = _string_values(fallback_keywords.get("versions"))
    if not affected_products and software:
        affected_products = [{"name": name, "platform": "unknown", "affected_versions": versions} for name in software[:20]]

    files = _string_values(ioc.get("file"), source_text) or _string_values(fallback_ioc.get("file"))
    processes = _unique([*_string_values(keywords.get("processes"), source_text), *files])
    return {
        "content": {
            "source_type": source_type,
            "title": str(content.get("title") or title),
            "risk": str(content.get("risk") or _as_dict(fallback.get("content")).get("risk") or "unknown"),
            "summary": str(content.get("summary") or _as_dict(fallback.get("content")).get("summary") or "")[:1200],
            "source_url": source_url,
            "source_fetch": source_fetch,
        },
        "investigation_keywords": {
            "software": _unique([*software, *_software_from_affected_products(affected_products)]),
            "versions": _unique([*versions, *[version for product in affected_products for version in product.get("affected_versions", [])]]),
            "affected_products": affected_products,
            "processes": processes,
            "services": _string_values(keywords.get("services"), source_text) or _string_values(fallback_keywords.get("services")),
            "os": _string_values(keywords.get("os"), source_text) or _string_values(fallback_keywords.get("os")),
            "cve": _unique([value.upper() for value in _string_values(keywords.get("cve"), source_text) or _string_values(fallback_keywords.get("cve"))]),
            "ioc": {
                "ip": ip_values or _string_values(fallback_ioc.get("ip")),
                "domain": _string_values(ioc.get("domain"), source_text) or _string_values(fallback_ioc.get("domain")),
                "hash": _string_values(ioc.get("hash"), source_text) or _string_values(fallback_ioc.get("hash")),
                "file": files,
            },
        },
        "recommended_actions": _string_values(payload.get("recommended_actions")) or _string_values(fallback.get("recommended_actions")),
    }


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
    prompt_body = _focus_source_text(title, body)
    source_fetch = "fetched_url" if fetched_body else "fallback_local"
    fallback_payload = _rules_intelligence(source_type, title, body, source_url)
    fallback_payload["content"]["source_fetch"] = source_fetch
    payload = fallback_payload
    method = "rules"
    error = fetch_error
    llm_config = resolve_llm_config(db)
    if llm_config.provider != "disabled":
        schema = json.dumps(COMPACT_NEWS_INTELLIGENCE_SCHEMA, ensure_ascii=False, separators=(",", ":"))
        system_prompt = (
            "You are a security investigation planner for Tanium. Return valid JSON only. "
            "This is not a summary task. Build a compact endpoint investigation plan from the provided source text. "
            "Do not include markdown, code fences, or explanatory prose. Return minified JSON."
        )
        user_prompt = (
            "Analyze the source content and extract only endpoint-investigation data that can drive Tanium read-only checks. "
            "Focus on affected products, product aliases, vulnerable or fixed versions, process names, services, OS/platforms, CVEs, files, domains, IPs, and hashes. "
            "For product vulnerabilities, affected_products must include the software name even when exact vulnerable versions are not fully clear. "
            "For fixed-release articles, treat the fixed version as the threshold used to identify older potentially affected installs. "
            "Keep only the most important 5 software names and 5 affected_products. Prefer core affected products over related products. "
            "Use compact version strings such as 1.30.4 instead of prose. content.summary must be Korean and 120 characters or less. "
            "Do not invent indicators. IOC values must appear in the source text. "
            "Never classify product versions as IP addresses. "
            "If evidence is absent, use empty arrays. "
            "Use the exact compact JSON structure below and keep the entire response within configured max_tokens.\n\n"
            f"Configured max_tokens: {llm_config.max_tokens}\n"
            f"Required compact JSON schema: {schema}\n\n"
            f"Source type: {source_type}\nTitle: {title}\nSource URL: {source_url or ''}\n"
            f"Source fetch status: {source_fetch}\n"
            f"Focused source text:\n{prompt_body}"
        )
        try:
            raw = await SummaryService(llm_config).complete(system_prompt, user_prompt)
            parsed = _extract_json(raw)
            if parsed:
                payload = _normalize_intelligence_payload(
                    parsed,
                    fallback_payload,
                    source_type=source_type,
                    title=title,
                    source_url=source_url,
                    source_fetch=source_fetch,
                    source_text=body,
                )
                method = "llm_plan"
            else:
                error = f"{fetch_error}; llm_json_parse_failed" if fetch_error else "llm_json_parse_failed"
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
    software_values = _unique([str(value) for value in [*list_values("software"), *affected_names] if value])
    version_values = _unique([str(value) for value in [*list_values("versions"), *affected_versions] if value])
    if not affected_products and software_values:
        affected_products = [{"name": name, "platform": "unknown", "affected_versions": version_values} for name in software_values[:20]]
    return {
        "software": software_values,
        "versions": version_values,
        "affected_products": affected_products,
        "processes": _unique([str(value) for value in [*list_values("processes"), *ioc.get("file", [])] if value]),
        "services": _unique([str(value) for value in list_values("services") if value]),
        "os": _unique([str(value) for value in list_values("os") if value]),
        "cve": _unique([str(value).upper() for value in list_values("cve") if value]),
        "ip": _unique([str(value) for value in ioc.get("ip", []) if value]),
        "domain": _unique([str(value) for value in ioc.get("domain", []) if value]),
        "hash": _unique([str(value) for value in ioc.get("hash", []) if value]),
    }


def _contains(text: str, keyword: str) -> bool:
    return keyword.lower() in text.lower()


def _clean_version(value: str | None) -> str | None:
    if not value:
        return None
    match = VERSION_RE.search(str(value))
    return match.group(0) if match else None


def _version_tuple(value: str | None) -> tuple[int, ...] | None:
    cleaned = _clean_version(value)
    if not cleaned:
        return None
    return tuple(int(part) for part in cleaned.split("."))


def _same_version_branch(installed: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    if len(installed) < 2 or len(threshold) < 2:
        return True
    if len(threshold) >= 3 and threshold[1] == 0 and threshold[2] == 0:
        return True
    return installed[:2] == threshold[:2]


def _version_status(installed_version: str | None, affected_versions: list[str]) -> str:
    installed = _version_tuple(installed_version)
    thresholds = [_version_tuple(value) for value in affected_versions]
    thresholds = [value for value in thresholds if value is not None]
    if installed is None:
        return "version_unknown"
    if not thresholds:
        return "no_version_rule"

    comparable = [threshold for threshold in thresholds if _same_version_branch(installed, threshold)]
    if not comparable:
        comparable = thresholds
    if any(installed < threshold for threshold in comparable):
        return "affected_version"
    return "safe_version"


def _normalize_product(value: str) -> str:
    text = re.sub(r"\([^)]*\)", " ", value)
    text = re.sub(r"\b(?:for|on)\s+(?:windows|linux|macos|mac os|android|ios)\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(?:desktop|client|application|app|software)\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"[^a-z0-9+.#]+", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


def _product_terms(product_name: str) -> list[str]:
    normalized = _normalize_product(product_name)
    terms = [normalized] if normalized else []
    if normalized in {"7 zip", "7zip"} or "7 zip" in normalized:
        terms.extend(["7 zip", "7zip", "p7zip"])
    if normalized.startswith("zoom workplace"):
        terms.append("zoom workplace")
        terms.append("zoom")
    elif normalized == "zoom":
        terms.append("zoom")
    return _unique([term for term in terms if len(term) >= 3 and term not in GENERIC_SOFTWARE_TERMS])


def _product_matches(installed_name: str, product_name: str) -> bool:
    installed = _normalize_product(installed_name)
    if not installed:
        return False
    return any(term and term in installed for term in _product_terms(product_name))


def _endpoint_platform_text(endpoint: EndpointSnapshot) -> str:
    return " ".join(value for value in (endpoint.os_name, endpoint.os_version, endpoint.platform) if value)


def _platform_matches(endpoint: EndpointSnapshot, platform: str | None) -> bool:
    if not platform or platform == "unknown":
        return True
    endpoint_text = _endpoint_platform_text(endpoint).lower()
    normalized = platform.lower()
    if normalized == "mac os":
        normalized = "macos"
    if normalized == "macos":
        return "mac" in endpoint_text
    return normalized in endpoint_text


def _endpoint_summary(endpoint: EndpointSnapshot) -> dict[str, Any]:
    return {
        "id": endpoint.id,
        "hostname": endpoint.hostname,
        "ip_address": endpoint.ip_address,
        "os": " ".join(value for value in (endpoint.os_name, endpoint.os_version) if value),
        "platform": endpoint.platform,
    }


def _software_records(endpoint: EndpointSnapshot) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for item in endpoint.software or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        records.append({"name": name, "version": str(item.get("version") or "").strip()})
    return records


def _service_records(endpoint: EndpointSnapshot) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for item in endpoint.services or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("displayName") or item.get("serviceName") or "").strip()
        if not name:
            continue
        records.append({"name": name, "state": str(item.get("state") or item.get("status") or "").strip()})
    return records


def _process_values(endpoint: EndpointSnapshot) -> list[str]:
    values: list[str] = []
    for item in endpoint.processes or []:
        if not isinstance(item, dict):
            continue
        for value in item.get("values", []) or []:
            if value:
                values.append(str(value))
    return _unique(values)


def _endpoint_text(endpoint: EndpointSnapshot) -> dict[str, str]:
    software = " ".join(f"{item.get('name', '')} {item.get('version', '')}" for item in endpoint.software or [] if isinstance(item, dict))
    processes = " ".join(" ".join(str(value) for value in item.get("values", [])) for item in endpoint.processes or [] if isinstance(item, dict))
    services = " ".join(f"{item.get('name', '')} {item.get('displayName', '')} {item.get('state', '')}" for item in endpoint.services or [] if isinstance(item, dict))
    os_text = " ".join(value for value in (endpoint.os_name, endpoint.os_version, endpoint.platform) if value)
    return {
        "software": software,
        "processes": processes,
        "services": services,
        "os": os_text,
        "ip": endpoint.ip_address or "",
        "identity": " ".join(value for value in (endpoint.hostname, endpoint.tanium_endpoint_id, endpoint.ip_address) if value),
    }


def _assessment_rank(classification: str) -> int:
    return {"confirmed": 4, "potential": 3, "environment_candidate": 2, "not_affected": 1}.get(classification, 0)


def _make_assessment(
    endpoint: EndpointSnapshot,
    classification: str,
    reason: str,
    evidence: list[dict[str, Any]],
    affected_products: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "classification": classification,
        "reason": reason,
        "endpoint": _endpoint_summary(endpoint),
        "evidence": evidence[:30],
        "affected_products": affected_products[:20],
        "confidence": {
            "confirmed": 0.9,
            "potential": 0.65,
            "environment_candidate": 0.35,
            "not_affected": 0.15,
        }.get(classification, 0.2),
    }


def _assess_endpoint(endpoint: EndpointSnapshot, groups: dict[str, list[Any]]) -> dict[str, Any] | None:
    affected_products = [item for item in groups.get("affected_products", []) if isinstance(item, dict)]
    product_names = _unique(
        [
            str(item.get("name"))
            for item in affected_products
            if isinstance(item, dict) and item.get("name")
        ]
        + [str(value) for value in groups.get("software", []) if value]
    )
    product_matches: list[dict[str, Any]] = []
    not_affected: list[dict[str, Any]] = []

    for app in _software_records(endpoint):
        for product in affected_products:
            product_name = str(product.get("name") or "")
            if not product_name or not _product_matches(app["name"], product_name):
                continue
            platform = str(product.get("platform") or "unknown")
            versions = [str(value) for value in product.get("affected_versions", []) or [] if value]
            platform_ok = _platform_matches(endpoint, platform)
            version_status = _version_status(app["version"], versions)
            evidence = {
                "scope": "software",
                "product": product_name,
                "installed_name": app["name"],
                "installed_version": app["version"] or None,
                "affected_versions": versions,
                "platform": platform,
                "platform_match": platform_ok,
                "version_status": version_status,
            }
            if platform_ok and version_status == "affected_version":
                product_matches.append({**evidence, "classification": "confirmed"})
            elif platform_ok and version_status in {"version_unknown", "no_version_rule"}:
                product_matches.append({**evidence, "classification": "potential"})
            else:
                not_affected.append({**evidence, "classification": "not_affected"})

    process_evidence: list[dict[str, Any]] = []
    process_text = _normalize_product(" ".join(_process_values(endpoint)))
    for keyword in _unique([str(value) for value in [*groups.get("processes", []), *product_names] if value]):
        if keyword and any(term and term in process_text for term in _product_terms(str(keyword))):
            process_evidence.append({"scope": "process", "keyword": str(keyword)})

    service_evidence: list[dict[str, Any]] = []
    service_records = _service_records(endpoint)
    for service in service_records:
        normalized_service = _normalize_product(f"{service['name']} {service['state']}")
        for keyword in _unique([str(value) for value in [*groups.get("services", []), *product_names] if value]):
            if any(term and term in normalized_service for term in _product_terms(str(keyword))):
                service_evidence.append({"scope": "service", "keyword": str(keyword), "service_name": service["name"], "state": service["state"] or None})

    os_evidence: list[dict[str, Any]] = []
    os_text = _endpoint_platform_text(endpoint).lower()
    for keyword in groups.get("os", []):
        if keyword and str(keyword).lower() in os_text:
            os_evidence.append({"scope": "os", "keyword": str(keyword)})

    ip_evidence: list[dict[str, Any]] = []
    for keyword in groups.get("ip", []):
        if keyword and _contains(endpoint.ip_address or "", str(keyword)):
            ip_evidence.append({"scope": "ip", "keyword": str(keyword)})

    if any(item["classification"] == "confirmed" for item in product_matches):
        return _make_assessment(endpoint, "confirmed", "affected_product_version_match", product_matches, affected_products)
    if product_matches or process_evidence or service_evidence or ip_evidence:
        return _make_assessment(endpoint, "potential", "product_process_service_or_ip_match_requires_review", [*product_matches, *process_evidence, *service_evidence, *ip_evidence], affected_products)
    if not_affected:
        return _make_assessment(endpoint, "not_affected", "product_found_but_version_or_platform_not_affected", not_affected, affected_products)
    if os_evidence:
        return _make_assessment(endpoint, "environment_candidate", "platform_only_match", os_evidence, affected_products)
    return None


CLASSIFICATION_KEYS = ("confirmed", "potential", "environment_candidate", "not_affected", "insufficient_data")


def _normalize_classification(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text == "environment_candidates":
        text = "environment_candidate"
    return text if text in CLASSIFICATION_KEYS else "potential"


def _empty_buckets() -> dict[str, list[dict[str, Any]]]:
    return {key: [] for key in CLASSIFICATION_KEYS}


def _bucket_assessments(assessments: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets = _empty_buckets()
    for assessment in assessments:
        key = _normalize_classification(assessment.get("classification"))
        assessment["classification"] = key
        buckets[key].append(assessment)
    return buckets


def _candidate_for_llm(assessment: dict[str, Any]) -> dict[str, Any]:
    endpoint = _as_dict(assessment.get("endpoint"))
    evidence = []
    for item in _as_list(assessment.get("evidence"))[:12]:
        if isinstance(item, dict):
            evidence.append(item)
    return {
        "endpoint_id": endpoint.get("id"),
        "hostname": endpoint.get("hostname"),
        "ip_address": endpoint.get("ip_address"),
        "os": endpoint.get("os"),
        "platform": endpoint.get("platform"),
        "rule_classification": assessment.get("classification"),
        "rule_reason": assessment.get("reason"),
        "evidence": evidence,
    }


async def _llm_judge_inventory(
    db: Session,
    intelligence: NewsIntelligence,
    payload: dict[str, Any],
    groups: dict[str, list[Any]],
    rule_assessments: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
    llm_config = resolve_llm_config(db)
    if llm_config.provider == "disabled":
        return None, {"method": "rules", "error": "llm_disabled"}
    if not rule_assessments:
        return None, {"method": "rules", "error": "no_tanium_candidate_evidence"}

    candidates = [_candidate_for_llm(assessment) for assessment in rule_assessments[:50]]
    source_summary = _as_dict(payload.get("content")).get("summary") or intelligence.title
    system_prompt = (
        "You are a Tanium endpoint investigation judge. Return valid JSON only. "
        "Use only the provided source intelligence and Tanium candidate evidence. "
        "Do not invent endpoints, software, versions, processes, or network indicators."
    )
    user_prompt = (
        "Classify each candidate endpoint using the required JSON schema. "
        "confirmed means Tanium evidence shows the affected product and vulnerable version. "
        "potential means product/process/service evidence exists but version or exploitability is unclear. "
        "environment_candidate means only OS/platform context matches. "
        "not_affected means the product exists but the version/platform evidence indicates it is not affected. "
        "insufficient_data means evidence exists but is too weak to decide. "
        "Keep the response compact and within max_tokens.\n\n"
        f"Configured max_tokens: {llm_config.max_tokens}\n"
        f"Required JSON schema: {json.dumps(INVESTIGATION_JUDGEMENT_SCHEMA, ensure_ascii=False)}\n\n"
        f"Source title: {intelligence.title}\n"
        f"Source summary: {source_summary}\n"
        f"Investigation keywords: {json.dumps(groups, ensure_ascii=False)[:5000]}\n"
        f"Tanium candidate evidence: {json.dumps(candidates, ensure_ascii=False)[:9000]}"
    )
    try:
        raw = await SummaryService(llm_config).complete(system_prompt, user_prompt)
        parsed = _extract_json(raw)
        rows = _as_list(_as_dict(parsed).get("endpoint_assessments")) if parsed else []
        if not rows:
            return None, {"method": "rules", "error": "llm_judgement_json_parse_failed"}

        by_id = {int(_as_dict(item.get("endpoint")).get("id")): item for item in rule_assessments if _as_dict(item.get("endpoint")).get("id") is not None}
        judged: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            endpoint_id = row.get("endpoint_id")
            try:
                endpoint_key = int(endpoint_id)
            except (TypeError, ValueError):
                continue
            base = by_id.get(endpoint_key)
            if not base:
                continue
            classification = _normalize_classification(row.get("classification"))
            confidence = row.get("confidence")
            try:
                confidence_value = max(0.0, min(1.0, float(confidence)))
            except (TypeError, ValueError):
                confidence_value = base.get("confidence", 0.5)
            judged.append(
                {
                    **base,
                    "classification": classification,
                    "reason": str(row.get("reason") or base.get("reason") or "llm_evidence_judgement"),
                    "confidence": confidence_value,
                    "llm_evidence_refs": _string_values(row.get("evidence_refs")),
                }
            )
        if not judged:
            return None, {"method": "rules", "error": "llm_judgement_missing_endpoint_ids"}
        return judged, {
            "method": "llm",
            "error": None,
            "summary_ko": _as_dict(parsed).get("summary_ko"),
            "unmatched_reason": _as_dict(parsed).get("unmatched_reason"),
            "recommended_actions": _as_list(_as_dict(parsed).get("recommended_actions")),
        }
    except Exception as exc:
        return None, {"method": "rules", "error": sanitize_llm_error(exc)}


async def run_inventory_investigation(db: Session, intelligence: NewsIntelligence) -> InvestigationRun:
    payload = intelligence.intelligence if isinstance(intelligence.intelligence, dict) else {}
    groups = _keyword_groups(payload)
    endpoints = db.scalars(select(EndpointSnapshot).order_by(EndpointSnapshot.hostname.asc().nullslast())).all()
    rule_assessments: list[dict[str, Any]] = []

    for endpoint in endpoints:
        assessment = _assess_endpoint(endpoint, groups)
        if assessment:
            rule_assessments.append(assessment)

    judged_assessments, judge_meta = await _llm_judge_inventory(db, intelligence, payload, groups, rule_assessments)
    assessments = judged_assessments or rule_assessments
    buckets = _bucket_assessments(assessments)

    matches = [*buckets["confirmed"], *buckets["potential"]]
    candidates = buckets["environment_candidate"]
    not_affected = buckets["not_affected"]
    counts = {
        "confirmed": len(buckets["confirmed"]),
        "potential": len(buckets["potential"]),
        "environment_candidate": len(candidates),
        "insufficient_data": len(buckets["insufficient_data"]),
        "not_affected": len(not_affected),
        "total_endpoints": len(endpoints),
    }
    investigation_plan = {
        "affected_products": groups["affected_products"],
        "software_queries": groups["software"],
        "version_rules": groups["versions"],
        "platform_queries": groups["os"],
        "process_queries": groups["processes"],
        "service_queries": groups["services"],
        "cves": groups["cve"],
        "decision_model": {
            "confirmed": "제품명 매칭 + 플랫폼 일치 + 설치 버전이 영향 버전 조건에 해당",
            "potential": "제품/프로세스/서비스/IP 근거는 있으나 버전 정보가 없거나 판정 불가",
            "environment_candidate": "제품 근거 없이 OS/플랫폼만 일치",
            "not_affected": "제품은 발견됐지만 플랫폼 불일치 또는 안전 버전",
            "insufficient_data": "Tanium 증거는 있으나 LLM/룰 기준으로 판정 근거가 부족",
        },
    }
    analysis_mode = "llm_planned" if intelligence.extraction_method == "llm_plan" and judge_meta.get("method") == "llm" else "rules_fallback"
    if intelligence.extraction_method == "llm_plan" and judge_meta.get("method") != "llm":
        analysis_mode = "llm_plan_rules_assessment"
    empty_match_reason = None
    if not rule_assessments:
        empty_match_reason = "Tanium Inventory에서 software/process/service/IP 기준 후보 증거가 발견되지 않았습니다."
    result = {
        "analysis_mode": analysis_mode,
        "summary_counts": counts,
        "investigation_plan": investigation_plan,
        "planner": {"method": intelligence.extraction_method, "error": intelligence.error},
        "judge": judge_meta,
        "tanium_evidence": {
            "candidate_endpoint_count": len(rule_assessments),
            "candidate_evidence": [_candidate_for_llm(assessment) for assessment in rule_assessments[:80]],
            "empty_match_reason": empty_match_reason,
        },
        "confirmed": buckets["confirmed"][:200],
        "potential": buckets["potential"][:200],
        "environment_candidates": candidates[:200],
        "insufficient_data": buckets["insufficient_data"][:200],
        "not_affected": not_affected[:200],
        "matched_endpoint_count": len(matches),
        "candidate_endpoint_count": len(rule_assessments),
        "matches": matches[:200],
        "unmatched_indicators": {
            "domain": groups["domain"],
            "hash": groups["hash"],
            "cve": groups["cve"],
        },
        "affected_versions": groups["versions"],
        "capabilities": TANIUM_CAPABILITIES,
    }
    summary = (
        f"확정 {counts['confirmed']}대, 추가 확인 {counts['potential']}대, "
        f"환경 후보 {counts['environment_candidate']}대, 증거 부족 {counts['insufficient_data']}대, "
        f"영향 없음 {counts['not_affected']}대로 분류되었습니다."
    )
    if judge_meta.get("summary_ko"):
        summary = str(judge_meta["summary_ko"])
    elif empty_match_reason:
        summary = empty_match_reason
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
