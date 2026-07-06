from datetime import datetime

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    kind: str
    url: str | None = None
    trust_score: float


class ArticleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    url: str
    published_at: datetime | None = None
    summary: str | None = None
    tags: dict | list | None = None
    risk_score: float
    source: SourceOut | None = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    title: str | None = None
    description: str | None = None
    summary: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    epss_score: float | None = None
    kev: bool = False
    vendor: str | None = None
    product: str | None = None
    references: dict | list | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None


class EndpointSnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tanium_endpoint_id: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    platform: str | None = None
    last_seen_at: datetime | None = None


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    match_reason: str
    confidence: float
    status: str
    vulnerability: VulnerabilityOut
    endpoint: EndpointSnapshotOut


class DashboardSummary(BaseModel):
    vulnerability_count: int
    kev_count: int
    article_count: int
    endpoint_count: int
    detection_count: int
    top_risks: list[VulnerabilityOut]
    latest_articles: list[ArticleOut]


class CollectionResult(BaseModel):
    source: str
    fetched: int = 0
    created_or_updated: int = 0
    errors: list[str] = Field(default_factory=list)


class ImpactAnalysisResult(BaseModel):
    endpoints_fetched: int = 0
    endpoints_created_or_updated: int = 0
    detections_created: int = 0
    errors: list[str] = Field(default_factory=list)


class SummaryRunResult(BaseModel):
    target: str
    fetched: int = 0
    summarized: int = 0
    errors: list[str] = Field(default_factory=list)


class TrendNewsItem(BaseModel):
    title: str
    summary: str
    source: str | None = None
    url: str
    published_at: datetime | None = None


class TrendVulnerabilityItem(BaseModel):
    title: str
    summary: str
    cve_id: str
    url: str | None = None
    kev: bool = False
    cvss_score: float | None = None
    epss_score: float | None = None


class TrendReport(BaseModel):
    themes: list[str]
    news: list[TrendNewsItem]
    vulnerabilities: list[TrendVulnerabilityItem]


class TaniumStatus(BaseModel):
    configured: bool
    gateway_url: str | None = None
    message: str


class TaniumGraphQLRequest(BaseModel):
    query: str
    variables: dict | None = None


LlmProvider = Literal["disabled", "ollama", "openai", "gemini", "anthropic"]


class LlmSettingOut(BaseModel):
    provider: LlmProvider
    base_url: str | None = None
    model: str | None = None
    timeout_seconds: int = 180
    max_tokens: int = 512
    has_api_key: bool = False
    source: str = "runtime"


class LlmSettingUpdate(BaseModel):
    provider: LlmProvider
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    clear_api_key: bool = False
    timeout_seconds: int = Field(default=180, ge=30, le=600)
    max_tokens: int = Field(default=512, ge=64, le=4096)


class LlmTestResult(BaseModel):
    ok: bool
    provider: str
    model: str | None = None
    message: str
