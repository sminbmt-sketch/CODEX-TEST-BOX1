from datetime import datetime

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    kind: str
    url: str | None = None
    enabled: bool = True
    trust_score: float


class SourceUpdate(BaseModel):
    name: str | None = None
    kind: str | None = None
    url: str | None = None
    enabled: bool | None = None


class SourceCreate(BaseModel):
    name: str
    kind: str
    url: str
    enabled: bool = True


class DataResetResult(BaseModel):
    target: str
    deleted: dict[str, int]


class ArticleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    url: str
    published_at: datetime | None = None
    summary: str | None = None
    summary_status: str | None = None
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
    summary_status: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_updated_at: datetime | None = None
    epss_checked_at: datetime | None = None
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


class CollectionJobStatus(BaseModel):
    job_id: str
    status: str
    source: str
    start_year: int | None = None
    end_year: int | None = None
    current_year: int | None = None
    mode: str | None = None
    retry_days: int | None = None
    current_batch: int | None = None
    total_batches: int | None = None
    fetched: int = 0
    created_or_updated: int = 0
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


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


class SummarySelectionRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)


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


class AutomationSettingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    enabled: bool = False
    cve_enabled: bool = True
    news_enabled: bool = True
    frequency: Literal["daily", "weekly", "monthly"] = "daily"
    day_of_week: int | None = None
    day_of_month: int | None = None
    run_time: str = "09:00"
    timezone: str = "Asia/Seoul"
    collection_days: int = 7
    last_run_at: datetime | None = None
    updated_at: datetime | None = None


class AutomationSettingUpdate(BaseModel):
    enabled: bool = False
    cve_enabled: bool = True
    news_enabled: bool = True
    frequency: Literal["daily", "weekly", "monthly"] = "daily"
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=31)
    run_time: str = Field(default="09:00", pattern=r"^\d{2}:\d{2}$")
    timezone: str = "Asia/Seoul"
    collection_days: int = Field(default=7, ge=1, le=365)


class EmailSettingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    sender: str | None = None
    recipients: str | None = None
    use_tls: bool = True
    has_password: bool = False
    updated_at: datetime | None = None


class EmailSettingUpdate(BaseModel):
    enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: str | None = None
    clear_password: bool = False
    sender: str | None = None
    recipients: str | None = None
    use_tls: bool = True
