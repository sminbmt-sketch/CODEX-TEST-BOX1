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
    summary_error: str | None = None
    summary_error_detail: str | None = None
    tags: dict | list | None = None
    view_count: int | None = None
    risk_score: float
    source: SourceOut | None = None
    created_at: datetime | None = None


class EmailMessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    message_id: str | None = None
    sender: str | None = None
    recipients: str | None = None
    subject: str
    body_excerpt: str | None = None
    received_at: datetime | None = None
    created_at: datetime | None = None


class EmailCollectionRequest(BaseModel):
    sender: str = Field(min_length=1, max_length=255)
    limit: int = Field(default=50, ge=1, le=500)


class EmailCollectionResult(BaseModel):
    fetched: int = 0
    created_or_updated: int = 0
    errors: list[str] = Field(default_factory=list)


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    title: str | None = None
    description: str | None = None
    summary: str | None = None
    summary_status: str | None = None
    summary_error: str | None = None
    summary_error_detail: str | None = None
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
    created_at: datetime | None = None


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
    software: dict | list | None = None
    processes: dict | list | None = None
    services: dict | list | None = None
    hardware: dict | list | None = None
    ports: dict | list | None = None
    sbom: dict | list | None = None
    last_seen_at: datetime | None = None


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    match_reason: str
    confidence: float
    status: str
    vulnerability: VulnerabilityOut
    endpoint: EndpointSnapshotOut


class HotTopicItem(BaseModel):
    keyword: str
    count: int
    article_count: int
    total_views: int = 0
    top_article_title: str | None = None
    top_article_url: str | None = None
    aliases: list[str] = Field(default_factory=list)
    description: str | None = None


class DashboardSummary(BaseModel):
    vulnerability_count: int
    kev_count: int
    article_count: int
    endpoint_count: int
    detection_count: int
    top_risks: list[VulnerabilityOut]
    latest_articles: list[ArticleOut]
    hot_topics: list[HotTopicItem] = Field(default_factory=list)
    hot_topic_brief: str | None = None
    hot_topic_source: str | None = None
    hot_topic_updated_at: datetime | None = None


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


class IntelligenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_type: str
    article_id: int | None = None
    vulnerability_id: int | None = None
    email_id: int | None = None
    title: str
    source_url: str | None = None
    status: str
    intelligence: dict | list | None = None
    extraction_method: str
    error: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class IntelligenceEntityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    intelligence_id: int
    source_type: str
    article_id: int | None = None
    vulnerability_id: int | None = None
    email_id: int | None = None
    entity_type: str
    value: str
    confidence: float
    attributes: dict | list | None = None
    created_at: datetime | None = None


class IntelligenceIocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    intelligence_id: int
    source_type: str
    article_id: int | None = None
    vulnerability_id: int | None = None
    email_id: int | None = None
    ioc_type: str
    value: str
    context: str | None = None
    confidence: float
    attributes: dict | list | None = None
    created_at: datetime | None = None


class InvestigationRequest(BaseModel):
    source_type: Literal["news", "cve", "email"]
    item_id: int
    refresh_intelligence: bool = False


class InvestigationRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    intelligence_id: int
    source_type: str
    source_title: str
    status: str
    query_plan: dict | list | None = None
    results: dict | list | None = None
    summary: str | None = None
    error: str | None = None
    created_at: datetime | None = None


class SummaryRunResult(BaseModel):
    target: str
    fetched: int = 0
    summarized: int = 0
    processed: int = 0
    llm_success: int = 0
    fallback: int = 0
    errors: list[str] = Field(default_factory=list)


class SummarySelectionRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)


class SummaryLogItem(BaseModel):
    target: str
    item_id: int
    title: str
    status: str | None = None
    error: str | None = None
    error_detail: str | None = None
    published_at: datetime | None = None
    source_url: str | None = None
    summary_preview: str | None = None


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


class TaniumSensorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    category: str | None = None
    platform: str | None = None
    parameters: dict | list | None = None
    result_columns: dict | list | None = None
    source: str
    usable: bool
    last_seen_at: datetime | None = None
    updated_at: datetime | None = None


class TaniumSensorSyncResult(BaseModel):
    fetched: int = 0
    created_or_updated: int = 0
    source: str = "unknown"
    errors: list[str] = Field(default_factory=list)


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


class LlmModelList(BaseModel):
    provider: str
    models: list[str] = Field(default_factory=list)


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
    inventory_enabled: bool = False
    inventory_interval_value: int = 1
    inventory_interval_unit: Literal["minutes", "hours", "days"] = "hours"
    inventory_last_run_at: datetime | None = None
    summary_enabled: bool = False
    summary_cve_enabled: bool = True
    summary_news_enabled: bool = True
    summary_run_time: str = "10:00"
    summary_days: int = 7
    summary_last_run_at: datetime | None = None
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
    inventory_enabled: bool = False
    inventory_interval_value: int = Field(default=1, ge=1, le=365)
    inventory_interval_unit: Literal["minutes", "hours", "days"] = "hours"
    summary_enabled: bool = False
    summary_cve_enabled: bool = True
    summary_news_enabled: bool = True
    summary_run_time: str = Field(default="10:00", pattern=r"^\d{2}:\d{2}$")
    summary_days: int = Field(default=7, ge=1, le=365)


class HotTopicSettingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    excluded_keywords: list[str] = Field(default_factory=list)
    llm_enabled: bool = True
    updated_at: datetime | None = None


class HotTopicSettingUpdate(BaseModel):
    excluded_keywords: list[str] = Field(default_factory=list, max_length=300)
    llm_enabled: bool = True


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
