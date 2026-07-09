import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.db.models import Article, AuditLog, AutomationSetting, Detection, EmailSetting, EndpointSnapshot, LlmSetting, Source, Vulnerability
from app.db.session import get_db
from app.schemas import (
    AutomationSettingOut,
    AutomationSettingUpdate,
    DataResetResult,
    EmailSettingOut,
    EmailSettingUpdate,
    LlmSettingOut,
    LlmSettingUpdate,
    LlmModelList,
    LlmTestResult,
    SourceCreate,
    SourceOut,
    SourceUpdate,
)
from app.services.news_sources import DEFAULT_HTML_SOURCES, DEFAULT_NEWS_FEEDS
from app.services.llm import LlmRuntimeConfig, SummaryService, default_base_url, default_model, get_llm_setting, ollama_root_url, resolve_llm_config, sanitize_llm_error
from app.services.vulnerability_sources import CISA_KEV_URL, EPSS_URL, NVD_CVE_URL, NVD_DATA_FEEDS_URL

router = APIRouter(prefix="/settings", tags=["settings"])


MODEL_ALIASES = {
    "gemini 3.1 flash lite": "gemini-3.1-flash-lite",
    "gemini 3.1 flash-lite": "gemini-3.1-flash-lite",
    "gemini-3.1-flash lite": "gemini-3.1-flash-lite",
}


def normalize_model(provider: str, model: str | None) -> str:
    value = (model or default_model(provider)).strip()
    if provider == "gemini":
        return MODEL_ALIASES.get(value.lower(), value)
    return value


def ensure_default_sources(db: Session) -> None:
    defaults = [
        ("NVD", NVD_CVE_URL, "vulnerability"),
        ("NVD JSON Feeds", NVD_DATA_FEEDS_URL, "vulnerability"),
        ("CISA KEV", CISA_KEV_URL, "vulnerability"),
        ("FIRST EPSS", EPSS_URL, "vulnerability"),
        *DEFAULT_NEWS_FEEDS,
        *DEFAULT_HTML_SOURCES,
    ]
    for name, url, kind in defaults:
        deleted = db.scalar(select(AuditLog.id).where(AuditLog.action == "source_deleted", AuditLog.target == name))
        if deleted is not None:
            continue
        source = db.scalar(select(Source).where(Source.name == name))
        if source is None:
            db.add(Source(name=name, url=url, kind=kind, license_note="Store metadata, source URL, and generated summaries only.", trust_score=0.7))
        elif source.url is None:
            source.url = url
    db.commit()


def _out(setting: LlmSetting | None) -> LlmSettingOut:
    config = resolve_llm_config()
    if setting is not None:
        config = resolve_llm_config_from_row(setting)
    return LlmSettingOut(
        provider=config.provider,
        base_url=config.base_url,
        model=config.model,
        timeout_seconds=config.timeout_seconds,
        max_tokens=config.max_tokens,
        has_api_key=bool(config.api_key),
        source="database" if setting is not None else "environment",
    )


def resolve_llm_config_from_row(setting: LlmSetting):
    provider = setting.provider or "disabled"
    return LlmRuntimeConfig(
        provider=provider,
        base_url=setting.base_url or default_base_url(provider),
        model=normalize_model(provider, setting.model),
        api_key=setting.api_key,
        timeout_seconds=setting.timeout_seconds,
        max_tokens=setting.max_tokens,
    )


def resolve_llm_config_from_payload(payload: LlmSettingUpdate, saved: LlmSetting | None) -> LlmRuntimeConfig:
    saved_key = saved.api_key if saved is not None and not payload.clear_api_key else None
    api_key = payload.api_key or saved_key
    return LlmRuntimeConfig(
        provider=payload.provider,
        base_url=payload.base_url or default_base_url(payload.provider),
        model=normalize_model(payload.provider, payload.model),
        api_key=api_key,
        timeout_seconds=payload.timeout_seconds,
        max_tokens=payload.max_tokens,
    )


async def fetch_llm_models(config: LlmRuntimeConfig) -> list[str]:
    if config.provider == "disabled":
        return []
    if config.provider == "ollama":
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(f"{ollama_root_url(config.base_url)}/api/tags")
            response.raise_for_status()
            data = response.json()
            return sorted(
                model.get("name")
                for model in data.get("models", [])
                if model.get("name") and "completion" in (model.get("capabilities") or ["completion"])
            )
    if config.provider == "openai":
        headers = {"Authorization": f"Bearer {config.api_key}"} if config.api_key else {}
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(f"{config.base_url.rstrip('/')}/models", headers=headers)
            response.raise_for_status()
            data = response.json()
            return sorted(model.get("id") for model in data.get("data", []) if model.get("id"))
    if config.provider == "gemini":
        params = {"key": config.api_key} if config.api_key else None
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(f"{config.base_url.rstrip('/')}/models", params=params)
            response.raise_for_status()
            data = response.json()
            return sorted((model.get("name") or "").replace("models/", "") for model in data.get("models", []) if model.get("name"))
    if config.provider == "anthropic":
        return ["claude-3-5-haiku-latest", "claude-3-5-sonnet-latest", "claude-3-7-sonnet-latest"]
    return []


def get_automation_row(db: Session) -> AutomationSetting:
    row = db.scalar(select(AutomationSetting).order_by(AutomationSetting.id.asc()))
    if row is None:
        row = AutomationSetting()
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def get_email_row(db: Session) -> EmailSetting:
    row = db.scalar(select(EmailSetting).order_by(EmailSetting.id.asc()))
    if row is None:
        row = EmailSetting()
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def email_out(row: EmailSetting) -> EmailSettingOut:
    return EmailSettingOut(
        enabled=row.enabled,
        smtp_host=row.smtp_host,
        smtp_port=row.smtp_port,
        smtp_username=row.smtp_username,
        sender=row.sender,
        recipients=row.recipients,
        use_tls=row.use_tls,
        has_password=bool(row.smtp_password),
        updated_at=row.updated_at,
    )


@router.get("/llm", response_model=LlmSettingOut)
def get_llm_settings(db: Session = Depends(get_db)) -> LlmSettingOut:
    return _out(get_llm_setting(db))


@router.post("/llm/models", response_model=LlmModelList)
async def list_llm_models(
    payload: LlmSettingUpdate | None = Body(default=None),
    db: Session = Depends(get_db),
) -> LlmModelList:
    config = resolve_llm_config_from_payload(payload, get_llm_setting(db)) if payload is not None else resolve_llm_config(db)
    try:
        models = await fetch_llm_models(config)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM model list failed: {sanitize_llm_error(exc)}") from exc
    return LlmModelList(provider=config.provider, models=models)


@router.get("/automation", response_model=AutomationSettingOut)
def get_automation_settings(db: Session = Depends(get_db)) -> AutomationSettingOut:
    return AutomationSettingOut.model_validate(get_automation_row(db))


@router.put("/automation", response_model=AutomationSettingOut)
def update_automation_settings(payload: AutomationSettingUpdate, db: Session = Depends(get_db)) -> AutomationSettingOut:
    row = get_automation_row(db)
    row.enabled = payload.enabled
    row.cve_enabled = payload.cve_enabled
    row.news_enabled = payload.news_enabled
    row.frequency = payload.frequency
    row.day_of_week = payload.day_of_week
    row.day_of_month = payload.day_of_month
    row.run_time = payload.run_time
    row.timezone = payload.timezone
    row.collection_days = payload.collection_days
    db.commit()
    db.refresh(row)
    return AutomationSettingOut.model_validate(row)


@router.get("/email", response_model=EmailSettingOut)
def get_email_settings(db: Session = Depends(get_db)) -> EmailSettingOut:
    return email_out(get_email_row(db))


@router.put("/email", response_model=EmailSettingOut)
def update_email_settings(payload: EmailSettingUpdate, db: Session = Depends(get_db)) -> EmailSettingOut:
    row = get_email_row(db)
    row.enabled = payload.enabled
    row.smtp_host = payload.smtp_host
    row.smtp_port = payload.smtp_port
    row.smtp_username = payload.smtp_username
    row.sender = payload.sender
    row.recipients = payload.recipients
    row.use_tls = payload.use_tls
    if payload.clear_password:
        row.smtp_password = None
    elif payload.smtp_password:
        row.smtp_password = payload.smtp_password
    db.commit()
    db.refresh(row)
    return email_out(row)


@router.get("/sources", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db)) -> list[SourceOut]:
    ensure_default_sources(db)
    rows = db.scalars(select(Source).order_by(Source.kind.asc(), Source.name.asc())).all()
    return [SourceOut.model_validate(row) for row in rows]


@router.post("/sources", response_model=SourceOut)
def create_source(payload: SourceCreate, db: Session = Depends(get_db)) -> SourceOut:
    name = payload.name.strip()
    kind = payload.kind.strip()
    url = payload.url.strip()
    if not name or not kind or not url:
        raise HTTPException(status_code=400, detail="Source name, kind, and URL are required")
    source = Source(
        name=name,
        kind=kind,
        url=url,
        enabled=payload.enabled,
        license_note="Store metadata, source URL, and generated summaries only.",
        trust_score=0.7,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return SourceOut.model_validate(source)


@router.put("/sources/{source_id}", response_model=SourceOut)
def update_source(source_id: int, payload: SourceUpdate, db: Session = Depends(get_db)) -> SourceOut:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    if payload.name is not None:
        source.name = payload.name
    if payload.kind is not None:
        source.kind = payload.kind
    if payload.url is not None:
        source.url = payload.url
    if payload.enabled is not None:
        source.enabled = payload.enabled
    db.commit()
    db.refresh(source)
    return SourceOut.model_validate(source)


@router.delete("/sources/{source_id}", response_model=SourceOut)
def delete_source(source_id: int, db: Session = Depends(get_db)) -> SourceOut:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    output = SourceOut.model_validate(source)
    db.execute(update(Article).where(Article.source_id == source_id).values(source_id=None))
    db.add(AuditLog(action="source_deleted", target=source.name, detail={"kind": source.kind, "url": source.url}))
    db.delete(source)
    db.commit()
    return output


def _delete_count(db: Session, statement) -> int:
    result = db.execute(statement)
    return int(result.rowcount or 0)


@router.delete("/data/{target}", response_model=DataResetResult)
def reset_data(target: str, db: Session = Depends(get_db)) -> DataResetResult:
    if target not in {"all", "cves", "news", "inventory"}:
        raise HTTPException(status_code=400, detail="target must be one of: all, cves, news, inventory")

    deleted: dict[str, int] = {}
    if target in {"all", "cves"}:
        deleted["detections"] = _delete_count(db, delete(Detection))
        deleted["vulnerabilities"] = _delete_count(db, delete(Vulnerability))
    if target in {"all", "news"}:
        deleted["articles"] = _delete_count(db, delete(Article))
    if target in {"all", "inventory"}:
        if target == "inventory":
            deleted["detections"] = _delete_count(db, delete(Detection))
        deleted["endpoint_snapshots"] = _delete_count(db, delete(EndpointSnapshot))

    db.add(AuditLog(action="data_reset", target=target, detail=deleted))
    db.commit()
    return DataResetResult(target=target, deleted=deleted)


@router.put("/llm", response_model=LlmSettingOut)
def update_llm_settings(payload: LlmSettingUpdate, db: Session = Depends(get_db)) -> LlmSettingOut:
    row = get_llm_setting(db)
    if row is None:
        row = LlmSetting()
        db.add(row)

    row.provider = payload.provider
    row.base_url = payload.base_url or default_base_url(payload.provider)
    row.model = normalize_model(payload.provider, payload.model)
    row.timeout_seconds = payload.timeout_seconds
    row.max_tokens = payload.max_tokens

    if payload.clear_api_key:
        row.api_key = None
    elif payload.api_key:
        row.api_key = payload.api_key

    db.commit()
    db.refresh(row)
    return _out(row)


@router.post("/llm/test", response_model=LlmTestResult)
async def test_llm_settings(
    payload: LlmSettingUpdate | None = Body(default=None),
    db: Session = Depends(get_db),
) -> LlmTestResult:
    config = resolve_llm_config_from_payload(payload, get_llm_setting(db)) if payload is not None else resolve_llm_config(db)
    if config.provider == "disabled":
        return LlmTestResult(ok=False, provider=config.provider, model=config.model, message="LLM provider is disabled.")
    try:
        content = await SummaryService(config).summarize(
            "LLM 연결 테스트",
            "This is a short security dashboard LLM connection test. Reply in Korean with one short sentence.",
            [],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM test failed: {sanitize_llm_error(exc)}") from exc
    if not content:
        return LlmTestResult(ok=False, provider=config.provider, model=config.model, message="No response from provider.")
    return LlmTestResult(ok=True, provider=config.provider, model=config.model, message=content[:300])
