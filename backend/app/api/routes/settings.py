from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.db.models import Article, AuditLog, Detection, EndpointSnapshot, LlmSetting, Source, Vulnerability
from app.db.session import get_db
from app.schemas import DataResetResult, LlmSettingOut, LlmSettingUpdate, LlmTestResult, SourceCreate, SourceOut, SourceUpdate
from app.services.news_sources import DEFAULT_HTML_SOURCES, DEFAULT_NEWS_FEEDS
from app.services.llm import LlmRuntimeConfig, SummaryService, default_base_url, default_model, get_llm_setting, resolve_llm_config, sanitize_llm_error
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


@router.get("/llm", response_model=LlmSettingOut)
def get_llm_settings(db: Session = Depends(get_db)) -> LlmSettingOut:
    return _out(get_llm_setting(db))


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
