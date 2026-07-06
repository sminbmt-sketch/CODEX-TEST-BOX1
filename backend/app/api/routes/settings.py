from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import LlmSetting
from app.db.session import get_db
from app.schemas import LlmSettingOut, LlmSettingUpdate, LlmTestResult
from app.services.llm import LlmRuntimeConfig, SummaryService, default_base_url, default_model, get_llm_setting, resolve_llm_config, sanitize_llm_error

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
