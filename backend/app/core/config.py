from functools import cached_property

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    app_name: str = "SecureWatch MVP"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    database_url: str = "sqlite:///./securewatch.db"

    nvd_api_key: str | None = None
    github_token: str | None = None

    tanium_base_url: AnyHttpUrl | None = None
    tanium_api_token: str | None = None
    tanium_gateway_path: str = "/plugin/products/gateway/graphql"
    tanium_verify_tls: bool = False
    tanium_timeout_seconds: int = Field(default=30, ge=5, le=180)

    llm_provider: str = "disabled"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "qwen3:8b"
    llm_api_key: str | None = None

    @cached_property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @cached_property
    def tanium_gateway_url(self) -> str | None:
        if self.tanium_base_url is None:
            return None
        base = str(self.tanium_base_url).rstrip("/")
        path = self.tanium_gateway_path if self.tanium_gateway_path.startswith("/") else f"/{self.tanium_gateway_path}"
        return f"{base}{path}"


settings = Settings()
