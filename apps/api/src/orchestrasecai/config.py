from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+asyncpg://orchestrasec:orchestrasec@localhost:5432/orchestrasecai"
    database_url_sync: str = "postgresql://orchestrasec:orchestrasec@localhost:5432/orchestrasecai"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "change-me"
    jwt_access_expire_minutes: int = 15
    jwt_refresh_expire_days: int = 7

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:3000"

    worker_concurrency: int = 2
    scan_global_timeout_seconds: int = 1800

    vllm_base_url: str = "http://localhost:8000/v1"
    vllm_model: str = "meta-llama/Llama-3.1-8B-Instruct"
    mock_ai: bool = True
    qdrant_enabled: bool = False
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""

    multi_tenant_enabled: bool = False

    rate_limit_requests_per_minute: int = 120
    rate_limit_scans_per_day: int = 50
    rate_limit_fail_open: bool = True

    log_level: str = "INFO"
    sentry_dsn: str = ""
    sentry_environment: str = "development"
    otel_enabled: bool = True
    otel_service_name_api: str = "orchestrasecai-api"
    otel_service_name_worker: str = "orchestrasecai-worker"
    otel_exporter_otlp_endpoint: str = ""
    trusted_proxy_depth: int = 0

    seed_admin_email: str = "admin@orchestrasec.local"
    seed_admin_password: str = "changeme123"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
