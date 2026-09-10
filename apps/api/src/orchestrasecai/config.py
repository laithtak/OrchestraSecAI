from enum import Enum
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class AppEnvironment(str, Enum):
    development = "development"
    test = "test"
    production = "production"


class ProductionConfigurationError(RuntimeError):
    """Raised when production is configured with known unsafe values."""


_DEVELOPMENT_JWT_SECRETS = {
    "change-me",
    "change-me-in-production-use-openssl-rand-hex-32",
}
_DEVELOPMENT_DATABASE_USERNAME = "orchestrasec"
_DEVELOPMENT_DATABASE_PASSWORD = "orchestrasec"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_env: AppEnvironment = AppEnvironment.development

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

    agent_max_iterations: int = 10
    agent_max_tools_per_plan: int = 8
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json"
    nvd_api_key: str = ""

    seed_admin_email: str = "admin@orchestrasec.local"
    seed_admin_password: str = "changeme123"
    seed_enabled: bool = True

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


def _uses_development_database_credentials(value: str) -> bool:
    try:
        url = make_url(value)
    except ArgumentError:
        return False
    return (
        url.username == _DEVELOPMENT_DATABASE_USERNAME
        and url.password == _DEVELOPMENT_DATABASE_PASSWORD
    )


def validate_production_safety(settings: Settings) -> None:
    """Validate deterministic security invariants for a production process."""
    if settings.app_env is not AppEnvironment.production:
        return

    violations: list[str] = []
    jwt_secret_bytes = len(settings.jwt_secret.encode("utf-8"))
    if settings.jwt_secret in _DEVELOPMENT_JWT_SECRETS or jwt_secret_bytes < 32:
        violations.append(
            "JWT_SECRET must be a non-placeholder secret of at least 32 bytes in production."
        )
    if _uses_development_database_credentials(settings.database_url):
        violations.append(
            "DATABASE_URL must not use the documented development database credentials "
            "in production."
        )
    if _uses_development_database_credentials(settings.database_url_sync):
        violations.append(
            "DATABASE_URL_SYNC must not use the documented development database credentials "
            "in production."
        )
    if settings.seed_enabled:
        violations.append("SEED_ENABLED must be false in production.")
    if settings.mock_ai:
        violations.append("MOCK_AI must be false in production.")
    if "*" in settings.cors_origin_list:
        violations.append("CORS_ORIGINS must not contain '*' in production.")
    if settings.rate_limit_fail_open:
        violations.append("RATE_LIMIT_FAIL_OPEN must be false in production.")

    if violations:
        details = "\n".join(f"- {message}" for message in violations)
        raise ProductionConfigurationError(f"Production configuration invalid:\n{details}")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    validate_production_safety(settings)
    return settings
