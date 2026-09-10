import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from orchestrasecai.config import (
    AppEnvironment,
    ProductionConfigurationError,
    Settings,
    validate_production_safety,
)

SAFE_PRODUCTION_VALUES = {
    "app_env": AppEnvironment.production,
    "database_url": "postgresql+asyncpg://production_user:production_password@db/prod",
    "database_url_sync": "postgresql://production_user:production_password@db/prod",
    "jwt_secret": "a-secure-production-signing-secret-32-bytes",
    "seed_enabled": False,
    "mock_ai": False,
    "cors_origins": "https://app.example.com,https://admin.example.com",
    "rate_limit_fail_open": False,
}


def production_settings(**overrides) -> Settings:
    values = {**SAFE_PRODUCTION_VALUES, **overrides}
    return Settings(_env_file=None, **values)


@pytest.mark.parametrize("app_env", ["development", "test", "production"])
def test_supported_application_environments_parse(app_env):
    settings = Settings(_env_file=None, app_env=app_env)

    assert settings.app_env.value == app_env


def test_unknown_application_environment_is_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="prod")


@pytest.mark.parametrize("app_env", [AppEnvironment.development, AppEnvironment.test])
def test_development_defaults_are_allowed_outside_production(app_env):
    settings = Settings(_env_file=None, app_env=app_env)

    validate_production_safety(settings)


def test_valid_production_configuration_is_allowed():
    validate_production_safety(production_settings())


@pytest.mark.parametrize(
    "jwt_secret",
    [
        "",
        "too-short",
        "change-me",
        "change-me-in-production-use-openssl-rand-hex-32",
    ],
)
def test_production_rejects_unsafe_jwt_secrets(jwt_secret):
    settings = production_settings(jwt_secret=jwt_secret)

    with pytest.raises(ProductionConfigurationError, match="JWT_SECRET"):
        validate_production_safety(settings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "database_url",
            "postgresql+asyncpg://orchestrasec:orchestrasec@database.example/prod",
        ),
        (
            "database_url_sync",
            "postgresql://orchestrasec:orchestrasec@database.example/prod",
        ),
    ],
)
def test_production_rejects_published_database_credentials(field, value):
    settings = production_settings(**{field: value})

    with pytest.raises(ProductionConfigurationError, match=field.upper()):
        validate_production_safety(settings)


def test_production_rejects_enabled_seed_data():
    settings = production_settings(seed_enabled=True)

    with pytest.raises(ProductionConfigurationError, match="SEED_ENABLED"):
        validate_production_safety(settings)


def test_production_rejects_mock_ai():
    settings = production_settings(mock_ai=True)

    with pytest.raises(ProductionConfigurationError, match="MOCK_AI"):
        validate_production_safety(settings)


@pytest.mark.parametrize("cors_origins", ["*", "https://app.example.com, *", " *, "])
def test_production_rejects_wildcard_cors(cors_origins):
    settings = production_settings(cors_origins=cors_origins)

    with pytest.raises(ProductionConfigurationError, match="CORS_ORIGINS"):
        validate_production_safety(settings)


def test_production_rejects_fail_open_rate_limiting():
    settings = production_settings(rate_limit_fail_open=True)

    with pytest.raises(ProductionConfigurationError, match="RATE_LIMIT_FAIL_OPEN"):
        validate_production_safety(settings)


def test_production_reports_all_violations_together():
    settings = Settings(_env_file=None, app_env=AppEnvironment.production, cors_origins="*")

    with pytest.raises(ProductionConfigurationError) as exc_info:
        validate_production_safety(settings)

    message = str(exc_info.value)
    assert message.startswith("Production configuration invalid:")
    for field in (
        "JWT_SECRET",
        "DATABASE_URL",
        "DATABASE_URL_SYNC",
        "SEED_ENABLED",
        "MOCK_AI",
        "CORS_ORIGINS",
        "RATE_LIMIT_FAIL_OPEN",
    ):
        assert field in message


def test_production_error_does_not_expose_secret_values():
    secret = "do-not-leak"
    settings = production_settings(jwt_secret=secret)

    with pytest.raises(ProductionConfigurationError) as exc_info:
        validate_production_safety(settings)

    assert secret not in str(exc_info.value)


def _subprocess_environment() -> dict[str, str]:
    api_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.update(
        {
            "APP_ENV": "production",
            "DATABASE_URL": SAFE_PRODUCTION_VALUES["database_url"],
            "DATABASE_URL_SYNC": SAFE_PRODUCTION_VALUES["database_url_sync"],
            "JWT_SECRET": SAFE_PRODUCTION_VALUES["jwt_secret"],
            "SEED_ENABLED": "false",
            "MOCK_AI": "false",
            "CORS_ORIGINS": SAFE_PRODUCTION_VALUES["cors_origins"],
            "RATE_LIMIT_FAIL_OPEN": "false",
            "PYTHONPATH": os.pathsep.join(
                filter(None, [str(api_root / "src"), env.get("PYTHONPATH", "")])
            ),
        }
    )
    return env


@pytest.mark.parametrize(
    "module_name",
    ["orchestrasecai.main", "orchestrasecai.workers.settings"],
)
def test_api_and_worker_reject_same_unsafe_production_configuration(module_name, tmp_path):
    env = _subprocess_environment()
    env["MOCK_AI"] = "true"

    result = subprocess.run(
        [sys.executable, "-c", f"import {module_name}"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    combined = result.stderr + result.stdout

    assert result.returncode != 0
    assert "Production configuration invalid:" in combined
    assert "MOCK_AI must be false in production." in combined
    assert SAFE_PRODUCTION_VALUES["jwt_secret"] not in combined


@pytest.mark.parametrize(
    "module_name",
    ["orchestrasecai.main", "orchestrasecai.workers.settings"],
)
def test_api_and_worker_accept_valid_production_configuration(module_name, tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module_name}"],
        cwd=tmp_path,
        env=_subprocess_environment(),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
