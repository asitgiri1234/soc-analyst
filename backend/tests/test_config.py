"""Settings parsing behaviour that is easy to break."""

from app.core.config import Settings


def _settings(**overrides: object) -> Settings:
    # _env_file=None isolates the test from any local .env.
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def test_cors_origins_accept_comma_separated_string() -> None:
    settings = _settings(BACKEND_CORS_ORIGINS="http://a.test, http://b.test")
    assert settings.BACKEND_CORS_ORIGINS == ["http://a.test", "http://b.test"]


def test_blank_redis_password_becomes_none() -> None:
    assert _settings(REDIS_PASSWORD="").REDIS_PASSWORD is None


def test_database_urls_use_expected_drivers() -> None:
    settings = _settings()
    assert settings.database_url.startswith("postgresql+asyncpg://")
    assert settings.sync_database_url.startswith("postgresql+psycopg://")


def test_redis_url_includes_database_index() -> None:
    assert _settings(REDIS_DB=3).redis_url.endswith("/3")
