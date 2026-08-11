"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Central settings object. Values come from the environment or a .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---------------------------------------------------
    PROJECT_NAME: str = "AI SOC Analyst"
    ENVIRONMENT: Literal["local", "development", "staging", "production"] = "local"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    # --- Server --------------------------------------------------------
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # --- CORS ----------------------------------------------------------
    # Comma-separated list of allowed origins, e.g. "http://localhost:3000".
    # NoDecode opts out of pydantic-settings' JSON parsing so the validator
    # below sees the raw string.
    BACKEND_CORS_ORIGINS: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000"]
    )

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    # --- PostgreSQL / pgvector ------------------------------------------
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "soc"
    POSTGRES_PASSWORD: str = "soc"
    POSTGRES_DB: str = "soc_analyst"

    # Dimensionality reserved for future pgvector embedding columns.
    EMBEDDING_DIMENSIONS: int = 1536

    @property
    def database_url(self) -> str:
        """Async SQLAlchemy DSN."""
        return str(
            PostgresDsn.build(
                scheme="postgresql+asyncpg",
                username=self.POSTGRES_USER,
                password=self.POSTGRES_PASSWORD,
                host=self.POSTGRES_HOST,
                port=self.POSTGRES_PORT,
                path=self.POSTGRES_DB,
            )
        )

    @property
    def sync_database_url(self) -> str:
        """Synchronous DSN, used by migration tooling."""
        return str(
            PostgresDsn.build(
                scheme="postgresql+psycopg",
                username=self.POSTGRES_USER,
                password=self.POSTGRES_PASSWORD,
                host=self.POSTGRES_HOST,
                port=self.POSTGRES_PORT,
                path=self.POSTGRES_DB,
            )
        )

    # --- Redis ----------------------------------------------------------
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None

    @field_validator("REDIS_PASSWORD", mode="before")
    @classmethod
    def _blank_password_is_none(cls, value: object) -> object:
        # An unset `REDIS_PASSWORD=` in a .env file arrives as an empty string.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def redis_url(self) -> str:
        return str(
            RedisDsn.build(
                scheme="redis",
                password=self.REDIS_PASSWORD,
                host=self.REDIS_HOST,
                port=self.REDIS_PORT,
                path=str(self.REDIS_DB),
            )
        )


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor so the environment is parsed once per process."""
    return Settings()


settings = get_settings()
