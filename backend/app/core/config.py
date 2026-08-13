"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Annotated, Literal, Self

from pydantic import (
    Field,
    PostgresDsn,
    RedisDsn,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Placeholder shipped in .env.example. Refused outside local development so a
# deployment can never sign tokens with a publicly known key.
INSECURE_SECRET_KEY = "change-me-generate-with-openssl-rand-hex-32"
MIN_SECRET_KEY_LENGTH = 32


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

    # --- Authentication --------------------------------------------------
    # Signing key for access tokens. Override in every deployed environment.
    SECRET_KEY: str = INSECURE_SECRET_KEY
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=1440)
    JWT_ISSUER: str = "soc-analyst"

    # Logout revokes a token by storing its jti in Redis until it would have
    # expired. Disable only if Redis is unavailable and audit-only logout is
    # acceptable -- tokens then remain valid until they expire on their own.
    AUTH_TOKEN_DENYLIST_ENABLED: bool = True

    # Rejected at registration; also the floor for any password change.
    MIN_PASSWORD_LENGTH: int = Field(default=12, ge=8)

    # --- Rate limiting ---------------------------------------------------
    # Counters live in Redis. Disable only for a deployment that throttles at
    # the edge instead; without either, credential guessing is unbounded.
    RATE_LIMIT_ENABLED: bool = True

    # Login is the expensive, attackable endpoint: each attempt costs an Argon2
    # verification, and success grants a session. Limited per source address
    # and, separately, per account.
    RATE_LIMIT_LOGIN_ATTEMPTS: int = Field(default=10, ge=1, le=1000)
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = Field(default=300, ge=1, le=86_400)

    # Registration is open, so it is also a way to fill the user table.
    RATE_LIMIT_REGISTER_ATTEMPTS: int = Field(default=5, ge=1, le=1000)
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: int = Field(default=3600, ge=1, le=86_400)

    # Generating a report spends money and third-party quota, so it is limited
    # per analyst rather than per address.
    RATE_LIMIT_ANALYZE_REQUESTS: int = Field(default=20, ge=1, le=1000)
    RATE_LIMIT_ANALYZE_WINDOW_SECONDS: int = Field(default=3600, ge=1, le=86_400)

    # A backstop for authenticated traffic generally, generous enough that
    # normal console use never reaches it.
    RATE_LIMIT_DEFAULT_REQUESTS: int = Field(default=300, ge=1, le=100_000)
    RATE_LIMIT_DEFAULT_WINDOW_SECONDS: int = Field(default=60, ge=1, le=86_400)

    # Set only where a trusted proxy or load balancer terminates the connection
    # and sets X-Forwarded-For. Left false, the header is ignored, because a
    # client that can forge it can hand itself an unlimited quota.
    TRUST_PROXY_HEADERS: bool = False

    @model_validator(mode="after")
    def _reject_insecure_secret_key(self) -> Self:
        if self.ENVIRONMENT == "local":
            return self
        if self.SECRET_KEY == INSECURE_SECRET_KEY:
            raise ValueError(
                f"SECRET_KEY must be set to a generated value when ENVIRONMENT="
                f"{self.ENVIRONMENT!r}. Generate one with: openssl rand -hex 32"
            )
        if len(self.SECRET_KEY) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters "
                f"when ENVIRONMENT={self.ENVIRONMENT!r}."
            )
        return self

    # --- Log ingestion ---------------------------------------------------
    # Uploads are read fully into memory before parsing, so this bound is also
    # what stops one request from exhausting the process.
    MAX_UPLOAD_BYTES: int = Field(default=10 * 1024 * 1024, ge=1024)
    # Rows per INSERT. Large enough to amortise round trips, small enough that a
    # single statement stays well inside PostgreSQL's parameter limit.
    INGEST_BATCH_SIZE: int = Field(default=500, ge=1, le=5000)
    # Per-row failures kept on the job record. A file of entirely bad rows must
    # not write an unbounded JSON column.
    INGEST_MAX_REPORTED_ERRORS: int = Field(default=100, ge=1, le=1000)

    # --- AI incident analysis --------------------------------------------
    # The provider is selected here so it can be swapped without touching the
    # analyzer. "groq" is the shipped integration.
    LLM_PROVIDER: Literal["groq"] = "groq"
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    # SecretStr, so the key is masked in tracebacks, logging of the settings
    # object, and anything that reprs configuration. Reading it requires an
    # explicit .get_secret_value(), which is easy to audit for.
    GROQ_API_KEY: SecretStr | None = None
    LLM_TIMEOUT_SECONDS: float = Field(default=60.0, gt=0, le=600)
    LLM_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    LLM_MAX_OUTPUT_TOKENS: int = Field(default=2048, ge=256, le=32_000)
    # Low temperature: an incident report is an analysis, not a creative brief,
    # and reproducibility matters when two analysts compare notes.
    LLM_TEMPERATURE: float = Field(default=0.2, ge=0.0, le=2.0)

    # Bounds on what is packed into a prompt. Untrusted content is truncated
    # rather than trusted to be small: a single 10 MB log line should not be
    # able to push the real instructions out of the context window.
    AI_MAX_ANOMALIES: int = Field(default=20, ge=1, le=200)
    AI_MAX_LOG_ENTRIES: int = Field(default=40, ge=1, le=500)
    AI_MAX_FIELD_CHARS: int = Field(default=2000, ge=100, le=50_000)
    AI_KNOWLEDGE_TOP_K: int = Field(default=4, ge=0, le=20)

    @field_validator("GROQ_API_KEY", mode="before")
    @classmethod
    def _blank_api_key_is_none(cls, value: object) -> object:
        # An unset `GROQ_API_KEY=` in a .env file arrives as an empty string.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    # --- Knowledge base / RAG --------------------------------------------
    # Which embedding provider to use. "hashing" is deterministic and local:
    # no API key, no network, and reproducible across runs, which makes it the
    # right default for development and the whole test suite. "http" talks to
    # any OpenAI-compatible /embeddings endpoint (OpenAI, Voyage, a local
    # llama.cpp or Ollama server) selected by EMBEDDING_API_BASE_URL.
    EMBEDDING_PROVIDER: Literal["hashing", "http"] = "hashing"
    EMBEDDING_MODEL: str = "hashing-v1"
    EMBEDDING_API_BASE_URL: str = "https://api.openai.com/v1"
    EMBEDDING_API_KEY: str | None = None
    EMBEDDING_TIMEOUT_SECONDS: float = Field(default=30.0, gt=0, le=300)
    EMBEDDING_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    # Texts per provider call. Providers charge and rate-limit per request, so
    # batching matters; too large a batch risks the provider's own body limit.
    EMBEDDING_BATCH_SIZE: int = Field(default=32, ge=1, le=512)

    # Chunking. Characters, not tokens: the platform has no tokenizer for an
    # arbitrary provider's model, and a character budget is a predictable
    # proxy that never under-counts.
    RAG_CHUNK_SIZE: int = Field(default=1200, ge=100, le=20_000)
    RAG_CHUNK_OVERLAP: int = Field(default=200, ge=0, le=10_000)
    RAG_TOP_K: int = Field(default=5, ge=1, le=50)
    # Cosine similarity below this is not worth returning; retrieval that
    # answers every query with something is retrieval that cannot say
    # "nothing here is relevant".
    RAG_MIN_SIMILARITY: float = Field(default=0.05, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_chunk_overlap(self) -> Self:
        if self.RAG_CHUNK_OVERLAP >= self.RAG_CHUNK_SIZE:
            raise ValueError(
                "RAG_CHUNK_OVERLAP must be smaller than RAG_CHUNK_SIZE; an overlap "
                "at or above the chunk size never advances and would loop forever."
            )
        return self

    # --- Anomaly detection -----------------------------------------------
    # Default span analysed when a request does not give one.
    DETECTION_WINDOW_HOURS: int = Field(default=24, ge=1, le=720)
    # Detectors hold their input in memory, so the window has to be bounded.
    DETECTION_MAX_ENTRIES: int = Field(default=50_000, ge=100, le=1_000_000)

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
