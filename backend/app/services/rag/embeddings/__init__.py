"""Embedding providers, selected by configuration.

``get_provider()`` is the only thing the rest of the platform calls. Swapping
providers is an environment change:

    EMBEDDING_PROVIDER=hashing                 # local, deterministic, default
    EMBEDDING_PROVIDER=http                    # any OpenAI-compatible endpoint
    EMBEDDING_API_BASE_URL=https://api.voyageai.com/v1
    EMBEDDING_MODEL=voyage-3
    EMBEDDING_API_KEY=...
    EMBEDDING_DIMENSIONS=1024                  # must match the model

Changing the model or its dimensionality invalidates the stored corpus --
vectors from two models are not comparable — so a change means re-indexing.
"""

from __future__ import annotations

from functools import lru_cache

from app.core.config import settings
from app.services.rag.embeddings.base import (
    EmbeddingConfigurationError,
    EmbeddingError,
    EmbeddingProvider,
)
from app.services.rag.embeddings.hashing import HashingEmbeddingProvider
from app.services.rag.embeddings.http import HTTPEmbeddingProvider

__all__ = [
    "EmbeddingConfigurationError",
    "EmbeddingError",
    "EmbeddingProvider",
    "HTTPEmbeddingProvider",
    "HashingEmbeddingProvider",
    "get_provider",
    "reset_provider_cache",
]


def build_provider() -> EmbeddingProvider:
    """Construct the configured provider.

    Raises ``EmbeddingConfigurationError`` for a name that does not exist,
    rather than silently falling back -- a typo in EMBEDDING_PROVIDER should
    not quietly downgrade production to local hashing.
    """
    match settings.EMBEDDING_PROVIDER:
        case "hashing":
            return HashingEmbeddingProvider(dimensions=settings.EMBEDDING_DIMENSIONS)
        case "http":
            return HTTPEmbeddingProvider(
                dimensions=settings.EMBEDDING_DIMENSIONS,
                model=settings.EMBEDDING_MODEL,
                base_url=settings.EMBEDDING_API_BASE_URL,
                api_key=settings.EMBEDDING_API_KEY,
                timeout_seconds=settings.EMBEDDING_TIMEOUT_SECONDS,
                max_retries=settings.EMBEDDING_MAX_RETRIES,
            )
        case unknown:  # pragma: no cover - pydantic constrains the literal
            raise EmbeddingConfigurationError(f"unknown embedding provider {unknown!r}")


@lru_cache(maxsize=1)
def get_provider() -> EmbeddingProvider:
    """The configured provider, built once per process."""
    return build_provider()


def reset_provider_cache() -> None:
    """Forget the cached provider, so a settings change takes effect."""
    get_provider.cache_clear()
