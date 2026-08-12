"""AI incident analysis.

The layering keeps the model provider replaceable and keeps the analyzer
honest about what it trusts:

``base``      the LLMProvider protocol and its error types
``groq``      the shipped provider, an OpenAI-compatible Groq client
``prompts``   system instructions, and the fencing that keeps case data as data
``analyzer``  gather context -> prompt -> call -> validate -> store

``get_provider()`` is the only thing outside this package that names a
provider; swapping one in is a configuration change.
"""

from functools import lru_cache

from app.core.config import settings
from app.services.ai.analyzer import analyze_incident, gather_context, parse_analysis
from app.services.ai.base import (
    Completion,
    LLMConfigurationError,
    LLMError,
    LLMProvider,
    LLMResponseError,
)
from app.services.ai.groq import GroqProvider

__all__ = [
    "Completion",
    "GroqProvider",
    "LLMConfigurationError",
    "LLMError",
    "LLMProvider",
    "LLMResponseError",
    "analyze_incident",
    "build_provider",
    "gather_context",
    "get_provider",
    "parse_analysis",
    "reset_provider_cache",
]


def build_provider() -> LLMProvider:
    """Construct the configured provider.

    The key is read from its SecretStr here and handed to the provider, which
    is the only place it is held. It is never returned, logged or serialised.
    """
    match settings.LLM_PROVIDER:
        case "groq":
            return GroqProvider(
                model=settings.GROQ_MODEL,
                base_url=settings.GROQ_BASE_URL,
                api_key=(
                    settings.GROQ_API_KEY.get_secret_value()
                    if settings.GROQ_API_KEY
                    else None
                ),
                timeout_seconds=settings.LLM_TIMEOUT_SECONDS,
                max_retries=settings.LLM_MAX_RETRIES,
                max_output_tokens=settings.LLM_MAX_OUTPUT_TOKENS,
                temperature=settings.LLM_TEMPERATURE,
            )
        case unknown:  # pragma: no cover - pydantic constrains the literal
            raise LLMConfigurationError(f"unknown LLM provider {unknown!r}")


@lru_cache(maxsize=1)
def get_provider() -> LLMProvider:
    """The configured provider, built once per process."""
    return build_provider()


def reset_provider_cache() -> None:
    """Forget the cached provider, so a settings change takes effect."""
    get_provider.cache_clear()
