"""Embeddings from an HTTP service.

Speaks the ``POST /embeddings`` shape that most hosted embedding services
expose -- ``{"model": ..., "input": [...]}`` in, ``{"data": [{"embedding":
[...]}]}`` out. Because the base URL is configuration, one implementation
covers OpenAI, Voyage, Azure OpenAI, and a local llama.cpp or Ollama server
without a code change.

Anthropic does not offer an embeddings endpoint, so there is deliberately no
Claude-backed provider here; Claude's role in this platform starts with the
analysis phase, not with retrieval.

Failures are handled rather than propagated raw: transient statuses are retried
with backoff, and everything that is still broken afterwards becomes an
``EmbeddingError`` the API layer turns into a 503. A missing API key is
reported separately, because no amount of retrying will supply one.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import httpx

from app.core.logging import get_logger
from app.services.rag.embeddings.base import EmbeddingConfigurationError, EmbeddingError

logger = get_logger(__name__)

# Statuses worth retrying: rate limiting and the transient 5xx family. A 400 or
# 401 means the request or the credential is wrong, and repeating it wastes
# time and quota.
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class HTTPEmbeddingProvider:
    """Calls an OpenAI-compatible embeddings endpoint."""

    dimensions: int
    model: str
    base_url: str
    api_key: str | None = None
    timeout_seconds: float = 30.0
    max_retries: int = 2
    name: str = "http"
    # Injectable so tests can drive the provider without a live service.
    client_factory: object | None = field(default=None, compare=False)

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        if not self.api_key:
            raise EmbeddingConfigurationError(
                "EMBEDDING_API_KEY is not set; the http embedding provider cannot "
                "authenticate. Set it, or use EMBEDDING_PROVIDER=hashing."
            )

        payload = {"model": self.model, "input": list(texts)}
        data = await self._post(payload)
        vectors = self._parse(data, expected=len(texts))
        return vectors

    async def embed_query(self, text: str) -> list[float]:
        vectors = await self.embed([text])
        return vectors[0]

    def _client(self) -> httpx.AsyncClient:
        if self.client_factory is not None:
            return self.client_factory()  # type: ignore[operator]
        headers = {"Authorization": f"Bearer {self.api_key}"}
        return httpx.AsyncClient(
            base_url=self.base_url, headers=headers, timeout=self.timeout_seconds
        )

    async def _post(self, payload: Mapping[str, object]) -> dict[str, object]:
        """POST with bounded retries, converting every failure into EmbeddingError."""
        last_error: str = "no attempt was made"

        async with self._client() as client:
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.post("/embeddings", json=payload)
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                else:
                    if response.status_code == 200:
                        try:
                            return response.json()
                        except ValueError as exc:
                            raise EmbeddingError(
                                f"embedding provider returned a non-JSON body: {exc}"
                            ) from exc

                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    if response.status_code not in RETRYABLE_STATUS:
                        raise EmbeddingError(
                            f"embedding provider rejected the request ({last_error})"
                        )

                if attempt < self.max_retries:
                    # Exponential backoff: 0.5s, 1s, 2s...
                    delay = 0.5 * (2**attempt)
                    logger.warning(
                        "embedding attempt %d/%d failed (%s); retrying in %.1fs",
                        attempt + 1,
                        self.max_retries + 1,
                        last_error,
                        delay,
                    )
                    await asyncio.sleep(delay)

        raise EmbeddingError(
            f"embedding provider unavailable after {self.max_retries + 1} attempt(s): "
            f"{last_error}"
        )

    def _parse(self, data: dict[str, object], *, expected: int) -> list[list[float]]:
        """Pull vectors out of the response, failing loudly on any surprise."""
        items = data.get("data")
        if not isinstance(items, list):
            raise EmbeddingError("embedding response has no 'data' array")
        if len(items) != expected:
            raise EmbeddingError(
                f"embedding provider returned {len(items)} vectors for {expected} inputs"
            )

        vectors: list[list[float]] = []
        for item in items:
            embedding = item.get("embedding") if isinstance(item, dict) else None
            if not isinstance(embedding, list) or not embedding:
                raise EmbeddingError("embedding response contained an empty vector")
            if len(embedding) != self.dimensions:
                # Storing this would fail at the pgvector column anyway; failing
                # here names the actual problem.
                raise EmbeddingError(
                    f"embedding provider returned {len(embedding)}-dimensional vectors "
                    f"but the platform is configured for {self.dimensions}. Set "
                    f"EMBEDDING_DIMENSIONS to match the model and re-index."
                )
            vectors.append([float(value) for value in embedding])
        return vectors
