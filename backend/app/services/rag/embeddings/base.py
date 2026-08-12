"""The contract every embedding provider implements.

Deliberately tiny: a name, a model identifier, a dimensionality, and one method
that turns texts into vectors. Anything a specific provider needs beyond that --
API keys, retries, batching quirks -- stays inside that provider.

The rest of the platform depends on this protocol and never on a concrete
provider, so switching providers is a configuration change rather than a code
change. Embedding generation is also deliberately separate from any future LLM
analyzer: retrieval must keep working whether or not a generation model is
configured, and the two have different failure modes and different costs.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable


class EmbeddingError(Exception):
    """Raised when embeddings could not be produced.

    Deliberately one exception rather than a hierarchy: to a caller, a bad API
    key, a rate limit and a network timeout all mean the same thing -- no
    vectors this time. The message carries the detail for the logs.
    """


class EmbeddingConfigurationError(EmbeddingError):
    """The provider cannot run as configured -- a missing key, an unknown name.

    Separated because it is not transient: retrying will not fix it, and the
    API should say so rather than reporting a temporary outage.
    """


@runtime_checkable
class EmbeddingProvider(Protocol):
    """What the ingestion and retrieval services require of a provider.

    ``name`` and ``model`` are read-only so a frozen dataclass satisfies the
    protocol; ``model`` is stored alongside every vector, because vectors from
    different models are not comparable and a corpus embedded across a provider
    change must be detectable.
    """

    @property
    def name(self) -> str:
        """Short identifier for the provider, e.g. ``hashing``."""
        ...

    @property
    def model(self) -> str:
        """Model identifier recorded against every vector it produces."""
        ...

    @property
    def dimensions(self) -> int:
        """Length of the vectors produced. Must match the pgvector column."""
        ...

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed a batch of texts, returning one vector per input, in order.

        Raises ``EmbeddingError`` if the batch could not be embedded. Partial
        success is not a thing: a caller that received three vectors for five
        texts could not tell which three.
        """
        ...

    async def embed_query(self, text: str) -> list[float]:
        """Embed a single search query.

        Separate from ``embed`` because several providers ask for a different
        input type for queries than for documents, and asymmetric models score
        noticeably better when told which side they are embedding.
        """
        ...
