"""Chunking, embedding providers and failure handling, without a database."""

from __future__ import annotations

import httpx
import pytest

from app.core.config import settings
from app.services.rag import chunking
from app.services.rag.embeddings import (
    EmbeddingConfigurationError,
    EmbeddingError,
    EmbeddingProvider,
    HashingEmbeddingProvider,
    HTTPEmbeddingProvider,
    build_provider,
)

DIMS = settings.EMBEDDING_DIMENSIONS


# --- Chunking --------------------------------------------------------------


def test_short_text_is_a_single_chunk() -> None:
    chunks = chunking.chunk_text("A brief note about SSH.")
    assert len(chunks) == 1
    assert chunks[0].index == 0
    assert chunks[0].content == "A brief note about SSH."


def test_empty_text_produces_no_chunks() -> None:
    assert chunking.chunk_text("") == []
    assert chunking.chunk_text("   \n\n  \t ") == []


def test_long_text_splits_into_ordered_chunks() -> None:
    text = " ".join(f"sentence{i} about security." for i in range(400))
    chunks = chunking.chunk_text(text, chunk_size=500, overlap=50)

    assert len(chunks) > 1
    assert [c.index for c in chunks] == list(range(len(chunks)))
    assert all(c.content for c in chunks)


def test_chunks_respect_the_size_limit() -> None:
    text = " ".join(f"word{i}" for i in range(2000))
    chunks = chunking.chunk_text(text, chunk_size=300, overlap=40)
    assert all(c.char_count <= 300 for c in chunks)


def test_chunks_overlap_so_a_seam_is_not_lost() -> None:
    """A passage straddling a boundary must survive whole in one chunk."""
    text = " ".join(f"token{i}" for i in range(300))
    chunks = chunking.chunk_text(text, chunk_size=400, overlap=120)

    # The tail of each chunk reappears at the head of the next.
    first_tail = chunks[0].content[-60:]
    assert any(fragment in chunks[1].content for fragment in first_tail.split()[:3])


def test_zero_overlap_is_allowed() -> None:
    text = " ".join(f"word{i}" for i in range(500))
    chunks = chunking.chunk_text(text, chunk_size=300, overlap=0)
    assert len(chunks) > 1


def test_splitting_prefers_paragraph_boundaries() -> None:
    text = "First paragraph about brute force.\n\n" + ("x" * 50) + "\n\nThird paragraph."
    chunks = chunking.chunk_text(text, chunk_size=60, overlap=10)
    # No chunk should begin mid-word.
    assert all(not c.content.startswith("x " ) for c in chunks[1:] if c.content)


def test_overlap_at_or_above_chunk_size_is_rejected() -> None:
    """Otherwise the cursor never advances and the split loops forever."""
    with pytest.raises(ValueError, match="smaller than chunk_size"):
        chunking.chunk_text("some text here", chunk_size=100, overlap=100)


def test_line_endings_do_not_change_the_result() -> None:
    body = "Line one.\nLine two.\n\nLine three."
    assert chunking.chunk_text(body) == chunking.chunk_text(body.replace("\n", "\r\n"))


# --- Hashing provider ------------------------------------------------------


async def test_hashing_provider_returns_correctly_sized_vectors() -> None:
    provider = HashingEmbeddingProvider(dimensions=DIMS)
    vectors = await provider.embed(["ssh brute force", "sql injection"])

    assert len(vectors) == 2
    assert all(len(v) == DIMS for v in vectors)


async def test_hashing_provider_is_deterministic() -> None:
    """The same text must embed identically across calls and processes."""
    provider = HashingEmbeddingProvider(dimensions=DIMS)
    first = await provider.embed(["credential stuffing attack"])
    second = await provider.embed(["credential stuffing attack"])
    assert first == second


async def test_hashing_vectors_are_normalised() -> None:
    """Unit length makes cosine similarity a plain dot product."""
    provider = HashingEmbeddingProvider(dimensions=DIMS)
    (vector,) = await provider.embed(["incident response process"])
    assert sum(value * value for value in vector) == pytest.approx(1.0, abs=1e-6)


async def test_hashing_similarity_tracks_lexical_overlap() -> None:
    provider = HashingEmbeddingProvider(dimensions=DIMS)
    base, near, far = await provider.embed(
        [
            "ssh brute force authentication failures",
            "brute force ssh login failures detected",
            "quarterly budget spreadsheet for catering",
        ]
    )

    def cosine(a: list[float], b: list[float]) -> float:
        return sum(x * y for x, y in zip(a, b, strict=True))

    assert cosine(base, near) > cosine(base, far)


async def test_hashing_handles_empty_text() -> None:
    provider = HashingEmbeddingProvider(dimensions=DIMS)
    (vector,) = await provider.embed(["   "])
    assert len(vector) == DIMS
    assert all(value == 0.0 for value in vector)


async def test_hashing_query_embedding_matches_document_embedding() -> None:
    """A symmetric model must embed a query exactly as it embeds a document."""
    provider = HashingEmbeddingProvider(dimensions=DIMS)
    (document,) = await provider.embed(["phishing awareness"])
    query = await provider.embed_query("phishing awareness")
    assert document == query


def test_providers_satisfy_the_protocol() -> None:
    """The interface the rest of the platform depends on."""
    hashing = HashingEmbeddingProvider(dimensions=DIMS)
    http = HTTPEmbeddingProvider(dimensions=DIMS, model="m", base_url="http://x")
    assert isinstance(hashing, EmbeddingProvider)
    assert isinstance(http, EmbeddingProvider)


# --- Provider selection ----------------------------------------------------


def test_provider_comes_from_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swapping providers is an environment change, not a code change."""
    monkeypatch.setattr(settings, "EMBEDDING_PROVIDER", "hashing")
    assert build_provider().name == "hashing"

    monkeypatch.setattr(settings, "EMBEDDING_PROVIDER", "http")
    monkeypatch.setattr(settings, "EMBEDDING_MODEL", "text-embedding-3-small")
    provider = build_provider()
    assert provider.name == "http"
    assert provider.model == "text-embedding-3-small"


# --- HTTP provider failure handling ---------------------------------------


def _client_factory(handler):
    """An httpx client whose transport is a callable, so no network is used."""

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://embeddings.test"
        )

    return factory


def _ok(count: int) -> httpx.Response:
    return httpx.Response(
        200, json={"data": [{"embedding": [0.1] * DIMS} for _ in range(count)]}
    )


async def test_http_provider_parses_a_successful_response() -> None:
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="test-model",
        base_url="http://embeddings.test",
        api_key="key",
        client_factory=_client_factory(lambda request: _ok(2)),
    )

    vectors = await provider.embed(["one", "two"])
    assert len(vectors) == 2
    assert len(vectors[0]) == DIMS


async def test_http_provider_without_a_key_fails_as_misconfiguration() -> None:
    """Not transient: retrying will never supply a key."""
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS, model="m", base_url="http://embeddings.test", api_key=None
    )

    with pytest.raises(EmbeddingConfigurationError, match="EMBEDDING_API_KEY"):
        await provider.embed(["text"])


async def test_http_provider_retries_transient_failures() -> None:
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] < 3:
            return httpx.Response(503, text="upstream busy")
        return _ok(1)

    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="key",
        max_retries=2,
        client_factory=_client_factory(handler),
    )

    vectors = await provider.embed(["text"])
    assert attempts["count"] == 3
    assert len(vectors) == 1


async def test_http_provider_gives_up_after_max_retries() -> None:
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="key",
        max_retries=1,
        client_factory=_client_factory(lambda r: httpx.Response(503, text="down")),
    )

    with pytest.raises(EmbeddingError, match="unavailable after 2 attempt"):
        await provider.embed(["text"])


async def test_http_provider_does_not_retry_a_client_error() -> None:
    """A 401 will not fix itself; repeating it wastes time and quota."""
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return httpx.Response(401, text="invalid api key")

    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="wrong",
        max_retries=3,
        client_factory=_client_factory(handler),
    )

    with pytest.raises(EmbeddingError, match="rejected the request"):
        await provider.embed(["text"])
    assert attempts["count"] == 1


async def test_http_provider_retries_network_errors() -> None:
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise httpx.ConnectError("connection refused")
        return _ok(1)

    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="key",
        max_retries=2,
        client_factory=_client_factory(handler),
    )

    assert len(await provider.embed(["text"])) == 1


async def test_http_provider_rejects_a_dimension_mismatch() -> None:
    """Storing these would fail at the pgvector column with a worse message."""
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="key",
        client_factory=_client_factory(
            lambda r: httpx.Response(200, json={"data": [{"embedding": [0.1] * 8}]})
        ),
    )

    with pytest.raises(EmbeddingError, match="EMBEDDING_DIMENSIONS"):
        await provider.embed(["text"])


async def test_http_provider_rejects_a_short_batch() -> None:
    """Three vectors for five inputs is unusable: which three?"""
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="key",
        client_factory=_client_factory(lambda r: _ok(1)),
    )

    with pytest.raises(EmbeddingError, match="returned 1 vectors for 2 inputs"):
        await provider.embed(["a", "b"])


async def test_http_provider_rejects_a_malformed_body() -> None:
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS,
        model="m",
        base_url="http://embeddings.test",
        api_key="key",
        client_factory=_client_factory(
            lambda r: httpx.Response(200, json={"unexpected": True})
        ),
    )

    with pytest.raises(EmbeddingError, match="no 'data' array"):
        await provider.embed(["text"])


async def test_http_provider_embeds_nothing_for_no_input() -> None:
    provider = HTTPEmbeddingProvider(
        dimensions=DIMS, model="m", base_url="http://embeddings.test", api_key="key"
    )
    assert await provider.embed([]) == []
