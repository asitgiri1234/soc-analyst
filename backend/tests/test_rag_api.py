"""The knowledge base over HTTP, against real pgvector storage."""

from __future__ import annotations

import json
import pathlib
import uuid

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.document_chunk import DocumentChunk
from app.models.enums import UserRole
from app.models.security_document import SecurityDocument
from app.services.rag.embeddings import EmbeddingError, get_provider
from app.services.rag.embeddings.base import EmbeddingConfigurationError

KNOWLEDGE = "/api/v1/knowledge"
SEED_DIR = pathlib.Path(__file__).resolve().parent.parent / "seed_data" / "knowledge"

SSH_DOC = {
    "title": "SSH Brute Force Response",
    "document_type": "playbook",
    "tags": ["ssh", "brute-force"],
    "content": (
        "# SSH Brute Force Response\n\n"
        "Repeated failed SSH authentication attempts against one account indicate a "
        "brute force attack. Block the offending source address at the perimeter "
        "firewall and force a credential reset for any account that authenticated "
        "successfully from it. Disable password authentication and require public keys."
    ),
}

XSS_DOC = {
    "title": "Cross-Site Scripting Prevention",
    "document_type": "playbook",
    "tags": ["xss", "web"],
    "content": (
        "# Cross-Site Scripting Prevention\n\n"
        "Cross-site scripting injects attacker controlled script into a page other "
        "users load. Encode on output for the HTML, attribute and JavaScript contexts, "
        "set HttpOnly on session cookies, and deploy a strict Content Security Policy."
    ),
}


@pytest.fixture
async def analyst(make_user):
    return await make_user(UserRole.ANALYST)


@pytest.fixture
def headers(analyst, auth_header) -> dict[str, str]:
    return auth_header(analyst)


@pytest.fixture
async def viewer_headers(make_user, auth_header) -> dict[str, str]:
    return auth_header(await make_user(UserRole.VIEWER))


@pytest.fixture
async def admin_headers(make_user, auth_header) -> dict[str, str]:
    return auth_header(await make_user(UserRole.ADMIN))


async def add_document(client: httpx.AsyncClient, headers, **overrides) -> dict:
    response = await client.post(
        f"{KNOWLEDGE}/documents", headers=headers, json={**SSH_DOC, **overrides}
    )
    assert response.status_code == 201, response.text
    return response.json()


# --- Document creation -----------------------------------------------------


async def test_a_document_is_stored_chunked_and_embedded(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    body = await add_document(client, headers)

    assert body["chunks_created"] >= 1
    assert body["embedded"] == body["chunks_created"]
    assert body["provider"] == get_provider().name
    assert body["document"]["title"] == SSH_DOC["title"]
    assert body["document"]["chunk_count"] == body["chunks_created"]
    assert body["document"]["embedded_chunks"] == body["chunks_created"]

    stored = await session.execute(
        select(func.count())
        .select_from(DocumentChunk)
        .where(DocumentChunk.document_id == uuid.UUID(body["document"]["id"]))
    )
    assert stored.scalar_one() == body["chunks_created"]


async def test_chunks_carry_vectors_of_the_configured_size(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    from app.core.config import settings

    body = await add_document(client, headers)
    chunk = (
        await session.execute(
            select(DocumentChunk).where(
                DocumentChunk.document_id == uuid.UUID(body["document"]["id"])
            )
        )
    ).scalars().first()

    assert chunk is not None
    assert chunk.embedding is not None
    assert len(chunk.embedding) == settings.EMBEDDING_DIMENSIONS
    assert chunk.embedding_model == get_provider().model
    assert chunk.embedded_at is not None


async def test_a_long_document_becomes_several_chunks(
    client: httpx.AsyncClient, headers
) -> None:
    long_body = "\n\n".join(
        f"## Section {i}\nGuidance about incident response step {i}. " * 8
        for i in range(12)
    )
    body = await add_document(client, headers, title="Long Runbook", content=long_body)
    assert body["chunks_created"] > 1


async def test_identical_content_is_rejected_as_duplicate(
    client: httpx.AsyncClient, headers
) -> None:
    await add_document(client, headers)
    response = await client.post(f"{KNOWLEDGE}/documents", headers=headers, json=SSH_DOC)
    assert response.status_code == 409


async def test_duplicate_detection_ignores_line_endings(
    client: httpx.AsyncClient, headers
) -> None:
    """The same text re-uploaded from a Windows editor is still the same text."""
    await add_document(client, headers)
    response = await client.post(
        f"{KNOWLEDGE}/documents",
        headers=headers,
        json={**SSH_DOC, "content": SSH_DOC["content"].replace("\n", "\r\n")},
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"title": "No content", "document_type": "playbook"},
        {"title": "Empty", "document_type": "playbook", "content": ""},
        {"title": "ab", "document_type": "playbook", "content": "text"},
        {"title": "Bad type", "document_type": "not-a-type", "content": "text"},
        {"title": "Extra field", "document_type": "policy", "content": "x", "checksum": "f"},
    ],
)
async def test_invalid_documents_are_rejected(
    client: httpx.AsyncClient, headers, payload: dict
) -> None:
    response = await client.post(f"{KNOWLEDGE}/documents", headers=headers, json=payload)
    assert response.status_code == 422


async def test_whitespace_only_content_is_rejected(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    response = await client.post(
        f"{KNOWLEDGE}/documents",
        headers=headers,
        json={**SSH_DOC, "title": "Blank body", "content": "   \n\n\t  "},
    )

    assert response.status_code == 422
    remaining = await session.execute(
        select(SecurityDocument).where(SecurityDocument.title == "Blank body")
    )
    assert remaining.scalars().all() == []


# --- Retrieval -------------------------------------------------------------


async def test_search_returns_the_relevant_passage(
    client: httpx.AsyncClient, headers
) -> None:
    await add_document(client, headers)
    await add_document(client, headers, **XSS_DOC)

    response = await client.post(
        f"{KNOWLEDGE}/search", headers=headers, json={"query": "ssh brute force login failures"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert body["results"][0]["document_title"] == SSH_DOC["title"]
    assert body["results"][0]["similarity"] > 0
    assert body["model"] == get_provider().model


async def test_results_are_ordered_by_similarity(
    client: httpx.AsyncClient, headers
) -> None:
    await add_document(client, headers)
    await add_document(client, headers, **XSS_DOC)

    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": "cross site scripting content security policy", "min_similarity": 0.0},
        )
    ).json()

    scores = [hit["similarity"] for hit in body["results"]]
    assert scores == sorted(scores, reverse=True)
    assert body["results"][0]["document_title"] == XSS_DOC["title"]


async def test_top_k_bounds_the_result_count(
    client: httpx.AsyncClient, headers
) -> None:
    for index in range(4):
        await add_document(
            client,
            headers,
            title=f"Playbook {index}",
            content=f"Guidance number {index} about authentication and brute force response.",
        )

    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": "authentication brute force", "top_k": 2, "min_similarity": 0.0},
        )
    ).json()
    assert len(body["results"]) <= 2


async def test_an_irrelevant_query_returns_nothing(
    client: httpx.AsyncClient, headers
) -> None:
    """Retrieval that always answers cannot say 'nothing here is relevant'."""
    await add_document(client, headers)

    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": "zzzz qqqq vvvv unrelated gibberish", "min_similarity": 0.5},
        )
    ).json()
    assert body["count"] == 0


async def test_search_can_filter_by_document_type(
    client: httpx.AsyncClient, headers
) -> None:
    await add_document(client, headers)
    await add_document(
        client,
        headers,
        title="Authentication Policy",
        document_type="policy",
        content="Policy on authentication, brute force lockouts and credential handling.",
    )

    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={
                "query": "brute force authentication",
                "document_types": ["policy"],
                "min_similarity": 0.0,
            },
        )
    ).json()

    assert body["count"] >= 1
    assert all(hit["document_type"] == "policy" for hit in body["results"])


async def test_search_can_filter_by_tag(client: httpx.AsyncClient, headers) -> None:
    await add_document(client, headers)
    await add_document(client, headers, **XSS_DOC)

    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": "attack response", "tags": ["xss"], "min_similarity": 0.0},
        )
    ).json()
    assert all("xss" in hit["tags"] for hit in body["results"])


async def test_an_inactive_document_is_not_retrieved(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    """Retired guidance stays stored for audit but must not be returned."""
    body = await add_document(client, headers)
    document = await session.get(SecurityDocument, uuid.UUID(body["document"]["id"]))
    document.is_active = False
    await session.flush()

    results = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": "ssh brute force", "min_similarity": 0.0},
        )
    ).json()
    assert all(hit["document_id"] != body["document"]["id"] for hit in results["results"])


async def test_an_empty_query_is_rejected(client: httpx.AsyncClient, headers) -> None:
    response = await client.post(f"{KNOWLEDGE}/search", headers=headers, json={"query": "   "})
    assert response.status_code == 422


async def test_search_returning_no_match_is_empty_not_an_error(
    client: httpx.AsyncClient, headers
) -> None:
    """A query nothing satisfies returns an empty result, not a 404 or a throw.

    Expressed as a similarity floor no chunk can clear rather than as "the
    corpus is empty". Documents committed by a seed run are visible to this
    transaction, and any real deployment has a populated corpus, so a test that
    depends on the table being globally empty passes only on a virgin database.
    """
    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": "anything at all", "min_similarity": 0.999999},
        )
    ).json()
    assert body["count"] == 0
    assert body["results"] == []


# --- Re-indexing and lifecycle --------------------------------------------


async def test_reindexing_replaces_the_chunk_set(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    body = await add_document(client, headers)
    document_id = body["document"]["id"]

    before = (
        await session.execute(
            select(DocumentChunk.id).where(
                DocumentChunk.document_id == uuid.UUID(document_id)
            )
        )
    ).scalars().all()

    response = await client.post(
        f"{KNOWLEDGE}/documents/{document_id}/reindex", headers=headers
    )
    assert response.status_code == 200

    after = (
        await session.execute(
            select(DocumentChunk.id).where(
                DocumentChunk.document_id == uuid.UUID(document_id)
            )
        )
    ).scalars().all()

    # Same count, entirely new rows — replaced rather than merged.
    assert len(after) == len(before)
    assert set(after).isdisjoint(set(before))


async def test_deleting_a_document_removes_its_chunks(
    client: httpx.AsyncClient, session: AsyncSession, headers, admin_headers
) -> None:
    body = await add_document(client, headers)
    document_id = uuid.UUID(body["document"]["id"])

    response = await client.delete(
        f"{KNOWLEDGE}/documents/{document_id}", headers=admin_headers
    )
    assert response.status_code == 204

    remaining = await session.execute(
        select(func.count())
        .select_from(DocumentChunk)
        .where(DocumentChunk.document_id == document_id)
    )
    assert remaining.scalar_one() == 0


async def test_documents_can_be_listed_and_fetched(
    client: httpx.AsyncClient, headers
) -> None:
    created = await add_document(client, headers)

    listed = await client.get(f"{KNOWLEDGE}/documents", headers=headers)
    assert listed.status_code == 200
    assert created["document"]["id"] in [d["id"] for d in listed.json()]

    fetched = await client.get(
        f"{KNOWLEDGE}/documents/{created['document']['id']}", headers=headers
    )
    assert fetched.status_code == 200
    assert fetched.json()["content"] == SSH_DOC["content"]


async def test_an_unknown_document_is_not_found(
    client: httpx.AsyncClient, headers
) -> None:
    response = await client.get(f"{KNOWLEDGE}/documents/{uuid.uuid4()}", headers=headers)
    assert response.status_code == 404


async def test_stats_report_indexing_coverage(
    client: httpx.AsyncClient, headers
) -> None:
    body = await add_document(client, headers)

    stats = (await client.get(f"{KNOWLEDGE}/stats", headers=headers)).json()
    assert stats["documents"] >= 1
    assert stats["embedded_chunks"] >= body["chunks_created"]
    assert stats["provider"] == get_provider().name


# --- Provider failure handling --------------------------------------------


async def test_a_provider_outage_returns_503_and_stores_nothing(
    client: httpx.AsyncClient,
    session: AsyncSession,
    headers,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A document that cannot be embedded must not be left unsearchable."""

    async def failing_embed(self, texts):
        raise EmbeddingError("provider timed out")

    from app.services.rag.embeddings.hashing import HashingEmbeddingProvider

    monkeypatch.setattr(HashingEmbeddingProvider, "embed", failing_embed)

    response = await client.post(
        f"{KNOWLEDGE}/documents",
        headers=headers,
        json={**SSH_DOC, "title": "Never indexed"},
    )

    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]

    remaining = await session.execute(
        select(SecurityDocument).where(SecurityDocument.title == "Never indexed")
    )
    assert remaining.scalars().all() == []


async def test_a_misconfigured_provider_returns_500(
    client: httpx.AsyncClient, headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not transient: a missing key is a deployment fault, not an outage."""

    async def missing_key(self, texts):
        raise EmbeddingConfigurationError("EMBEDDING_API_KEY is not set")

    from app.services.rag.embeddings.hashing import HashingEmbeddingProvider

    monkeypatch.setattr(HashingEmbeddingProvider, "embed", missing_key)

    response = await client.post(
        f"{KNOWLEDGE}/documents", headers=headers, json={**SSH_DOC, "title": "No key"}
    )
    assert response.status_code == 500
    assert "misconfigured" in response.json()["detail"]


async def test_a_search_outage_returns_503(
    client: httpx.AsyncClient, headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    await add_document(client, headers)

    async def failing_query(self, text):
        raise EmbeddingError("provider timed out")

    from app.services.rag.embeddings.hashing import HashingEmbeddingProvider

    monkeypatch.setattr(HashingEmbeddingProvider, "embed_query", failing_query)

    response = await client.post(
        f"{KNOWLEDGE}/search", headers=headers, json={"query": "ssh brute force"}
    )
    assert response.status_code == 503


# --- Authorization ---------------------------------------------------------


async def test_knowledge_routes_require_authentication(
    client: httpx.AsyncClient,
) -> None:
    assert (await client.get(f"{KNOWLEDGE}/documents")).status_code == 401
    assert (
        await client.post(f"{KNOWLEDGE}/search", json={"query": "x"})
    ).status_code == 401


async def test_a_viewer_can_search_but_not_add(
    client: httpx.AsyncClient, headers, viewer_headers
) -> None:
    await add_document(client, headers)

    assert (
        await client.post(
            f"{KNOWLEDGE}/search", headers=viewer_headers, json={"query": "ssh"}
        )
    ).status_code == 200
    assert (
        await client.get(f"{KNOWLEDGE}/documents", headers=viewer_headers)
    ).status_code == 200
    assert (
        await client.post(
            f"{KNOWLEDGE}/documents",
            headers=viewer_headers,
            json={**SSH_DOC, "title": "Viewer attempt"},
        )
    ).status_code == 403


async def test_deleting_a_document_is_reserved_for_admins(
    client: httpx.AsyncClient, headers, viewer_headers, admin_headers
) -> None:
    body = await add_document(client, headers)
    document_id = body["document"]["id"]

    assert (
        await client.delete(f"{KNOWLEDGE}/documents/{document_id}", headers=viewer_headers)
    ).status_code == 403
    assert (
        await client.delete(f"{KNOWLEDGE}/documents/{document_id}", headers=headers)
    ).status_code == 403
    assert (
        await client.delete(f"{KNOWLEDGE}/documents/{document_id}", headers=admin_headers)
    ).status_code == 204


async def test_the_provider_endpoint_reports_configuration(
    client: httpx.AsyncClient, viewer_headers
) -> None:
    body = (await client.get(f"{KNOWLEDGE}/provider", headers=viewer_headers)).json()
    provider = get_provider()
    assert body == {
        "name": provider.name,
        "model": provider.model,
        "dimensions": provider.dimensions,
    }


# --- The shipped seed corpus ----------------------------------------------


def test_the_seed_corpus_covers_the_required_topics() -> None:
    titles = " ".join(
        json.loads(path.read_text(encoding="utf-8"))["title"].lower()
        for path in SEED_DIR.glob("*.json")
    )
    for topic in (
        "ssh brute force",
        "sql injection",
        "cross-site scripting",
        "credential stuffing",
        "suspicious authentication",
        "incident response",
        "best practices",
    ):
        assert topic in titles, topic


@pytest.mark.parametrize(
    ("filename", "query"),
    [
        ("ssh-brute-force-detection-and-response.json", "ssh brute force failed logins"),
        ("sql-injection-detection-and-mitigation.json", "sql injection union select"),
        ("cross-site-scripting-xss-detection-and-prevention.json", "cross site scripting"),
        ("credential-stuffing-detection-and-response.json", "credential stuffing password reuse"),
        ("incident-response-process.json", "incident response containment eradication"),
    ],
)
async def test_each_seed_document_is_retrievable_by_its_topic(
    client: httpx.AsyncClient, headers, filename: str, query: str
) -> None:
    """The corpus is only useful if the right document comes back for its topic."""
    for path in SEED_DIR.glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        response = await client.post(
            f"{KNOWLEDGE}/documents", headers=headers, json=payload
        )
        # 409 when a seed run has already committed this document. Either way
        # it is in the corpus, which is all this test needs; asserting on 201
        # would make the test depend on the database never having been seeded.
        assert response.status_code in {201, 409}, response.text

    expected = json.loads((SEED_DIR / filename).read_text(encoding="utf-8"))["title"]
    body = (
        await client.post(
            f"{KNOWLEDGE}/search",
            headers=headers,
            json={"query": query, "top_k": 3, "min_similarity": 0.0},
        )
    ).json()

    assert body["count"] >= 1
    titles = [hit["document_title"] for hit in body["results"]]
    assert expected in titles, f"{expected!r} not in {titles!r}"
