"""Turning a document into stored, embedded chunks.

Order matters here: the text is chunked and *embedded before anything is
written*. A provider outage then leaves the corpus exactly as it was rather
than leaving a document with no vectors that silently never appears in search
results.

Re-indexing replaces a document's chunks wholesale. Chunk boundaries shift when
the chunk size changes and vectors are meaningless across a model change, so
merging old chunks with new would leave a corpus that is half one thing and
half another.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.models.document_chunk import DocumentChunk
from app.models.security_document import SecurityDocument
from app.services.rag import chunking
from app.services.rag.embeddings import EmbeddingProvider, get_provider

logger = get_logger(__name__)


class EmptyDocumentError(ValueError):
    """The document has no content worth indexing."""


class DuplicateDocumentError(ValueError):
    """A document with the same content is already stored."""

    def __init__(self, existing_id: uuid.UUID) -> None:
        self.existing_id = existing_id
        super().__init__(f"identical content already stored as {existing_id}")


@dataclass(slots=True)
class IndexResult:
    """What indexing produced."""

    document: SecurityDocument
    chunks_created: int
    embedded: int
    provider: str
    model: str


def checksum(content: str) -> str:
    """SHA-256 of the normalised content, for de-duplicating re-uploads."""
    return hashlib.sha256(chunking.normalise(content).encode("utf-8")).hexdigest()


async def _embed_all(
    provider: EmbeddingProvider, texts: list[str]
) -> list[list[float]]:
    """Embed every text, one provider call per batch.

    Batched because providers charge and rate-limit per request; bounded
    because an unbounded batch trips their own body-size limits.
    """
    vectors: list[list[float]] = []
    size = settings.EMBEDDING_BATCH_SIZE
    for start in range(0, len(texts), size):
        batch = texts[start : start + size]
        vectors.extend(await provider.embed(batch))
    return vectors


async def index_document(
    session: AsyncSession,
    document: SecurityDocument,
    *,
    provider: EmbeddingProvider | None = None,
) -> IndexResult:
    """Chunk, embed and store a document's passages, replacing any existing set."""
    provider = provider or get_provider()

    chunks = chunking.chunk_text(document.content)
    if not chunks:
        raise EmptyDocumentError("document has no indexable content")

    # Embed first: a failure here must not leave the document partly indexed.
    vectors = await _embed_all(provider, [chunk.content for chunk in chunks])
    now = datetime.now(UTC)

    await session.execute(
        delete(DocumentChunk).where(DocumentChunk.document_id == document.id)
    )
    # Flushed before the inserts so the delete lands first and the
    # (document_id, chunk_index) uniqueness is never momentarily violated.
    await session.flush()

    for chunk, vector in zip(chunks, vectors, strict=True):
        session.add(
            DocumentChunk(
                document_id=document.id,
                chunk_index=chunk.index,
                content=chunk.content,
                char_count=chunk.char_count,
                embedding=vector,
                embedding_model=provider.model,
                embedded_at=now,
                chunk_metadata={"provider": provider.name},
            )
        )
    await session.flush()

    logger.info(
        "indexed %s into %d chunk(s) with %s/%s",
        document.title,
        len(chunks),
        provider.name,
        provider.model,
    )
    return IndexResult(
        document=document,
        chunks_created=len(chunks),
        embedded=len(vectors),
        provider=provider.name,
        model=provider.model,
    )


async def create_document(
    session: AsyncSession,
    *,
    values: dict[str, object],
    uploaded_by_id: uuid.UUID | None = None,
    provider: EmbeddingProvider | None = None,
) -> IndexResult:
    """Store a document and index it.

    Rejects content that is empty or already stored. The checksum comparison is
    over *normalised* content, so the same text re-uploaded with different line
    endings is still recognised as a duplicate.
    """
    content = str(values.get("content") or "")
    if not chunking.normalise(content):
        raise EmptyDocumentError("document content is empty")

    digest = checksum(content)
    existing = (
        await session.execute(
            select(SecurityDocument.id).where(SecurityDocument.checksum == digest)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise DuplicateDocumentError(existing)

    document = SecurityDocument(
        **values, checksum=digest, uploaded_by_id=uploaded_by_id
    )
    session.add(document)
    await session.flush()

    return await index_document(session, document, provider=provider)
