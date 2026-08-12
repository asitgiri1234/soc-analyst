"""Finding the passages most relevant to a query.

The search is a cosine-distance ordering over chunk embeddings, executed in
PostgreSQL by pgvector and backed by the HNSW index on
``document_chunks.embedding``. Ordering happens in the database rather than in
Python: pulling every chunk into the process to sort them would defeat the
index and would not survive a corpus of any size.

Similarity is reported as ``1 - cosine_distance`` so that higher is better,
which is what a reader expects of a relevance score.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import Float, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.document_chunk import DocumentChunk
from app.models.enums import DocumentType
from app.models.security_document import SecurityDocument
from app.services.rag.embeddings import EmbeddingProvider, get_provider


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    """One passage, with enough of its document to cite it."""

    chunk_id: uuid.UUID
    document_id: uuid.UUID
    document_title: str
    document_type: DocumentType
    chunk_index: int
    content: str
    similarity: float
    source_url: str | None
    tags: list[str]


async def search(
    session: AsyncSession,
    query: str,
    *,
    top_k: int | None = None,
    min_similarity: float | None = None,
    document_types: list[DocumentType] | None = None,
    tags: list[str] | None = None,
    provider: EmbeddingProvider | None = None,
) -> list[RetrievedChunk]:
    """Return the passages most similar to ``query``, best first.

    An empty or whitespace-only query returns nothing rather than an arbitrary
    ordering of the corpus: there is no such thing as the chunk most similar to
    nothing.
    """
    if not query.strip():
        return []

    provider = provider or get_provider()
    limit = top_k if top_k is not None else settings.RAG_TOP_K
    floor = min_similarity if min_similarity is not None else settings.RAG_MIN_SIMILARITY

    embedding = await provider.embed_query(query)

    # 1 - cosine_distance, so higher is more similar.
    similarity = (1 - DocumentChunk.embedding.cosine_distance(embedding)).cast(Float)

    statement = (
        select(
            DocumentChunk.id,
            DocumentChunk.document_id,
            DocumentChunk.chunk_index,
            DocumentChunk.content,
            similarity.label("similarity"),
            SecurityDocument.title,
            SecurityDocument.document_type,
            SecurityDocument.source_url,
            SecurityDocument.tags,
        )
        .join(SecurityDocument, SecurityDocument.id == DocumentChunk.document_id)
        .where(
            DocumentChunk.embedding.is_not(None),
            # Retired documents stay stored for audit but must not be retrieved.
            SecurityDocument.is_active.is_(True),
            # Vectors from a different model are not comparable to this query's.
            DocumentChunk.embedding_model == provider.model,
        )
        .order_by(DocumentChunk.embedding.cosine_distance(embedding))
        .limit(limit)
    )

    if document_types:
        statement = statement.where(SecurityDocument.document_type.in_(document_types))
    if tags:
        # JSONB containment: the document's tags must include all requested.
        statement = statement.where(SecurityDocument.tags.contains(tags))

    rows = (await session.execute(statement)).all()

    return [
        RetrievedChunk(
            chunk_id=row.id,
            document_id=row.document_id,
            document_title=row.title,
            document_type=row.document_type,
            chunk_index=row.chunk_index,
            content=row.content,
            similarity=round(float(row.similarity), 6),
            source_url=row.source_url,
            tags=list(row.tags or []),
        )
        for row in rows
        # Filtered after ordering: the floor decides what is worth returning,
        # not what the index scans.
        if float(row.similarity) >= floor
    ]
