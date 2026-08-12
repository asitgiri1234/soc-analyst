"""A slice of a security document, with its embedding.

Retrieval works at chunk granularity, not document granularity: an incident
response playbook has one embedding's worth of meaning per section, not per
file, and returning the whole document would bury the relevant paragraph.

The embedding therefore lives here rather than on SecurityDocument. Keeping a
second, unpopulated vector column on the parent would leave the next person
guessing which one retrieval actually reads.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import settings
from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin, json_object

if TYPE_CHECKING:
    from app.models.security_document import SecurityDocument


class DocumentChunk(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One embedded passage of a document."""

    __tablename__ = "document_chunks"
    __table_args__ = (
        # Re-chunking replaces a document's chunks; the position must stay unique.
        UniqueConstraint("document_id", "chunk_index", name="uq_document_chunks_doc_index"),
        # Cosine distance is what retrieval orders by; an index built for a
        # different operator class would simply be ignored by the planner.
        Index(
            "ix_document_chunks_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )

    document_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Position within the document, 0-based, so chunks can be re-assembled in
    # order and a citation can say "section 3 of 7".
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Nullable: a chunk exists before it is embedded, and a provider outage
    # leaves it that way rather than losing the text.
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(settings.EMBEDDING_DIMENSIONS)
    )
    # Recorded per chunk: a corpus embedded across a provider change contains
    # vectors from two models, and mixing them in one search is meaningless.
    embedding_model: Mapped[str | None] = mapped_column(String(128))
    embedded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    chunk_metadata: Mapped[dict[str, Any]] = json_object()

    # --- Relationships ---------------------------------------------------
    document: Mapped[SecurityDocument] = relationship(back_populates="chunks")

    def __repr__(self) -> str:
        return f"<DocumentChunk {self.document_id}#{self.chunk_index}>"
