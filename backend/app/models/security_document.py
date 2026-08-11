"""Knowledge-base documents: playbooks, policies, threat intel.

These are the corpus that later phases embed and retrieve against, which is why
the embedding column and its vector index live here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import settings
from app.db.base import Base
from app.models.enums import DocumentType
from app.models.mixins import (
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    json_array,
    json_object,
    pg_enum,
)

if TYPE_CHECKING:
    from app.models.user import User


class SecurityDocument(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A reference document available to analysts and to retrieval."""

    __tablename__ = "security_documents"
    __table_args__ = (
        Index("ix_security_documents_type_active", "document_type", "is_active"),
        # Cosine distance is the metric the retrieval layer will query with; an
        # index built for a different operator class would simply be ignored.
        Index(
            "ix_security_documents_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    document_type: Mapped[DocumentType] = mapped_column(
        pg_enum(DocumentType, "document_type"), nullable=False
    )

    summary: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    # SHA-256 of the normalised content; keeps re-uploads from duplicating rows.
    checksum: Mapped[str | None] = mapped_column(String(64), unique=True)

    language: Mapped[str] = mapped_column(
        String(16), nullable=False, default="en", server_default="en"
    )
    version: Mapped[str | None] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    tags: Mapped[list[str]] = json_array()
    doc_metadata: Mapped[dict[str, Any]] = json_object()

    # Populated by the embedding pipeline in a later phase.
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(settings.EMBEDDING_DIMENSIONS)
    )
    embedding_model: Mapped[str | None] = mapped_column(String(128))
    embedded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    # --- Relationships ---------------------------------------------------
    uploaded_by: Mapped[User | None] = relationship(back_populates="uploaded_documents")

    def __repr__(self) -> str:
        return f"<SecurityDocument {self.title} ({self.document_type})>"
