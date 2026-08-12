"""add document chunks

Moves embeddings from the document to a new chunk table. Retrieval works at
passage granularity -- one embedding per document would bury the relevant
paragraph of a playbook -- and leaving a second, unpopulated vector column on
security_documents would only leave the next reader guessing which one search
reads.

As in earlier migrations, the rendered Vector column needs the pgvector import
that autogeneration omits.

Revision ID: acbe61e24ead
Revises: 753abb7600a4
Create Date: 2026-08-12 11:09:41.751713
"""

from collections.abc import Sequence

import pgvector.sqlalchemy
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "acbe61e24ead"
down_revision: str | None = "753abb7600a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

HNSW_OPTIONS = {
    "postgresql_using": "hnsw",
    "postgresql_with": {"m": 16, "ef_construction": 64},
    "postgresql_ops": {"embedding": "vector_cosine_ops"},
}


def upgrade() -> None:
    op.create_table(
        "document_chunks",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("document_id", sa.UUID(), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("char_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("embedding", pgvector.sqlalchemy.Vector(dim=1536), nullable=True),
        sa.Column("embedding_model", sa.String(length=128), nullable=True),
        sa.Column("embedded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "chunk_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["security_documents.id"],
            name=op.f("fk_document_chunks_document_id_security_documents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_chunks")),
        sa.UniqueConstraint("document_id", "chunk_index", name="uq_document_chunks_doc_index"),
    )
    op.create_index(
        op.f("ix_document_chunks_created_at"), "document_chunks", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_document_chunks_document_id"), "document_chunks", ["document_id"], unique=False
    )
    op.create_index(
        "ix_document_chunks_embedding_hnsw",
        "document_chunks",
        ["embedding"],
        unique=False,
        **HNSW_OPTIONS,
    )

    # The document-level vector and its index move to the chunk table.
    op.drop_index(
        op.f("ix_security_documents_embedding_hnsw"),
        table_name="security_documents",
        **HNSW_OPTIONS,
    )
    op.drop_column("security_documents", "embedding")
    op.drop_column("security_documents", "embedding_model")
    op.drop_column("security_documents", "embedded_at")


def downgrade() -> None:
    op.add_column(
        "security_documents",
        sa.Column("embedded_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "security_documents", sa.Column("embedding_model", sa.VARCHAR(length=128), nullable=True)
    )
    op.add_column(
        "security_documents",
        sa.Column("embedding", pgvector.sqlalchemy.Vector(dim=1536), nullable=True),
    )
    op.create_index(
        op.f("ix_security_documents_embedding_hnsw"),
        "security_documents",
        ["embedding"],
        unique=False,
        **HNSW_OPTIONS,
    )

    op.drop_index("ix_document_chunks_embedding_hnsw", table_name="document_chunks", **HNSW_OPTIONS)
    op.drop_index(op.f("ix_document_chunks_document_id"), table_name="document_chunks")
    op.drop_index(op.f("ix_document_chunks_created_at"), table_name="document_chunks")
    op.drop_table("document_chunks")
