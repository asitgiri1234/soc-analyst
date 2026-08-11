"""add ingestion jobs

Adds the per-upload record backing ingestion status tracking.

As in the initial migration, the enum types are created and dropped explicitly:
autogeneration emits the CREATE TYPE inline but never a DROP, which leaves a
downgrade followed by an upgrade failing on the already-existing type.

Revision ID: a50308d09ae3
Revises: 8a549b9707fc
Create Date: 2026-08-11 20:51:57.683955
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a50308d09ae3"
down_revision: str | None = "8a549b9707fc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ingestion_format = postgresql.ENUM(
    "csv", "json", "ndjson", name="ingestion_format", create_type=False
)
ingestion_status = postgresql.ENUM(
    "pending",
    "running",
    "completed",
    "partial",
    "failed",
    name="ingestion_status",
    create_type=False,
)

ENUM_TYPES = (ingestion_format, ingestion_status)


def _now_column(name: str) -> sa.Column:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    )


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in ENUM_TYPES:
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "ingestion_jobs",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("log_source_id", sa.UUID(), nullable=False),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("format", ingestion_format, nullable=False),
        sa.Column("status", ingestion_status, server_default="pending", nullable=False),
        sa.Column("total_records", sa.Integer(), server_default="0", nullable=False),
        sa.Column("accepted_records", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rejected_records", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "errors",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_ingestion_jobs_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["log_source_id"],
            ["log_sources.id"],
            name=op.f("fk_ingestion_jobs_log_source_id_log_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_jobs")),
    )
    op.create_index(
        op.f("ix_ingestion_jobs_created_at"), "ingestion_jobs", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_ingestion_jobs_created_by_id"), "ingestion_jobs", ["created_by_id"], unique=False
    )
    op.create_index(
        op.f("ix_ingestion_jobs_log_source_id"),
        "ingestion_jobs",
        ["log_source_id"],
        unique=False,
    )
    op.create_index(
        "ix_ingestion_jobs_source_created",
        "ingestion_jobs",
        ["log_source_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_ingestion_jobs_status_created",
        "ingestion_jobs",
        ["status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_table("ingestion_jobs")
    for enum_type in reversed(ENUM_TYPES):
        enum_type.drop(bind, checkfirst=True)
