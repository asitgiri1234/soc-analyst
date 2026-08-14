"""add incident attachments

Files an analyst attaches to an incident for context, stored as extracted text
rather than bytes: the analyzer needs the content, and keeping files on disk
would give an otherwise stateless service a filesystem to mount, back up and
clean up.

Nothing to hand-correct in this one -- no Vector columns and no shared enum
types, which are what autogeneration gets wrong elsewhere in this history.

Revision ID: a9602ab2287e
Revises: acbe61e24ead
Create Date: 2026-08-14 15:37:33.575462
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a9602ab2287e"
down_revision: str | None = "acbe61e24ead"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incident_attachments",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("uploaded_by_id", sa.UUID(), nullable=True),
        sa.Column("uploaded_by_username", sa.String(length=64), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # Deleting an incident takes its attachments with it, as it does its
        # notes and reports. Deleting the uploader leaves the attachment in
        # place, attributed by the username kept alongside the key.
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_attachments_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"],
            ["users.id"],
            name=op.f("fk_incident_attachments_uploaded_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_attachments")),
    )
    op.create_index(
        op.f("ix_incident_attachments_created_at"),
        "incident_attachments",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_incident_attachments_incident_created",
        "incident_attachments",
        ["incident_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_attachments_incident_id"),
        "incident_attachments",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incident_attachments_uploaded_by_id"),
        "incident_attachments",
        ["uploaded_by_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_incident_attachments_uploaded_by_id"), table_name="incident_attachments"
    )
    op.drop_index(
        op.f("ix_incident_attachments_incident_id"), table_name="incident_attachments"
    )
    op.drop_index(
        "ix_incident_attachments_incident_created", table_name="incident_attachments"
    )
    op.drop_index(
        op.f("ix_incident_attachments_created_at"), table_name="incident_attachments"
    )
    op.drop_table("incident_attachments")
