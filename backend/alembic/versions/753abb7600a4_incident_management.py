"""incident management

Three changes to the incident schema, plus the notes table.

*Status.* Phase 1 speculatively modelled the seven NIST 800-61 phases. The
lifecycle in use is three states, and one of them -- ``resolved`` -- was not
among the seven. PostgreSQL cannot drop values from an enum in place, so the
type is rebuilt and existing rows are mapped onto the nearest surviving state.

*Attack type.* Replaces the free-text ``category`` with an enum, so incidents
can be counted by attack type without first normalising a dozen spellings of
"brute force".

*Notes.* A table rather than a column, because an investigation is worked by
several people and a single blob loses who wrote what.

Revision ID: 753abb7600a4
Revises: e9e79a9db3fd
Create Date: 2026-08-12 11:14:35.802214
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "753abb7600a4"
down_revision: str | None = "e9e79a9db3fd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_STATUSES = ("open", "investigating", "resolved")
OLD_STATUSES = (
    "open",
    "triaged",
    "investigating",
    "contained",
    "eradicated",
    "recovered",
    "closed",
)

# Where each retired state lands. Mid-response phases are all still work in
# progress; a closed incident is a resolved one under the new vocabulary.
COLLAPSE = {
    "triaged": "open",
    "contained": "investigating",
    "eradicated": "investigating",
    "recovered": "investigating",
    "closed": "resolved",
}

attack_type = postgresql.ENUM(
    "brute_force",
    "credential_access",
    "privilege_escalation",
    "lateral_movement",
    "malware",
    "ransomware",
    "phishing",
    "data_exfiltration",
    "denial_of_service",
    "reconnaissance",
    "insider_threat",
    "policy_violation",
    "misconfiguration",
    "unknown",
    "other",
    name="attack_type",
    create_type=False,
)


def _rebuild_status(values: tuple[str, ...], mapping: dict[str, str] | None = None) -> None:
    """Swap ``incident_status`` for a type with a different value list.

    Retired values are translated inside the ``USING`` clause rather than by an
    UPDATE beforehand: until the new type exists, ``resolved`` is not a value
    the column can be set to, so the UPDATE would fail.

    The default is dropped first -- it is a cast bound to the old type and would
    otherwise block the ALTER.
    """
    literals = ", ".join(f"'{value}'" for value in values)
    # Values are module constants, not input. A CASE needs at least one WHEN, so
    # with nothing to translate the cast is used directly.
    if mapping:
        cases = "".join(f" WHEN '{old}' THEN '{new}'" for old, new in mapping.items())
        conversion = f"(CASE status::text{cases} ELSE status::text END)::incident_status"
    else:
        conversion = "status::text::incident_status"

    op.execute("ALTER TABLE incidents ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TYPE incident_status RENAME TO incident_status_old")
    op.execute(f"CREATE TYPE incident_status AS ENUM ({literals})")
    op.execute(f"ALTER TABLE incidents ALTER COLUMN status TYPE incident_status USING {conversion}")
    op.execute("ALTER TABLE incidents ALTER COLUMN status SET DEFAULT 'open'")
    op.execute("DROP TYPE incident_status_old")


def upgrade() -> None:
    bind = op.get_bind()

    _rebuild_status(NEW_STATUSES, COLLAPSE)

    # --- attack_type replaces category ------------------------------------
    attack_type.create(bind, checkfirst=True)
    op.drop_index(op.f("ix_incidents_category"), table_name="incidents")
    op.drop_column("incidents", "category")
    op.add_column(
        "incidents",
        sa.Column("attack_type", attack_type, server_default="unknown", nullable=False),
    )
    op.create_index(
        op.f("ix_incidents_attack_type"), "incidents", ["attack_type"], unique=False
    )
    op.create_index(
        "ix_incidents_attack_type_status", "incidents", ["attack_type", "status"], unique=False
    )

    # --- timeline columns for states that no longer exist -------------------
    op.drop_column("incidents", "contained_at")
    op.drop_column("incidents", "closed_at")

    # --- notes --------------------------------------------------------------
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("author_id", sa.UUID(), nullable=True),
        sa.Column("author_username", sa.String(length=64), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("is_system", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_incident_notes_author_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_notes_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_notes")),
    )
    op.create_index(
        op.f("ix_incident_notes_author_id"), "incident_notes", ["author_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_notes_created_at"), "incident_notes", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_incident_notes_incident_id"), "incident_notes", ["incident_id"], unique=False
    )
    op.create_index(
        "ix_incident_notes_incident_created",
        "incident_notes",
        ["incident_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_table("incident_notes")

    op.add_column("incidents", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "incidents", sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True)
    )

    op.drop_index("ix_incidents_attack_type_status", table_name="incidents")
    op.drop_index(op.f("ix_incidents_attack_type"), table_name="incidents")
    op.drop_column("incidents", "attack_type")
    attack_type.drop(bind, checkfirst=True)
    op.add_column("incidents", sa.Column("category", sa.String(length=64), nullable=True))
    op.create_index(op.f("ix_incidents_category"), "incidents", ["category"], unique=False)

    # Restores the retired values; rows collapsed on the way up are not
    # un-collapsed, because which state each came from is no longer recorded.
    _rebuild_status(OLD_STATUSES)
