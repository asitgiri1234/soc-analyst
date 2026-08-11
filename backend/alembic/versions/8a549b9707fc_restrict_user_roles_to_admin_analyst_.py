"""restrict user roles to admin analyst viewer

Phase 1 speculatively included a ``responder`` role. The authorization model
defines exactly three ranked tiers -- admin, analyst, viewer -- and a role with
no permissions attached to it is a hazard in an authz system, so it is removed.

PostgreSQL cannot drop a value from an enum type in place, so the type is
rebuilt: any account still holding ``responder`` is moved to ``analyst``, the
closest tier by privilege.

Revision ID: 8a549b9707fc
Revises: 8a301cc1babd
Create Date: 2026-08-11 20:58:41.702233
"""

from collections.abc import Sequence

from alembic import op

revision: str = "8a549b9707fc"
down_revision: str | None = "8a301cc1babd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_VALUES = ("admin", "analyst", "viewer")
OLD_VALUES = ("admin", "analyst", "responder", "viewer")


def _rebuild_user_role(values: tuple[str, ...], default: str) -> None:
    """Swap ``user_role`` for a type with a different value list.

    The column default is dropped first: it is a cast expression bound to the
    old type, and would otherwise block the ALTER.
    """
    # Values are module constants, not input.
    literals = ", ".join(f"'{value}'" for value in values)

    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
    op.execute("ALTER TYPE user_role RENAME TO user_role_old")
    op.execute(f"CREATE TYPE user_role AS ENUM ({literals})")
    op.execute("ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::text::user_role")
    op.execute(f"ALTER TABLE users ALTER COLUMN role SET DEFAULT '{default}'")
    op.execute("DROP TYPE user_role_old")


def upgrade() -> None:
    # Re-home any existing responder before the value disappears.
    op.execute("UPDATE users SET role = 'analyst' WHERE role = 'responder'")
    # The default also drops to the least-privileged role: a row written without
    # an explicit role should not arrive with investigation rights.
    _rebuild_user_role(NEW_VALUES, default="viewer")


def downgrade() -> None:
    # Restores the value; accounts moved to analyst above are not reverted,
    # because which ones they were is no longer recorded.
    _rebuild_user_role(OLD_VALUES, default="analyst")
