"""Append-only record of who did what to which resource."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import AuditAction
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin, json_object, pg_enum

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One audited operation.

    Entries are never updated or deleted, so there is no ``updated_at``. The
    actor's email is denormalised alongside the foreign key: the account may be
    removed later, and the trail has to stay readable.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_actor_created_at", "actor_id", "created_at"),
        Index("ix_audit_logs_action_created_at", "action", "created_at"),
    )

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320))

    action: Mapped[AuditAction] = mapped_column(
        pg_enum(AuditAction, "audit_action"), nullable=False
    )
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    description: Mapped[str | None] = mapped_column(Text)
    # Before/after values for the touched fields.
    changes: Mapped[dict[str, Any]] = json_object()
    context: Mapped[dict[str, Any]] = json_object()

    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)

    success: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # --- Relationships ---------------------------------------------------
    actor: Mapped[User | None] = relationship(back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} {self.resource_type}>"
