"""Analyst notes on an incident.

A table rather than a text column on the incident. An investigation is worked by
several people over hours or days, and a single mutable blob loses who observed
what and when -- exactly the record a handover or a post-incident review needs.

Notes are append-only: the trail of an investigation should not be quietly
rewritten after the fact.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.user import User


class IncidentNote(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One observation recorded against an incident."""

    __tablename__ = "incident_notes"
    __table_args__ = (
        Index("ix_incident_notes_incident_created", "incident_id", "created_at"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    # Kept alongside the foreign key so the note stays attributable after the
    # account is removed, as with the audit trail.
    author_username: Mapped[str | None] = mapped_column(String(64))

    body: Mapped[str] = mapped_column(Text, nullable=False)
    # Notes the platform writes itself (a status change, an anomaly linked) are
    # marked, so an analyst can tell their colleagues' words from the system's.
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # --- Relationships ---------------------------------------------------
    incident: Mapped[Incident] = relationship(back_populates="notes")
    author: Mapped[User | None] = relationship()

    def __repr__(self) -> str:
        return f"<IncidentNote {self.incident_id} by {self.author_username}>"
