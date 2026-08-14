"""Files an analyst attaches to an incident as context.

A packet capture summary, a vendor advisory, an export from another tool, the
paragraph a colleague sent over -- the material that explains an incident but
was never going to arrive through a log collector.

*The extracted text is stored, not the file.* What the AI analyzer needs is the
content, and keeping bytes on disk would add a filesystem to a service that
otherwise has none: somewhere to mount, back up, and clean up, plus a path
handling surface that is a classic source of traversal bugs. Text in a column
travels with the database backup and cannot escape its row.

*This is evidence to read, never telemetry.* Attachment text is passed to the
model inside the same untrusted fence as log lines, and is never parsed into
LogEntry rows. An analyst's uploaded file must not become data the detectors
then score as though it had been collected.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.incident import Incident


class IncidentAttachment(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One file attached to an incident, stored as its extracted text."""

    __tablename__ = "incident_attachments"
    __table_args__ = (
        Index("ix_incident_attachments_incident_created", "incident_id", "created_at"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    # Kept alongside the foreign key so the attachment stays attributable after
    # the account is removed, as with notes and the audit trail.
    uploaded_by_username: Mapped[str | None] = mapped_column(String(64))

    # Already reduced to a bare name by the endpoint: no directories, no
    # control characters.
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(128))
    # Size of the uploaded file, which is not the length of `content` once
    # decoding and truncation have happened.
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    content: Mapped[str] = mapped_column(Text, nullable=False)
    # True when the file was longer than the configured cap, so a reader knows
    # the analysis saw only part of it.
    truncated: Mapped[bool] = mapped_column(
        default=False, server_default="false", nullable=False
    )

    incident: Mapped[Incident] = relationship(back_populates="attachments")

    def __repr__(self) -> str:
        return f"<IncidentAttachment {self.filename!r}>"
