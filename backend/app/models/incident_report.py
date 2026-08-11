"""Written write-ups attached to an incident."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import ReportFormat, ReportStatus
from app.models.mixins import (
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    json_array,
    json_object,
    pg_enum,
)

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.user import User


class IncidentReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A versioned report for an incident.

    Reports are immutable once published: revisions are new rows with an
    incremented ``version`` rather than edits in place. Whether the body was
    drafted by a human or generated is recorded but not acted on until the AI
    phase.
    """

    __tablename__ = "incident_reports"
    __table_args__ = (
        UniqueConstraint("incident_id", "version", name="uq_incident_reports_incident_version"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    status: Mapped[ReportStatus] = mapped_column(
        pg_enum(ReportStatus, "report_status"),
        nullable=False,
        default=ReportStatus.DRAFT,
        server_default=ReportStatus.DRAFT.value,
        index=True,
    )
    format: Mapped[ReportFormat] = mapped_column(
        pg_enum(ReportFormat, "report_format"),
        nullable=False,
        default=ReportFormat.MARKDOWN,
        server_default=ReportFormat.MARKDOWN.value,
    )

    executive_summary: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # Structured breakdown (timeline, impact, root cause, ...) kept beside the
    # rendered body so sections can be re-assembled without re-parsing it.
    sections: Mapped[dict[str, Any]] = json_object()
    recommendations: Mapped[list[dict[str, Any]]] = json_array()

    is_ai_generated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Model name, prompt version, token counts -- filled in by the AI phase.
    generation_metadata: Mapped[dict[str, Any]] = json_object()

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- Relationships ---------------------------------------------------
    incident: Mapped[Incident] = relationship(back_populates="reports")
    author: Mapped[User | None] = relationship(back_populates="authored_reports")

    def __repr__(self) -> str:
        return f"<IncidentReport v{self.version} ({self.status})>"
