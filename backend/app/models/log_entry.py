"""Normalised log events ingested from a log source."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import settings
from app.db.base import Base
from app.models.enums import Severity
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin, json_object, pg_enum

if TYPE_CHECKING:
    from app.models.anomaly import Anomaly
    from app.models.log_source import LogSource


class LogEntry(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A single event.

    Rows are append-only: ingestion never rewrites an entry, so the table carries
    a creation timestamp but no ``updated_at``. Free-form vendor fields live in
    ``attributes`` rather than growing the column list per source type.
    """

    __tablename__ = "log_entries"
    __table_args__ = (
        # Primary access pattern: one source's events over a time window.
        Index("ix_log_entries_source_event_time", "log_source_id", "event_timestamp"),
        Index("ix_log_entries_severity_event_time", "severity", "event_timestamp"),
        Index("ix_log_entries_event_type", "event_type"),
        Index("ix_log_entries_username", "username"),
        Index("ix_log_entries_source_ip", "source_ip"),
    )

    log_source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # When the event happened at the source, vs. when we stored it.
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        default=Severity.INFO,
        server_default=Severity.INFO.value,
    )
    category: Mapped[str | None] = mapped_column(String(64))
    event_type: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str | None] = mapped_column(String(128))
    outcome: Mapped[str | None] = mapped_column(String(32))

    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = json_object()

    host: Mapped[str | None] = mapped_column(String(255), index=True)
    process: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))

    # Stable hash of the normalised event, used to drop duplicate deliveries.
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)

    # Populated by the embedding pipeline in a later phase.
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(settings.EMBEDDING_DIMENSIONS)
    )

    # --- Relationships ---------------------------------------------------
    log_source: Mapped[LogSource] = relationship(back_populates="entries")
    anomalies: Mapped[list[Anomaly]] = relationship(
        back_populates="log_entry", passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<LogEntry {self.event_timestamp} {self.severity}>"
