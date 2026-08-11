"""Registered origins of telemetry: firewalls, endpoints, cloud trails, ..."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import LogSourceStatus, LogSourceType
from app.models.mixins import (
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    json_array,
    json_object,
    pg_enum,
)
from app.models.types import INETStr

if TYPE_CHECKING:
    from app.models.anomaly import Anomaly
    from app.models.ingestion_job import IngestionJob
    from app.models.log_entry import LogEntry
    from app.models.user import User


class LogSource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A configured collector that feeds log entries into the platform."""

    __tablename__ = "log_sources"
    __table_args__ = (
        Index("ix_log_sources_type_status", "source_type", "status"),
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[LogSourceType] = mapped_column(
        pg_enum(LogSourceType, "log_source_type"), nullable=False
    )
    status: Mapped[LogSourceStatus] = mapped_column(
        pg_enum(LogSourceStatus, "log_source_status"),
        nullable=False,
        default=LogSourceStatus.PENDING,
        server_default=LogSourceStatus.PENDING.value,
    )

    vendor: Mapped[str | None] = mapped_column(String(128))
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(INETStr)
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="UTC"
    )

    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    collection_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default="60"
    )

    # Collector-specific settings (credentials references, paths, filters, ...).
    config: Mapped[dict[str, Any]] = json_object()
    tags: Mapped[list[str]] = json_array()

    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    events_ingested: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    # --- Relationships ---------------------------------------------------
    created_by: Mapped[User | None] = relationship(back_populates="log_sources")
    entries: Mapped[list[LogEntry]] = relationship(
        back_populates="log_source",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    anomalies: Mapped[list[Anomaly]] = relationship(
        back_populates="log_source", passive_deletes=True
    )
    ingestion_jobs: Mapped[list[IngestionJob]] = relationship(
        back_populates="log_source",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<LogSource {self.name} ({self.source_type})>"
