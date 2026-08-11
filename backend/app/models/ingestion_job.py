"""One record per uploaded log file.

Keeps the outcome of an upload after the response has been sent: how many
records were accepted, how many were rejected and why. Without this, a partial
ingest would be invisible the moment the client closed the connection.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import IngestionFormat, IngestionStatus
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin, json_array, pg_enum

if TYPE_CHECKING:
    from app.models.log_source import LogSource
    from app.models.user import User


class IngestionJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The result of ingesting one file into one log source."""

    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        Index("ix_ingestion_jobs_source_created", "log_source_id", "created_at"),
        Index("ix_ingestion_jobs_status_created", "status", "created_at"),
    )

    log_source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(128))
    size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    format: Mapped[IngestionFormat] = mapped_column(
        pg_enum(IngestionFormat, "ingestion_format"), nullable=False
    )

    status: Mapped[IngestionStatus] = mapped_column(
        pg_enum(IngestionStatus, "ingestion_status"),
        nullable=False,
        default=IngestionStatus.PENDING,
        server_default=IngestionStatus.PENDING.value,
    )

    total_records: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    accepted_records: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    rejected_records: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    # A capped sample of per-row failures: enough to fix the feed, bounded so a
    # pathological file cannot write an unbounded row.
    errors: Mapped[list[dict[str, Any]]] = json_array()
    # Set when the file itself could not be read, as opposed to its rows.
    error_detail: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- Relationships ---------------------------------------------------
    log_source: Mapped[LogSource] = relationship(back_populates="ingestion_jobs")
    created_by: Mapped[User | None] = relationship()

    def __repr__(self) -> str:
        return f"<IngestionJob {self.filename} ({self.status})>"
