"""Suspicious findings raised against log entries."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import AnomalyStatus, AnomalyType, Severity
from app.models.mixins import (
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    json_array,
    json_object,
    pg_enum,
)

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.log_entry import LogEntry
    from app.models.log_source import LogSource
    from app.models.user import User


class Anomaly(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A detector's finding, optionally promoted into an incident.

    The detectors themselves land in a later phase; this model defines where
    their output is stored.
    """

    __tablename__ = "anomalies"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 1", name="score_range"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="confidence_range",
        ),
        Index("ix_anomalies_status_severity", "status", "severity"),
        Index("ix_anomalies_detected_at_score", "detected_at", "score"),
    )

    log_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("log_entries.id", ondelete="SET NULL"), index=True
    )
    log_source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("log_sources.id", ondelete="SET NULL"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    anomaly_type: Mapped[AnomalyType] = mapped_column(
        pg_enum(AnomalyType, "anomaly_type"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        default=Severity.MEDIUM,
        server_default=Severity.MEDIUM.value,
    )
    status: Mapped[AnomalyStatus] = mapped_column(
        pg_enum(AnomalyStatus, "anomaly_status"),
        nullable=False,
        default=AnomalyStatus.NEW,
        server_default=AnomalyStatus.NEW.value,
    )

    # Normalised 0-1 outlier score and the detector's own certainty in it.
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0")
    confidence: Mapped[float | None] = mapped_column(Float)

    detector: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    detector_version: Mapped[str | None] = mapped_column(String(32))

    # Identity of the finding: which detector, about what, in which window --
    # deliberately not the score. Re-analysing an overlapping window recognises
    # what it already stored instead of duplicating it. Nullable and unique, so
    # anomalies raised by hand are unaffected (PostgreSQL allows repeated NULLs
    # in a unique index).
    fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Supporting data: matched rules, baselines, feature vectors, related events.
    evidence: Mapped[dict[str, Any]] = json_object()
    features: Mapped[dict[str, Any]] = json_object()
    mitre_techniques: Mapped[list[str]] = json_array()

    # --- Relationships ---------------------------------------------------
    log_entry: Mapped[LogEntry | None] = relationship(back_populates="anomalies")
    log_source: Mapped[LogSource | None] = relationship(back_populates="anomalies")
    incident: Mapped[Incident | None] = relationship(back_populates="anomalies")
    assigned_to: Mapped[User | None] = relationship(back_populates="assigned_anomalies")

    def __repr__(self) -> str:
        return f"<Anomaly {self.title} ({self.severity}/{self.status})>"
