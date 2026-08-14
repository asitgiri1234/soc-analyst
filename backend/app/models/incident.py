"""Investigations opened from one or more anomalies."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import AttackType, IncidentPriority, IncidentStatus, Severity
from app.models.mixins import (
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    json_array,
    json_object,
    pg_enum,
)

if TYPE_CHECKING:
    from app.models.anomaly import Anomaly
    from app.models.incident_attachment import IncidentAttachment
    from app.models.incident_note import IncidentNote
    from app.models.incident_report import IncidentReport
    from app.models.user import User


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A tracked security investigation.

    Alongside the UUID primary key each incident gets a short sequential
    ``number`` (INC-1042), because analysts need something quotable.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_assigned_status", "assigned_to_id", "status"),
        Index("ix_incidents_attack_type_status", "attack_type", "status"),
    )

    number: Mapped[int] = mapped_column(
        BigInteger, Identity(start=1000, increment=1), nullable=False, unique=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    attack_type: Mapped[AttackType] = mapped_column(
        pg_enum(AttackType, "attack_type"),
        nullable=False,
        default=AttackType.UNKNOWN,
        server_default=AttackType.UNKNOWN.value,
        index=True,
    )

    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        default=Severity.MEDIUM,
        server_default=Severity.MEDIUM.value,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        pg_enum(IncidentStatus, "incident_status"),
        nullable=False,
        default=IncidentStatus.OPEN,
        server_default=IncidentStatus.OPEN.value,
    )
    priority: Mapped[IncidentPriority] = mapped_column(
        pg_enum(IncidentPriority, "incident_priority"),
        nullable=False,
        default=IncidentPriority.P3,
        server_default=IncidentPriority.P3.value,
    )

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    # Response timeline. One column per state transition, so dwell time between
    # stages (detected -> acknowledged -> resolved) can be reported on directly
    # rather than reconstructed from the audit trail.
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    affected_assets: Mapped[list[dict[str, Any]]] = json_array()
    indicators: Mapped[list[dict[str, Any]]] = json_array()
    mitre_techniques: Mapped[list[str]] = json_array()
    tags: Mapped[list[str]] = json_array()
    context: Mapped[dict[str, Any]] = json_object()

    # --- Relationships ---------------------------------------------------
    assigned_to: Mapped[User | None] = relationship(
        back_populates="assigned_incidents", foreign_keys=[assigned_to_id]
    )
    created_by: Mapped[User | None] = relationship(
        back_populates="reported_incidents", foreign_keys=[created_by_id]
    )
    anomalies: Mapped[list[Anomaly]] = relationship(
        back_populates="incident", passive_deletes=True
    )
    reports: Mapped[list[IncidentReport]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IncidentReport.version",
    )
    notes: Mapped[list[IncidentNote]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IncidentNote.created_at",
    )
    attachments: Mapped[list[IncidentAttachment]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IncidentAttachment.created_at",
    )

    @property
    def reference(self) -> str:
        """Human-facing identifier, e.g. ``INC-1042``."""
        return f"INC-{self.number}"

    def __repr__(self) -> str:
        return f"<Incident {self.reference} {self.status}>"
