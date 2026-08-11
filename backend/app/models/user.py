"""Analyst and operator accounts."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import UserRole
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin, json_object, pg_enum

if TYPE_CHECKING:
    from app.models.anomaly import Anomaly
    from app.models.audit_log import AuditLog
    from app.models.incident import Incident
    from app.models.incident_report import IncidentReport
    from app.models.log_source import LogSource
    from app.models.security_document import SecurityDocument


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A person who operates the platform.

    Credential *handling* arrives with the authentication phase; this model only
    reserves the columns it will need.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    role: Mapped[UserRole] = mapped_column(
        pg_enum(UserRole, "user_role"),
        nullable=False,
        default=UserRole.ANALYST,
        server_default=UserRole.ANALYST.value,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    preferences: Mapped[dict[str, Any]] = json_object()

    # --- Relationships ---------------------------------------------------
    # Users are retained for audit purposes, so ownership links are nulled out
    # rather than cascading a delete into operational data.
    log_sources: Mapped[list[LogSource]] = relationship(
        back_populates="created_by", passive_deletes=True
    )
    assigned_anomalies: Mapped[list[Anomaly]] = relationship(
        back_populates="assigned_to", passive_deletes=True
    )
    assigned_incidents: Mapped[list[Incident]] = relationship(
        back_populates="assigned_to",
        foreign_keys="Incident.assigned_to_id",
        passive_deletes=True,
    )
    reported_incidents: Mapped[list[Incident]] = relationship(
        back_populates="created_by",
        foreign_keys="Incident.created_by_id",
        passive_deletes=True,
    )
    authored_reports: Mapped[list[IncidentReport]] = relationship(
        back_populates="author", passive_deletes=True
    )
    uploaded_documents: Mapped[list[SecurityDocument]] = relationship(
        back_populates="uploaded_by", passive_deletes=True
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        back_populates="actor", passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"
