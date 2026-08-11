"""SQLAlchemy ORM models.

Importing this package registers every model on ``Base.metadata``. The Alembic
environment imports it for that reason -- a model that is not reachable from here
is invisible to autogeneration.
"""

from app.models.anomaly import Anomaly
from app.models.audit_log import AuditLog
from app.models.enums import (
    AnomalyStatus,
    AnomalyType,
    AuditAction,
    DocumentType,
    IncidentPriority,
    IncidentStatus,
    IngestionFormat,
    IngestionStatus,
    LogSourceStatus,
    LogSourceType,
    ReportFormat,
    ReportStatus,
    Severity,
    UserRole,
)
from app.models.incident import Incident
from app.models.incident_report import IncidentReport
from app.models.ingestion_job import IngestionJob
from app.models.log_entry import LogEntry
from app.models.log_source import LogSource
from app.models.security_document import SecurityDocument
from app.models.user import User

__all__ = [
    # Models
    "Anomaly",
    "AuditLog",
    "Incident",
    "IncidentReport",
    "IngestionJob",
    "LogEntry",
    "LogSource",
    "SecurityDocument",
    "User",
    # Enums
    "AnomalyStatus",
    "AnomalyType",
    "AuditAction",
    "DocumentType",
    "IncidentPriority",
    "IncidentStatus",
    "IngestionFormat",
    "IngestionStatus",
    "LogSourceStatus",
    "LogSourceType",
    "ReportFormat",
    "ReportStatus",
    "Severity",
    "UserRole",
]
