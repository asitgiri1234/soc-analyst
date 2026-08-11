"""Enumerations shared by the ORM models.

Every enum is persisted as a native PostgreSQL enum type. Members are stored by
*value* (see `pg_enum` in `app.models.mixins`), so the Python member names can be
renamed without a data migration -- the string values cannot.
"""

from enum import StrEnum


class UserRole(StrEnum):
    """Coarse-grained role attached to a user account."""

    ADMIN = "admin"
    ANALYST = "analyst"
    RESPONDER = "responder"
    VIEWER = "viewer"


class LogSourceType(StrEnum):
    """The kind of system a log source collects from."""

    SYSLOG = "syslog"
    FIREWALL = "firewall"
    IDS = "ids"
    ENDPOINT = "endpoint"
    CLOUD_TRAIL = "cloud_trail"
    APPLICATION = "application"
    AUTHENTICATION = "authentication"
    NETWORK_FLOW = "network_flow"
    DATABASE = "database"
    OTHER = "other"


class LogSourceStatus(StrEnum):
    """Collector health for a log source."""

    PENDING = "pending"
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    DISABLED = "disabled"


class Severity(StrEnum):
    """Shared severity scale for log entries, anomalies and incidents."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(StrEnum):
    """Detection family that produced an anomaly."""

    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    SIGNATURE = "signature"
    CORRELATION = "correlation"
    THRESHOLD = "threshold"
    MACHINE_LEARNING = "machine_learning"


class AnomalyStatus(StrEnum):
    """Triage state of an anomaly."""

    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DISMISSED = "dismissed"


class IncidentStatus(StrEnum):
    """Incident lifecycle, loosely following the NIST 800-61 phases."""

    OPEN = "open"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class IncidentPriority(StrEnum):
    """Response urgency, independent of technical severity."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class ReportStatus(StrEnum):
    """Publication state of an incident report."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class ReportFormat(StrEnum):
    """Serialisation format of an incident report body."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"


class DocumentType(StrEnum):
    """Category of a security knowledge-base document."""

    PLAYBOOK = "playbook"
    RUNBOOK = "runbook"
    POLICY = "policy"
    THREAT_INTEL = "threat_intel"
    ADVISORY = "advisory"
    COMPLIANCE = "compliance"
    POSTMORTEM = "postmortem"
    OTHER = "other"


class AuditAction(StrEnum):
    """Auditable operation recorded against a resource."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    EXPORT = "export"
    ASSIGN = "assign"
    STATUS_CHANGE = "status_change"
