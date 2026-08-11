"""initial schema

Creates the eight core tables, their enum types and the pgvector extension.

Autogeneration gets three things wrong here, so the file is maintained by hand:

* ``severity`` is shared by three tables, and each ``sa.Enum`` would emit its own
  ``CREATE TYPE``. The enum types are therefore created once, up front, and every
  column references them with ``create_type=False``.
* Enum types are not dropped on downgrade, which breaks a second upgrade.
* The rendered ``Vector`` column needs the ``pgvector`` import.

Revision ID: 8a301cc1babd
Revises:
Create Date: 2026-08-11 20:14:02.117430
"""

from collections.abc import Sequence

import pgvector.sqlalchemy
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "8a301cc1babd"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# --- Enum types -----------------------------------------------------------
# create_type=False: these are created and dropped explicitly below.
def _enum(name: str, *values: str) -> postgresql.ENUM:
    return postgresql.ENUM(*values, name=name, create_type=False)


user_role = _enum("user_role", "admin", "analyst", "responder", "viewer")
severity = _enum("severity", "info", "low", "medium", "high", "critical")
log_source_type = _enum(
    "log_source_type",
    "syslog",
    "firewall",
    "ids",
    "endpoint",
    "cloud_trail",
    "application",
    "authentication",
    "network_flow",
    "database",
    "other",
)
log_source_status = _enum(
    "log_source_status", "pending", "active", "paused", "error", "disabled"
)
anomaly_type = _enum(
    "anomaly_type",
    "statistical",
    "behavioral",
    "signature",
    "correlation",
    "threshold",
    "machine_learning",
)
anomaly_status = _enum(
    "anomaly_status",
    "new",
    "triaged",
    "investigating",
    "confirmed",
    "false_positive",
    "dismissed",
)
incident_status = _enum(
    "incident_status",
    "open",
    "triaged",
    "investigating",
    "contained",
    "eradicated",
    "recovered",
    "closed",
)
incident_priority = _enum("incident_priority", "p1", "p2", "p3", "p4")
report_status = _enum(
    "report_status", "draft", "in_review", "approved", "published", "archived"
)
report_format = _enum("report_format", "markdown", "html", "json", "pdf")
document_type = _enum(
    "document_type",
    "playbook",
    "runbook",
    "policy",
    "threat_intel",
    "advisory",
    "compliance",
    "postmortem",
    "other",
)
audit_action = _enum(
    "audit_action",
    "create",
    "read",
    "update",
    "delete",
    "login",
    "logout",
    "login_failed",
    "export",
    "assign",
    "status_change",
)

ENUM_TYPES = (
    user_role,
    severity,
    log_source_type,
    log_source_status,
    anomaly_type,
    anomaly_status,
    incident_status,
    incident_priority,
    report_status,
    report_format,
    document_type,
    audit_action,
)

JSON_OBJECT = sa.text("'{}'::jsonb")
JSON_ARRAY = sa.text("'[]'::jsonb")


def _now_column(name: str) -> sa.Column:
    """A non-null, timezone-aware timestamp defaulting to the server clock."""
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    )


def upgrade() -> None:
    bind = op.get_bind()

    # The compose image ships these, but a hand-provisioned database may not.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    for enum_type in ENUM_TYPES:
        enum_type.create(bind, checkfirst=True)

    # --- users ------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", user_role, server_default="analyst", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("is_superuser", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "preferences",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_role"), "users", ["role"], unique=False)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    # --- log_sources ------------------------------------------------------
    op.create_table(
        "log_sources",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_type", log_source_type, nullable=False),
        sa.Column("status", log_source_status, server_default="pending", nullable=False),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("timezone", sa.String(length=64), server_default="UTC", nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "collection_interval_seconds", sa.Integer(), server_default="60", nullable=False
        ),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column(
            "tags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column("last_ingested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("events_ingested", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_log_sources_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_log_sources")),
    )
    op.create_index(op.f("ix_log_sources_created_at"), "log_sources", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_log_sources_created_by_id"), "log_sources", ["created_by_id"], unique=False
    )
    op.create_index(op.f("ix_log_sources_hostname"), "log_sources", ["hostname"], unique=False)
    op.create_index(op.f("ix_log_sources_name"), "log_sources", ["name"], unique=True)
    op.create_index(
        "ix_log_sources_type_status", "log_sources", ["source_type", "status"], unique=False
    )

    # --- log_entries ------------------------------------------------------
    op.create_table(
        "log_entries",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("log_source_id", sa.UUID(), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        _now_column("ingested_at"),
        sa.Column("severity", severity, server_default="info", nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("raw", sa.Text(), nullable=True),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("process", sa.String(length=255), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=True),
        sa.Column("embedding", pgvector.sqlalchemy.Vector(dim=1536), nullable=True),
        _now_column("created_at"),
        sa.ForeignKeyConstraint(
            ["log_source_id"],
            ["log_sources.id"],
            name=op.f("fk_log_entries_log_source_id_log_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_log_entries")),
    )
    op.create_index(op.f("ix_log_entries_created_at"), "log_entries", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_log_entries_event_timestamp"), "log_entries", ["event_timestamp"], unique=False
    )
    op.create_index("ix_log_entries_event_type", "log_entries", ["event_type"], unique=False)
    op.create_index(
        op.f("ix_log_entries_fingerprint"), "log_entries", ["fingerprint"], unique=False
    )
    op.create_index(op.f("ix_log_entries_host"), "log_entries", ["host"], unique=False)
    op.create_index(
        op.f("ix_log_entries_log_source_id"), "log_entries", ["log_source_id"], unique=False
    )
    op.create_index(
        "ix_log_entries_severity_event_time",
        "log_entries",
        ["severity", "event_timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_log_entries_source_event_time",
        "log_entries",
        ["log_source_id", "event_timestamp"],
        unique=False,
    )
    op.create_index("ix_log_entries_source_ip", "log_entries", ["source_ip"], unique=False)
    op.create_index("ix_log_entries_username", "log_entries", ["username"], unique=False)

    # --- incidents --------------------------------------------------------
    op.create_table(
        "incidents",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "number",
            sa.BigInteger(),
            sa.Identity(always=False, start=1000, increment=1),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("severity", severity, server_default="medium", nullable=False),
        sa.Column("status", incident_status, server_default="open", nullable=False),
        sa.Column("priority", incident_priority, server_default="p3", nullable=False),
        sa.Column("assigned_to_id", sa.UUID(), nullable=True),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        _now_column("detected_at"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "affected_assets",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column(
            "indicators",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column(
            "mitre_techniques",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column(
            "tags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column(
            "context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.ForeignKeyConstraint(
            ["assigned_to_id"],
            ["users.id"],
            name=op.f("fk_incidents_assigned_to_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_incidents_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.UniqueConstraint("number", name=op.f("uq_incidents_number")),
    )
    op.create_index(
        "ix_incidents_assigned_status", "incidents", ["assigned_to_id", "status"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_assigned_to_id"), "incidents", ["assigned_to_id"], unique=False
    )
    op.create_index(op.f("ix_incidents_category"), "incidents", ["category"], unique=False)
    op.create_index(op.f("ix_incidents_created_at"), "incidents", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_incidents_created_by_id"), "incidents", ["created_by_id"], unique=False
    )
    op.create_index(op.f("ix_incidents_detected_at"), "incidents", ["detected_at"], unique=False)
    op.create_index(
        "ix_incidents_status_severity", "incidents", ["status", "severity"], unique=False
    )

    # --- anomalies --------------------------------------------------------
    op.create_table(
        "anomalies",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("log_entry_id", sa.UUID(), nullable=True),
        sa.Column("log_source_id", sa.UUID(), nullable=True),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("assigned_to_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("anomaly_type", anomaly_type, nullable=False),
        sa.Column("severity", severity, server_default="medium", nullable=False),
        sa.Column("status", anomaly_status, server_default="new", nullable=False),
        sa.Column("score", sa.Float(), server_default="0", nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("detector", sa.String(length=128), nullable=False),
        sa.Column("detector_version", sa.String(length=32), nullable=True),
        _now_column("detected_at"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column(
            "features",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column(
            "mitre_techniques",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name=op.f("ck_anomalies_confidence_range"),
        ),
        sa.CheckConstraint("score >= 0 AND score <= 1", name=op.f("ck_anomalies_score_range")),
        sa.ForeignKeyConstraint(
            ["assigned_to_id"],
            ["users.id"],
            name=op.f("fk_anomalies_assigned_to_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_anomalies_incident_id_incidents"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["log_entry_id"],
            ["log_entries.id"],
            name=op.f("fk_anomalies_log_entry_id_log_entries"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["log_source_id"],
            ["log_sources.id"],
            name=op.f("fk_anomalies_log_source_id_log_sources"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_anomalies")),
    )
    op.create_index(
        op.f("ix_anomalies_assigned_to_id"), "anomalies", ["assigned_to_id"], unique=False
    )
    op.create_index(op.f("ix_anomalies_created_at"), "anomalies", ["created_at"], unique=False)
    op.create_index(op.f("ix_anomalies_detected_at"), "anomalies", ["detected_at"], unique=False)
    op.create_index(
        "ix_anomalies_detected_at_score", "anomalies", ["detected_at", "score"], unique=False
    )
    op.create_index(op.f("ix_anomalies_detector"), "anomalies", ["detector"], unique=False)
    op.create_index(op.f("ix_anomalies_incident_id"), "anomalies", ["incident_id"], unique=False)
    op.create_index(op.f("ix_anomalies_log_entry_id"), "anomalies", ["log_entry_id"], unique=False)
    op.create_index(
        op.f("ix_anomalies_log_source_id"), "anomalies", ["log_source_id"], unique=False
    )
    op.create_index(
        "ix_anomalies_status_severity", "anomalies", ["status", "severity"], unique=False
    )

    # --- incident_reports -------------------------------------------------
    op.create_table(
        "incident_reports",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("author_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", report_status, server_default="draft", nullable=False),
        sa.Column("format", report_format, server_default="markdown", nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "sections",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column(
            "recommendations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column("is_ai_generated", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "generation_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_incident_reports_author_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_reports_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_reports")),
        sa.UniqueConstraint("incident_id", "version", name="uq_incident_reports_incident_version"),
    )
    op.create_index(
        op.f("ix_incident_reports_author_id"), "incident_reports", ["author_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_reports_created_at"), "incident_reports", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_incident_reports_incident_id"), "incident_reports", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_reports_status"), "incident_reports", ["status"], unique=False
    )

    # --- security_documents -----------------------------------------------
    op.create_table(
        "security_documents",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("document_type", document_type, nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source_url", sa.String(length=2048), nullable=True),
        sa.Column("checksum", sa.String(length=64), nullable=True),
        sa.Column("language", sa.String(length=16), server_default="en", nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "tags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_ARRAY,
            nullable=False,
        ),
        sa.Column(
            "doc_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column("embedding", pgvector.sqlalchemy.Vector(dim=1536), nullable=True),
        sa.Column("embedding_model", sa.String(length=128), nullable=True),
        sa.Column("embedded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("uploaded_by_id", sa.UUID(), nullable=True),
        _now_column("created_at"),
        _now_column("updated_at"),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"],
            ["users.id"],
            name=op.f("fk_security_documents_uploaded_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_documents")),
        sa.UniqueConstraint("checksum", name=op.f("uq_security_documents_checksum")),
    )
    op.create_index(
        op.f("ix_security_documents_created_at"), "security_documents", ["created_at"], unique=False
    )
    op.create_index(
        "ix_security_documents_embedding_hnsw",
        "security_documents",
        ["embedding"],
        unique=False,
        postgresql_using="hnsw",
        postgresql_with={"m": 16, "ef_construction": 64},
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )
    op.create_index(
        op.f("ix_security_documents_title"), "security_documents", ["title"], unique=False
    )
    op.create_index(
        "ix_security_documents_type_active",
        "security_documents",
        ["document_type", "is_active"],
        unique=False,
    )
    op.create_index(
        op.f("ix_security_documents_uploaded_by_id"),
        "security_documents",
        ["uploaded_by_id"],
        unique=False,
    )

    # --- audit_logs -------------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("action", audit_action, nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.UUID(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "changes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column(
            "context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=JSON_OBJECT,
            nullable=False,
        ),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("success", sa.Boolean(), server_default="true", nullable=False),
        _now_column("created_at"),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name=op.f("fk_audit_logs_actor_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(
        "ix_audit_logs_action_created_at", "audit_logs", ["action", "created_at"], unique=False
    )
    op.create_index(
        "ix_audit_logs_actor_created_at", "audit_logs", ["actor_id", "created_at"], unique=False
    )
    op.create_index(op.f("ix_audit_logs_actor_id"), "audit_logs", ["actor_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_created_at"), "audit_logs", ["created_at"], unique=False)
    op.create_index(op.f("ix_audit_logs_request_id"), "audit_logs", ["request_id"], unique=False)
    op.create_index(
        "ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"], unique=False
    )


def downgrade() -> None:
    bind = op.get_bind()

    # Dropping a table takes its indexes and constraints with it.
    for table in (
        "audit_logs",
        "security_documents",
        "incident_reports",
        "anomalies",
        "incidents",
        "log_entries",
        "log_sources",
        "users",
    ):
        op.drop_table(table)

    for enum_type in reversed(ENUM_TYPES):
        enum_type.drop(bind, checkfirst=True)

    # The vector extension is left in place: it is provisioned with the database
    # rather than owned by this migration, and other schemas may depend on it.
