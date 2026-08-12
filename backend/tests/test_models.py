"""Schema-level guarantees that the rest of the platform will rely on.

These assertions read ``Base.metadata`` and need no database.
"""

from sqlalchemy import Enum as SAEnum

from app.core.config import settings
from app.db.base import Base
from app.models import (
    Anomaly,
    AuditLog,
    DocumentChunk,
    Incident,
    IncidentReport,
    LogEntry,
    LogSource,
    SecurityDocument,
    Severity,
    User,
)

ALL_MODELS = (
    User,
    LogSource,
    LogEntry,
    Anomaly,
    Incident,
    IncidentReport,
    SecurityDocument,
    AuditLog,
)

# Log entries and audit logs are append-only and carry no updated_at.
APPEND_ONLY_TABLES = {"log_entries", "audit_logs"}


def test_all_models_are_registered() -> None:
    expected = {
        "users",
        "log_sources",
        "log_entries",
        "anomalies",
        "incidents",
        "incident_reports",
        "security_documents",
        "audit_logs",
        "ingestion_jobs",
        "incident_notes",
        "document_chunks",
    }
    assert expected == set(Base.metadata.tables)


def test_every_table_has_a_uuid_primary_key() -> None:
    for model in ALL_MODELS:
        primary_key = list(model.__table__.primary_key.columns)
        assert [column.name for column in primary_key] == ["id"], model.__name__
        assert primary_key[0].type.python_type.__name__ == "UUID", model.__name__
        # Rows inserted outside the ORM still get an id.
        assert primary_key[0].server_default is not None, model.__name__


def test_tables_carry_timestamps() -> None:
    for model in ALL_MODELS:
        table = model.__table__
        assert "created_at" in table.columns, model.__name__
        assert table.columns["created_at"].type.timezone is True, model.__name__

        has_updated_at = "updated_at" in table.columns
        assert has_updated_at is (table.name not in APPEND_ONLY_TABLES), model.__name__


def test_enums_are_stored_by_value_not_by_name() -> None:
    """``severity`` must persist as 'critical', never as 'CRITICAL'."""
    column = Incident.__table__.columns["severity"]
    assert isinstance(column.type, SAEnum)
    assert column.type.enums == [member.value for member in Severity]


def test_severity_enum_type_is_shared_across_tables() -> None:
    """One PostgreSQL type backs every severity column."""
    names = {
        model.__table__.columns["severity"].type.name
        for model in (LogEntry, Anomaly, Incident)
    }
    assert names == {"severity"}


def test_foreign_keys_use_the_intended_delete_rules() -> None:
    expected = {
        # Deleting a source discards its telemetry.
        ("log_entries", "log_source_id"): "CASCADE",
        ("incident_reports", "incident_id"): "CASCADE",
        # Operational records outlive the accounts that touched them.
        ("log_sources", "created_by_id"): "SET NULL",
        ("audit_logs", "actor_id"): "SET NULL",
        ("anomalies", "incident_id"): "SET NULL",
        ("incidents", "assigned_to_id"): "SET NULL",
        ("security_documents", "uploaded_by_id"): "SET NULL",
    }
    for (table_name, column_name), ondelete in expected.items():
        column = Base.metadata.tables[table_name].columns[column_name]
        foreign_key = next(iter(column.foreign_keys))
        assert foreign_key.ondelete == ondelete, f"{table_name}.{column_name}"


def test_hot_query_paths_are_indexed() -> None:
    expected = {
        "log_entries": {"ix_log_entries_source_event_time", "ix_log_entries_severity_event_time"},
        "anomalies": {"ix_anomalies_status_severity", "ix_anomalies_detected_at_score"},
        "incidents": {"ix_incidents_status_severity", "ix_incidents_assigned_status"},
        "audit_logs": {"ix_audit_logs_resource", "ix_audit_logs_actor_created_at"},
    }
    for table_name, index_names in expected.items():
        actual = {index.name for index in Base.metadata.tables[table_name].indexes}
        assert index_names <= actual, table_name


def test_unique_constraints_on_natural_keys() -> None:
    assert User.__table__.columns["email"].index is True
    assert User.__table__.columns["email"].unique is True
    assert User.__table__.columns["username"].unique is True
    assert LogSource.__table__.columns["name"].unique is True
    assert SecurityDocument.__table__.columns["checksum"].unique is True

    # A report version may only be issued once per incident.
    constraint_names = {c.name for c in IncidentReport.__table__.constraints}
    assert "uq_incident_reports_incident_version" in constraint_names


def test_vector_columns_match_the_configured_dimensionality() -> None:
    for model in (LogEntry, DocumentChunk):
        column = model.__table__.columns["embedding"]
        assert column.type.dim == settings.EMBEDDING_DIMENSIONS, model.__name__
        assert column.nullable is True, model.__name__


def test_document_embedding_has_a_cosine_vector_index() -> None:
    """Retrieval orders by cosine distance; an index for another operator
    class would simply be ignored by the planner."""
    index = next(
        index
        for index in DocumentChunk.__table__.indexes
        if index.name == "ix_document_chunks_embedding_hnsw"
    )
    assert index.dialect_options["postgresql"]["using"] == "hnsw"
    assert index.dialect_options["postgresql"]["ops"] == {"embedding": "vector_cosine_ops"}


def test_json_columns_default_to_empty_containers() -> None:
    """Defaults apply on both sides, so no JSON column is ever null."""
    cases: dict[tuple[type, str], dict | list] = {
        (User, "preferences"): {},
        (Incident, "tags"): [],
        (Anomaly, "evidence"): {},
        (LogEntry, "attributes"): {},
    }
    for (model, column_name), empty in cases.items():
        column = model.__table__.columns[column_name]
        assert column.nullable is False, column_name
        # SQLAlchemy wraps the callable, so call it rather than compare identity.
        assert column.default.arg(None) == empty, column_name
        assert column.server_default is not None, column_name


def test_incident_reference_is_human_readable() -> None:
    incident = Incident(title="Suspicious egress")
    incident.number = 1042
    assert incident.reference == "INC-1042"
