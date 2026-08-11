"""Round-trip tests against a real PostgreSQL instance.

These exercise what metadata assertions cannot: server defaults, identity
columns, cascade rules, check constraints and pgvector storage. They skip when
no database is reachable, so the suite still runs without one.

Each test runs inside a transaction that is rolled back, leaving no residue.
"""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.models import (
    Anomaly,
    AnomalyType,
    AuditAction,
    AuditLog,
    DocumentType,
    Incident,
    IncidentReport,
    LogEntry,
    LogSource,
    LogSourceType,
    SecurityDocument,
    Severity,
    User,
)


@pytest.fixture
async def session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    try:
        connection = await engine.connect()
    except (OSError, SQLAlchemyError) as exc:  # pragma: no cover - environment dependent
        await engine.dispose()
        pytest.skip(f"PostgreSQL is not reachable: {exc}")

    transaction = await connection.begin()
    db = AsyncSession(bind=connection, expire_on_commit=False)
    try:
        yield db
    finally:
        await db.close()
        await transaction.rollback()
        await connection.close()
        await engine.dispose()


async def _user(session: AsyncSession, *, username: str = "analyst") -> User:
    user = User(
        email=f"{username}@soc.example.com",
        username=username,
        hashed_password="not-a-real-hash",
    )
    session.add(user)
    await session.flush()
    return user


async def _log_source(session: AsyncSession, *, name: str = "edge-firewall") -> LogSource:
    source = LogSource(name=name, source_type=LogSourceType.FIREWALL)
    session.add(source)
    await session.flush()
    return source


def _entry(source: LogSource, message: str = "denied inbound connection") -> LogEntry:
    return LogEntry(
        log_source=source,
        event_timestamp=datetime.now(UTC),
        message=message,
        severity=Severity.HIGH,
        source_ip="203.0.113.10",
        destination_port=22,
    )


async def test_server_defaults_populate_on_insert(session: AsyncSession) -> None:
    user = await _user(session)

    assert user.id is not None
    # Least privilege: a row written without an explicit role gets the lowest.
    assert user.role == "viewer"
    assert user.is_active is True
    assert user.is_superuser is False
    assert user.preferences == {}
    assert user.created_at is not None
    assert user.updated_at is not None


async def test_enum_values_are_stored_as_written(session: AsyncSession) -> None:
    """The database must hold 'high', not 'HIGH'."""
    source = await _log_source(session)
    session.add(_entry(source))
    await session.flush()

    stored = await session.execute(
        select(LogEntry.__table__.c.severity).where(
            LogEntry.__table__.c.log_source_id == source.id
        )
    )
    assert stored.scalar_one() == "high"


async def test_relationships_traverse_in_both_directions(session: AsyncSession) -> None:
    analyst = await _user(session)
    source = await _log_source(session)
    source.created_by = analyst
    entry = _entry(source)
    session.add(entry)
    await session.flush()

    incident = Incident(title="Brute force against edge SSH", created_by=analyst)
    session.add(incident)
    await session.flush()

    anomaly = Anomaly(
        title="Repeated auth failures",
        anomaly_type=AnomalyType.THRESHOLD,
        detector="threshold.auth_failures",
        score=0.87,
        log_entry=entry,
        log_source=source,
        incident=incident,
        assigned_to=analyst,
    )
    session.add(anomaly)
    await session.flush()

    await session.refresh(incident, ["anomalies"])
    assert [a.id for a in incident.anomalies] == [anomaly.id]

    await session.refresh(entry, ["log_source"])
    assert entry.log_source.name == source.name

    await session.refresh(analyst, ["assigned_anomalies", "reported_incidents"])
    assert [a.id for a in analyst.assigned_anomalies] == [anomaly.id]
    assert [i.id for i in analyst.reported_incidents] == [incident.id]


async def test_incident_number_is_assigned_by_the_database(session: AsyncSession) -> None:
    first = Incident(title="First")
    second = Incident(title="Second")
    session.add_all([first, second])
    await session.flush()
    await session.refresh(first)
    await session.refresh(second)

    assert first.number >= 1000
    assert second.number > first.number
    assert first.reference == f"INC-{first.number}"


async def test_deleting_a_source_cascades_to_its_entries(session: AsyncSession) -> None:
    source = await _log_source(session)
    session.add_all([_entry(source, "one"), _entry(source, "two")])
    await session.flush()

    await session.delete(source)
    await session.flush()

    remaining = await session.execute(select(func.count()).select_from(LogEntry.__table__))
    assert remaining.scalar_one() == 0


async def test_anomaly_survives_the_deletion_of_its_incident(session: AsyncSession) -> None:
    incident = Incident(title="Contained phishing")
    anomaly = Anomaly(
        title="Suspicious attachment",
        anomaly_type=AnomalyType.SIGNATURE,
        detector="yara.attachments",
        score=0.5,
        incident=incident,
    )
    session.add_all([incident, anomaly])
    await session.flush()

    await session.delete(incident)
    await session.flush()
    await session.refresh(anomaly)

    assert anomaly.incident_id is None


async def test_anomaly_score_must_be_a_probability(session: AsyncSession) -> None:
    # A savepoint keeps the rejected insert from tearing down the test's
    # surrounding transaction.
    with pytest.raises((IntegrityError, DBAPIError)):
        async with session.begin_nested():
            session.add(
                Anomaly(
                    title="Out of range",
                    anomaly_type=AnomalyType.STATISTICAL,
                    detector="zscore",
                    score=1.5,
                )
            )
            await session.flush()


async def test_report_versions_are_unique_per_incident(session: AsyncSession) -> None:
    incident = Incident(title="Data exfiltration")
    session.add(incident)
    await session.flush()

    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            session.add_all(
                [
                    IncidentReport(
                        incident=incident, title="Initial findings", version=1, content="..."
                    ),
                    IncidentReport(incident=incident, title="Duplicate", version=1, content="..."),
                ]
            )
            await session.flush()


async def test_embeddings_round_trip_through_pgvector(session: AsyncSession) -> None:
    vector = [0.05] * settings.EMBEDDING_DIMENSIONS
    document = SecurityDocument(
        title="Ransomware containment playbook",
        document_type=DocumentType.PLAYBOOK,
        content="1. Isolate the host.",
        embedding=vector,
        embedding_model="test-embedder",
    )
    session.add(document)
    await session.flush()
    session.expunge(document)

    loaded = await session.get(SecurityDocument, document.id)
    assert loaded is not None
    assert loaded.embedding is not None
    assert len(loaded.embedding) == settings.EMBEDDING_DIMENSIONS
    assert loaded.embedding[0] == pytest.approx(0.05)

    # The column is optional until the embedding pipeline runs.
    unembedded = SecurityDocument(
        title="Access control policy",
        document_type=DocumentType.POLICY,
        content="Least privilege.",
    )
    session.add(unembedded)
    await session.flush()
    assert unembedded.embedding is None


async def test_vector_similarity_search_is_usable(session: AsyncSession) -> None:
    near = [0.1] * settings.EMBEDDING_DIMENSIONS
    far = [-0.1] * settings.EMBEDDING_DIMENSIONS
    session.add_all(
        [
            SecurityDocument(
                title="Near", document_type=DocumentType.RUNBOOK, content="x", embedding=near
            ),
            SecurityDocument(
                title="Far", document_type=DocumentType.RUNBOOK, content="y", embedding=far
            ),
        ]
    )
    await session.flush()

    ranked = await session.execute(
        select(SecurityDocument.title).order_by(
            SecurityDocument.embedding.cosine_distance(near)
        )
    )
    assert ranked.scalars().first() == "Near"


async def test_audit_log_keeps_the_actor_email_after_deletion(session: AsyncSession) -> None:
    actor = await _user(session, username="responder")
    record = AuditLog(
        actor=actor,
        actor_email=actor.email,
        action=AuditAction.STATUS_CHANGE,
        resource_type="incident",
        changes={"status": {"from": "open", "to": "contained"}},
        ip_address="198.51.100.7",
    )
    session.add(record)
    await session.flush()

    await session.delete(actor)
    await session.flush()
    await session.refresh(record)

    assert record.actor_id is None
    assert record.actor_email == "responder@soc.example.com"
    assert record.changes["status"]["to"] == "contained"
