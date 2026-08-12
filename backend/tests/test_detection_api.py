"""Detection over the API, against log entries stored in PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.enums import LogSourceType, Severity, UserRole
from app.models.log_entry import LogEntry
from app.models.log_source import LogSource
from app.services.detection import registry
from tests import synthetic

ANALYZE = "/api/v1/detection/analyze"


@pytest.fixture(autouse=True)
def _clean_registry():
    """Restore the built-in detectors after a test registers its own."""
    yield
    registry.reset()


@pytest.fixture
async def analyst(make_user):
    return await make_user(UserRole.ANALYST)


@pytest.fixture
def headers(analyst, auth_header) -> dict[str, str]:
    return auth_header(analyst)


@pytest.fixture
async def source(session: AsyncSession, analyst) -> LogSource:
    log_source = LogSource(
        name=f"detection-src-{uuid.uuid4().hex[:8]}",
        source_type=LogSourceType.FIREWALL,
        created_by_id=analyst.id,
    )
    session.add(log_source)
    await session.flush()
    return log_source


async def store(session: AsyncSession, source: LogSource, entries: list[LogEntry]) -> None:
    """Persist synthetic entries against a real source."""
    for entry in entries:
        entry.log_source_id = source.id
        session.add(entry)
    await session.flush()


def window_for(entries: list[LogEntry]) -> dict[str, str]:
    """A request window that comfortably contains the entries."""
    start = min(e.event_timestamp for e in entries) - timedelta(minutes=5)
    end = max(e.event_timestamp for e in entries) + timedelta(minutes=5)
    return {"window_start": start.isoformat(), "window_end": end.isoformat()}


def brute_force_entries(count: int = 25) -> list[LogEntry]:
    return [
        synthetic.failed_login(
            source_ip="203.0.113.47", username="j.okafor", offset_seconds=i * 3
        )
        for i in range(count)
    ]


# --- Access control --------------------------------------------------------


async def test_analysis_requires_authentication(client: httpx.AsyncClient) -> None:
    assert (await client.post(ANALYZE, json={})).status_code == 401


async def test_a_viewer_cannot_run_analysis(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    """Analysis writes to the anomaly queue, so it is an analyst action."""
    viewer = await make_user(UserRole.VIEWER)
    response = await client.post(ANALYZE, headers=auth_header(viewer), json={})
    assert response.status_code == 403


async def test_a_viewer_can_read_anomalies(
    client: httpx.AsyncClient, make_user, auth_header
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    assert (await client.get("/api/v1/anomalies", headers=auth_header(viewer))).status_code == 200


async def test_detectors_are_listed(client: httpx.AsyncClient, headers) -> None:
    response = await client.get("/api/v1/detectors", headers=headers)

    assert response.status_code == 200
    names = {item["name"] for item in response.json()}
    assert names == {
        "rule.brute_force",
        "rule.suspicious_ip",
        "statistical.event_burst",
        "statistical.request_frequency",
    }


# --- Detection end to end --------------------------------------------------


async def test_brute_force_is_detected_and_persisted(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)

    response = await client.post(
        ANALYZE,
        headers=headers,
        json={"log_source_id": str(source.id), **window_for(entries)},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["entries_analysed"] == 25
    assert body["summary"]["findings"] >= 1
    assert body["summary"]["persisted"] >= 1

    anomaly = next(a for a in body["anomalies"] if a["detector"] == "rule.brute_force")
    assert anomaly["severity"] in ("high", "critical")
    assert 0.0 <= anomaly["score"] <= 1.0
    assert anomaly["evidence"]["failed_attempts"] == 25
    assert anomaly["evidence"]["account"] == "j.okafor"
    assert "T1110" in anomaly["mitre_techniques"]
    assert anomaly["log_source_id"] == str(source.id)

    stored = await session.execute(
        select(func.count()).select_from(Anomaly).where(Anomaly.log_source_id == source.id)
    )
    assert stored.scalar_one() >= 1


async def test_a_persisted_anomaly_carries_its_explanation(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    """The whole point of a rule-based V1: the row explains itself."""
    entries = brute_force_entries()
    await store(session, source, entries)

    await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    anomaly = (
        await session.execute(
            select(Anomaly).where(
                Anomaly.detector == "rule.brute_force",
                Anomaly.log_source_id == source.id,
            )
        )
    ).scalar_one()

    assert anomaly.description and len(anomaly.description) > 30
    assert "25 failed authentication attempts" in anomaly.description
    assert anomaly.evidence["threshold"] == 5
    assert anomaly.evidence["sample_log_entry_ids"]
    assert anomaly.features["failed_attempts"] == 25
    assert anomaly.detector_version == "1.0"
    assert anomaly.fingerprint


async def test_password_spraying_is_detected(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = [
        synthetic.failed_login(
            source_ip="198.51.100.7", username=f"user{i:02d}", offset_seconds=i * 5
        )
        for i in range(14)
    ]
    await store(session, source, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    anomalies = response.json()["anomalies"]
    spray = next(a for a in anomalies if "spraying" in a["title"])
    assert spray["evidence"]["distinct_accounts"] == 14
    assert spray["anomaly_type"] == "behavioral"


async def test_suspicious_ip_is_detected(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = [
        synthetic.connection(
            source_ip="203.0.113.99",
            destination_ip="10.20.3.15",
            destination_port=port,
            offset_seconds=port,
            blocked=True,
        )
        for port in range(1, 61)
    ]
    await store(session, source, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    anomaly = next(
        a for a in response.json()["anomalies"] if a["detector"] == "rule.suspicious_ip"
    )
    assert "port_scan" in anomaly["evidence"]["indicators"]
    assert anomaly["evidence"]["distinct_destination_ports"] == 60


async def test_unusual_frequency_is_detected(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = synthetic.normal_traffic(sources=10, per_source=10)
    entries += [
        synthetic.connection(source_ip="203.0.113.200", offset_seconds=1000 + i)
        for i in range(400)
    ]
    await store(session, source, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    anomaly = next(
        a
        for a in response.json()["anomalies"]
        if a["detector"] == "statistical.request_frequency"
    )
    assert anomaly["evidence"]["source"] == "203.0.113.200"
    assert anomaly["anomaly_type"] == "statistical"


async def test_an_event_burst_is_detected(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = [
        synthetic.connection(source_ip=f"10.20.4.{i % 20}", offset_seconds=i * 12)
        for i in range(100)
    ]
    entries += [
        synthetic.connection(source_ip=f"10.20.5.{i % 50}", offset_seconds=600 + (i % 55))
        for i in range(200)
    ]
    await store(session, source, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    anomaly = next(
        a for a in response.json()["anomalies"] if a["detector"] == "statistical.event_burst"
    )
    assert anomaly["evidence"]["event_count"] >= 200
    assert anomaly["evidence"]["top_sources"]


async def test_normal_traffic_produces_nothing(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    """The result that matters most: a quiet day stays quiet."""
    entries = synthetic.normal_traffic()
    await store(session, source, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    body = response.json()
    assert body["summary"]["entries_analysed"] == len(entries)
    assert body["summary"]["findings"] == 0
    assert body["anomalies"] == []


async def test_an_empty_window_produces_nothing(
    client: httpx.AsyncClient, source: LogSource, headers
) -> None:
    response = await client.post(ANALYZE, headers=headers, json={"log_source_id": str(source.id)})

    assert response.status_code == 200
    assert response.json()["summary"]["entries_analysed"] == 0
    assert response.json()["summary"]["findings"] == 0


# --- Persistence semantics -------------------------------------------------


async def test_re_analysis_does_not_duplicate(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    """A scheduled run and an analyst will both analyse the same window."""
    entries = brute_force_entries()
    await store(session, source, entries)
    payload = {"log_source_id": str(source.id), **window_for(entries)}

    first = await client.post(ANALYZE, headers=headers, json=payload)
    second = await client.post(ANALYZE, headers=headers, json=payload)

    assert first.json()["summary"]["duplicates_skipped"] == 0
    assert second.json()["summary"]["duplicates_skipped"] >= 1

    total = await session.execute(
        select(func.count()).select_from(Anomaly).where(Anomaly.log_source_id == source.id)
    )
    assert total.scalar_one() == first.json()["summary"]["persisted"]

    # The second run still reports what it found, even though it stored nothing new.
    assert second.json()["summary"]["findings"] == first.json()["summary"]["findings"]
    assert len(second.json()["findings"]) == len(first.json()["findings"])


async def test_persist_false_writes_nothing(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    """Lets an analyst preview a tuning change without filling the queue."""
    entries = brute_force_entries()
    await store(session, source, entries)

    response = await client.post(
        ANALYZE,
        headers=headers,
        json={"log_source_id": str(source.id), "persist": False, **window_for(entries)},
    )

    body = response.json()
    assert body["summary"]["findings"] >= 1
    assert body["summary"]["persisted"] == 0
    assert body["anomalies"] == []

    # The findings are still returned, or a preview would show nothing.
    assert len(body["findings"]) == body["summary"]["findings"]
    assert body["findings"][0]["reason"]
    assert body["findings"][0]["evidence"]

    stored = await session.execute(
        select(func.count()).select_from(Anomaly).where(Anomaly.log_source_id == source.id)
    )
    assert stored.scalar_one() == 0


async def test_findings_are_returned_worst_first(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    entries += [
        synthetic.connection(
            source_ip="203.0.113.99", destination_port=port, offset_seconds=port, blocked=True
        )
        for port in range(1, 25)
    ]
    await store(session, source, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    scores = [a["score"] for a in response.json()["anomalies"]]
    assert scores == sorted(scores, reverse=True)


async def test_the_severity_breakdown_matches_the_findings(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)

    body = (
        await client.post(
            ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
        )
    ).json()

    assert sum(body["summary"]["by_severity"].values()) == body["summary"]["findings"]


# --- Request handling ------------------------------------------------------


async def test_a_single_detector_can_be_selected(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)

    response = await client.post(
        ANALYZE,
        headers=headers,
        json={
            "log_source_id": str(source.id),
            "detectors": ["rule.brute_force"],
            **window_for(entries),
        },
    )

    assert response.json()["detectors_run"] == ["rule.brute_force"]


async def test_an_unknown_detector_is_a_client_error(
    client: httpx.AsyncClient, source: LogSource, headers
) -> None:
    """Silently running fewer detectors would hide the typo."""
    response = await client.post(
        ANALYZE,
        headers=headers,
        json={"log_source_id": str(source.id), "detectors": ["rule.does_not_exist"]},
    )

    assert response.status_code == 400
    assert "does_not_exist" in response.json()["detail"]


async def test_an_inverted_window_is_rejected(
    client: httpx.AsyncClient, source: LogSource, headers
) -> None:
    now = datetime.now(UTC)
    response = await client.post(
        ANALYZE,
        headers=headers,
        json={
            "window_start": now.isoformat(),
            "window_end": (now - timedelta(hours=1)).isoformat(),
        },
    )
    assert response.status_code == 422


async def test_an_unknown_source_is_not_found(client: httpx.AsyncClient, headers) -> None:
    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(uuid.uuid4())}
    )
    assert response.status_code == 404


async def test_unexpected_fields_are_rejected(client: httpx.AsyncClient, headers) -> None:
    response = await client.post(ANALYZE, headers=headers, json={"threshold": 3})
    assert response.status_code == 422


async def test_analysis_only_reads_the_requested_source(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, analyst, headers
) -> None:
    other = LogSource(
        name=f"other-{uuid.uuid4().hex[:8]}",
        source_type=LogSourceType.IDS,
        created_by_id=analyst.id,
    )
    session.add(other)
    await session.flush()

    entries = brute_force_entries()
    await store(session, other, entries)

    response = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )
    assert response.json()["summary"]["entries_analysed"] == 0


async def test_the_window_bounds_what_is_analysed(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)

    # A window ending before the traffic starts.
    start = min(e.event_timestamp for e in entries)
    response = await client.post(
        ANALYZE,
        headers=headers,
        json={
            "log_source_id": str(source.id),
            "window_start": (start - timedelta(hours=2)).isoformat(),
            "window_end": (start - timedelta(hours=1)).isoformat(),
        },
    )
    assert response.json()["summary"]["entries_analysed"] == 0


async def test_the_entry_cap_is_reported(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    """Partial coverage must be visible, not silent."""
    entries = brute_force_entries(30)
    await store(session, source, entries)

    response = await client.post(
        ANALYZE,
        headers=headers,
        json={"log_source_id": str(source.id), "limit": 10, **window_for(entries)},
    )

    body = response.json()
    assert body["summary"]["entries_analysed"] == 10
    assert body["summary"]["truncated"] is True


# --- Reading anomalies back ------------------------------------------------


async def test_anomalies_can_be_listed_and_filtered(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)
    await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    listed = await client.get(
        "/api/v1/anomalies",
        headers=headers,
        params={"log_source_id": str(source.id), "detector": "rule.brute_force"},
    )

    assert listed.status_code == 200
    body = listed.json()
    assert body
    assert all(a["detector"] == "rule.brute_force" for a in body)
    assert [a["score"] for a in body] == sorted((a["score"] for a in body), reverse=True)


async def test_an_anomaly_can_be_fetched_by_id(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)
    created = await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )
    anomaly_id = created.json()["anomalies"][0]["id"]

    fetched = await client.get(f"/api/v1/anomalies/{anomaly_id}", headers=headers)

    assert fetched.status_code == 200
    assert fetched.json()["id"] == anomaly_id
    assert fetched.json()["status"] == "new"


async def test_an_unknown_anomaly_is_not_found(client: httpx.AsyncClient, headers) -> None:
    response = await client.get(f"/api/v1/anomalies/{uuid.uuid4()}", headers=headers)
    assert response.status_code == 404


async def test_filtering_by_severity(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    entries = brute_force_entries()
    await store(session, source, entries)
    await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    response = await client.get(
        "/api/v1/anomalies",
        headers=headers,
        params={"log_source_id": str(source.id), "severity": Severity.CRITICAL.value},
    )

    assert response.status_code == 200
    assert all(a["severity"] == "critical" for a in response.json())


# --- Extensibility ---------------------------------------------------------


async def test_a_new_detector_needs_no_change_to_the_api(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    """The property the phase is judged on: an ML detector slots in here.

    A detector defined entirely outside the package is registered, runs through
    the same endpoint, and its findings persist in the same shape -- with no
    change to the engine, the schema or the route.
    """
    from app.models.enums import AnomalyType
    from app.services.detection.types import DetectionContext, Finding

    class ToyModelDetector:
        name = "ml.toy_model"
        version = "0.1"

        def detect(self, context: DetectionContext) -> list[Finding]:
            if not context.entries:
                return []
            return [
                Finding(
                    detector=self.name,
                    detector_version=self.version,
                    anomaly_type=AnomalyType.MACHINE_LEARNING,
                    title="Toy model flagged the window",
                    reason="A stand-in for a model-backed detector added later.",
                    score=0.72,
                    evidence={"entries": len(context.entries)},
                    features={"entries": len(context.entries)},
                    entity="toy",
                    window_key="fixed",
                )
            ]

    registry.register(ToyModelDetector())

    entries = brute_force_entries(6)
    await store(session, source, entries)

    response = await client.post(
        ANALYZE,
        headers=headers,
        json={
            "log_source_id": str(source.id),
            "detectors": ["ml.toy_model"],
            **window_for(entries),
        },
    )

    assert response.status_code == 200
    anomaly = response.json()["anomalies"][0]
    assert anomaly["detector"] == "ml.toy_model"
    assert anomaly["anomaly_type"] == "machine_learning"
    assert anomaly["severity"] == "high"  # 0.72 lands in the HIGH band


async def test_analysis_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, source: LogSource, headers
) -> None:
    from app.models.audit_log import AuditLog

    entries = brute_force_entries()
    await store(session, source, entries)
    await client.post(
        ANALYZE, headers=headers, json={"log_source_id": str(source.id), **window_for(entries)}
    )

    entries_logged = (
        await session.execute(
            select(AuditLog).where(AuditLog.resource_type == "anomaly_analysis")
        )
    ).scalars()
    contexts = [entry.context for entry in entries_logged]
    assert any(ctx.get("findings", 0) >= 1 for ctx in contexts)
