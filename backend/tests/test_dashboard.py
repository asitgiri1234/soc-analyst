"""The dashboard's aggregate counts and an incident's log evidence.

Both endpoints exist because the console needs them and the browser must not
compute them: a chart tallied from a paginated page describes the page, and log
evidence assembled client-side would mean shipping the whole log table to it.

The stats assertions are written as *deltas* -- read the counts, create data,
read them again -- rather than as absolutes. An absolute assertion here would
pass only on an empty database and start failing the moment the suite is run
against one that has been used.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.enums import (
    AnomalyType,
    LogSourceType,
    Severity,
    UserRole,
)
from app.models.incident import Incident
from app.models.log_entry import LogEntry
from app.models.log_source import LogSource

STATS = "/api/v1/dashboard/stats"
INCIDENTS = "/api/v1/incidents"


@pytest.fixture
async def analyst(make_user):
    return await make_user(UserRole.ANALYST)


@pytest.fixture
def headers(analyst, auth_header) -> dict[str, str]:
    return auth_header(analyst)


@pytest.fixture
async def viewer(make_user):
    return await make_user(UserRole.VIEWER)


@pytest.fixture
def viewer_headers(viewer, auth_header) -> dict[str, str]:
    return auth_header(viewer)


@pytest.fixture
async def source(session: AsyncSession) -> LogSource:
    log_source = LogSource(
        name=f"dashboard-source-{uuid.uuid4().hex[:8]}",
        source_type=LogSourceType.AUTHENTICATION,
    )
    session.add(log_source)
    await session.flush()
    return log_source


@pytest.fixture
async def make_entry(session: AsyncSession, source: LogSource):
    """A stored log entry an anomaly can cite."""

    async def _make(message: str = "Failed password for root", **overrides) -> LogEntry:
        entry = LogEntry(
            log_source_id=source.id,
            event_timestamp=overrides.pop("event_timestamp", datetime.now(UTC)),
            severity=overrides.pop("severity", Severity.HIGH),
            message=message,
            source_ip=overrides.pop("source_ip", "203.0.113.10"),
            username=overrides.pop("username", "root"),
            **overrides,
        )
        session.add(entry)
        await session.flush()
        return entry

    return _make


@pytest.fixture
async def make_anomaly(session: AsyncSession, source: LogSource):
    async def _make(entry: LogEntry | None = None, **overrides) -> Anomaly:
        anomaly = Anomaly(
            log_source_id=source.id,
            log_entry_id=entry.id if entry else None,
            title=overrides.pop("title", "Repeated failed logins"),
            anomaly_type=overrides.pop("anomaly_type", AnomalyType.THRESHOLD),
            severity=overrides.pop("severity", Severity.HIGH),
            score=overrides.pop("score", 0.91),
            detector="rule.brute_force",
            detector_version="1.0",
            **overrides,
        )
        session.add(anomaly)
        await session.flush()
        return anomaly

    return _make


async def create_incident(
    client: httpx.AsyncClient, headers: dict[str, str], **overrides
) -> dict:
    payload = {"title": "Brute force against the bastion host", **overrides}
    response = await client.post(INCIDENTS, headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


# --- Stats -----------------------------------------------------------------


async def test_stats_requires_authentication(client: httpx.AsyncClient) -> None:
    response = await client.get(STATS)
    assert response.status_code == 401


async def test_viewer_may_read_stats(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    """Counts of security data are readable at the lowest tier."""
    response = await client.get(STATS, headers=viewer_headers)
    assert response.status_code == 200
    assert "incidents_total" in response.json()


async def test_stats_counts_a_new_incident(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    before = (await client.get(STATS, headers=headers)).json()
    await create_incident(client, headers, severity="critical")
    after = (await client.get(STATS, headers=headers)).json()

    assert after["incidents_total"] == before["incidents_total"] + 1
    assert after["incidents_open"] == before["incidents_open"] + 1


def _count_for(rows: list[dict], key: str) -> int:
    return next((row["count"] for row in rows if row["key"] == key), 0)


async def test_stats_groups_by_severity(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    before = (await client.get(STATS, headers=headers)).json()
    await create_incident(client, headers, severity="critical")
    after = (await client.get(STATS, headers=headers)).json()

    assert _count_for(after["incidents_by_severity"], "critical") == (
        _count_for(before["incidents_by_severity"], "critical") + 1
    )


async def test_stats_groups_by_attack_type(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    before = (await client.get(STATS, headers=headers)).json()
    await create_incident(client, headers, attack_type="brute_force")
    after = (await client.get(STATS, headers=headers)).json()

    assert _count_for(after["incidents_by_attack_type"], "brute_force") == (
        _count_for(before["incidents_by_attack_type"], "brute_force") + 1
    )


async def test_stats_counts_anomalies_by_type(
    client: httpx.AsyncClient, headers: dict[str, str], make_anomaly
) -> None:
    before = (await client.get(STATS, headers=headers)).json()
    await make_anomaly()
    after = (await client.get(STATS, headers=headers)).json()

    assert after["anomalies_total"] == before["anomalies_total"] + 1
    assert _count_for(after["anomalies_by_type"], "threshold") == (
        _count_for(before["anomalies_by_type"], "threshold") + 1
    )


async def test_stats_time_series_records_today(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    """A newly opened incident lands on today's bucket."""
    await create_incident(client, headers)
    payload = (await client.get(STATS, headers=headers)).json()

    today = datetime.now(UTC).date().isoformat()
    days = [row["day"] for row in payload["incidents_over_time"]]
    assert today in days


async def test_stats_window_excludes_older_incidents(
    client: httpx.AsyncClient, headers: dict[str, str], session: AsyncSession
) -> None:
    """The series honours `days`; an old incident is outside a 1-day window.

    The total is unaffected -- only the time series is windowed -- which is the
    distinction the chart's caption makes.
    """
    incident = await create_incident(client, headers)
    stored = await session.get(Incident, uuid.UUID(incident["id"]))
    assert stored is not None
    stored.detected_at = datetime.now(UTC) - timedelta(days=10)
    await session.flush()

    narrow = (await client.get(f"{STATS}?days=1", headers=headers)).json()
    old_day = (datetime.now(UTC) - timedelta(days=10)).date().isoformat()
    assert old_day not in [row["day"] for row in narrow["incidents_over_time"]]

    wide = (await client.get(f"{STATS}?days=30", headers=headers)).json()
    assert old_day in [row["day"] for row in wide["incidents_over_time"]]


async def test_stats_rejects_an_out_of_range_window(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    assert (await client.get(f"{STATS}?days=0", headers=headers)).status_code == 422
    assert (await client.get(f"{STATS}?days=9999", headers=headers)).status_code == 422


# --- Log evidence ----------------------------------------------------------


async def test_evidence_requires_authentication(client: httpx.AsyncClient) -> None:
    response = await client.get(f"{INCIDENTS}/{uuid.uuid4()}/evidence")
    assert response.status_code == 401


async def test_evidence_returns_entries_behind_linked_anomalies(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_entry,
    make_anomaly,
) -> None:
    entry = await make_entry("Failed password for root from 203.0.113.10")
    anomaly = await make_anomaly(entry)
    incident = await create_incident(client, headers, anomaly_ids=[str(anomaly.id)])

    response = await client.get(f"{INCIDENTS}/{incident['id']}/evidence", headers=headers)
    assert response.status_code == 200

    body = response.json()
    assert [item["id"] for item in body] == [str(entry.id)]
    assert body[0]["message"] == "Failed password for root from 203.0.113.10"
    # The vector and the raw line are machinery, not evidence.
    assert "embedding" not in body[0]
    assert "raw" not in body[0]


async def test_evidence_is_scoped_to_the_incident(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_entry,
    make_anomaly,
) -> None:
    """An entry from the same source, but not cited here, must not leak.

    This is the guard against the endpoint becoming a log search that any
    viewer can page through by quoting an incident id.
    """
    linked_entry = await make_entry("Cited by the linked anomaly")
    unrelated_entry = await make_entry("Same source, different investigation")
    anomaly = await make_anomaly(linked_entry)
    incident = await create_incident(client, headers, anomaly_ids=[str(anomaly.id)])

    response = await client.get(f"{INCIDENTS}/{incident['id']}/evidence", headers=headers)
    returned = {item["id"] for item in response.json()}

    assert str(linked_entry.id) in returned
    assert str(unrelated_entry.id) not in returned


async def test_evidence_is_empty_without_linked_anomalies(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    incident = await create_incident(client, headers)
    response = await client.get(f"{INCIDENTS}/{incident['id']}/evidence", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


async def test_evidence_is_readable_by_a_viewer(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    viewer_headers: dict[str, str],
    make_entry,
    make_anomaly,
) -> None:
    entry = await make_entry()
    anomaly = await make_anomaly(entry)
    incident = await create_incident(client, headers, anomaly_ids=[str(anomaly.id)])

    response = await client.get(
        f"{INCIDENTS}/{incident['id']}/evidence", headers=viewer_headers
    )
    assert response.status_code == 200
    assert len(response.json()) == 1


async def test_evidence_404s_for_an_unknown_incident(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get(f"{INCIDENTS}/{uuid.uuid4()}/evidence", headers=headers)
    assert response.status_code == 404


async def test_evidence_respects_the_limit(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    make_entry,
    make_anomaly,
) -> None:
    anomaly_ids = []
    for index in range(3):
        entry = await make_entry(f"event {index}")
        anomaly = await make_anomaly(entry, title=f"detection {index}")
        anomaly_ids.append(str(anomaly.id))

    incident = await create_incident(client, headers, anomaly_ids=anomaly_ids)

    response = await client.get(
        f"{INCIDENTS}/{incident['id']}/evidence?limit=2", headers=headers
    )
    assert response.status_code == 200
    assert len(response.json()) == 2
