"""Incident management over the API."""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.audit_log import AuditLog
from app.models.enums import (
    AnomalyType,
    AttackType,
    AuditAction,
    IncidentStatus,
    Severity,
    UserRole,
)
from app.models.incident import Incident

INCIDENTS = "/api/v1/incidents"

MINIMAL = {"title": "Suspicious outbound traffic to flagged infrastructure"}


@pytest.fixture
async def analyst(make_user):
    return await make_user(UserRole.ANALYST)


@pytest.fixture
def headers(analyst, auth_header) -> dict[str, str]:
    return auth_header(analyst)


@pytest.fixture
async def admin(make_user):
    return await make_user(UserRole.ADMIN)


@pytest.fixture
def admin_headers(admin, auth_header) -> dict[str, str]:
    return auth_header(admin)


@pytest.fixture
async def viewer(make_user):
    return await make_user(UserRole.VIEWER)


@pytest.fixture
def viewer_headers(viewer, auth_header) -> dict[str, str]:
    return auth_header(viewer)


@pytest.fixture
async def make_anomaly(session: AsyncSession):
    """Create a stored anomaly to link as evidence."""

    async def _make(title: str = "Repeated failed logins", score: float = 0.9) -> Anomaly:
        anomaly = Anomaly(
            title=title,
            anomaly_type=AnomalyType.THRESHOLD,
            severity=Severity.HIGH,
            score=score,
            detector="rule.brute_force",
            detector_version="1.0",
        )
        session.add(anomaly)
        await session.flush()
        return anomaly

    return _make


async def create_incident(
    client: httpx.AsyncClient, headers: dict[str, str], **overrides
) -> dict:
    response = await client.post(INCIDENTS, headers=headers, json={**MINIMAL, **overrides})
    assert response.status_code == 201, response.text
    return response.json()


async def audit_entries(
    session: AsyncSession, incident_id: str, action: AuditAction
) -> list[AuditLog]:
    """Audit rows for one incident, scoped so the shared table cannot skew it."""
    result = await session.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "incident",
            AuditLog.resource_id == uuid.UUID(incident_id),
            AuditLog.action == action,
        )
    )
    return list(result.scalars())


# --- Creation --------------------------------------------------------------


async def test_an_analyst_can_open_an_incident(client: httpx.AsyncClient, headers) -> None:
    body = await create_incident(
        client,
        headers,
        severity=Severity.HIGH.value,
        attack_type=AttackType.DATA_EXFILTRATION.value,
        summary="Large transfer to an uncategorised host",
        tags=["egress", "after-hours"],
    )

    assert body["status"] == IncidentStatus.OPEN.value
    assert body["severity"] == Severity.HIGH.value
    assert body["attack_type"] == AttackType.DATA_EXFILTRATION.value
    assert body["tags"] == ["egress", "after-hours"]
    assert body["resolved_at"] is None
    assert body["created_at"] and body["updated_at"]
    assert uuid.UUID(body["id"])


async def test_an_incident_gets_a_quotable_reference(client: httpx.AsyncClient, headers) -> None:
    body = await create_incident(client, headers)

    assert body["number"] >= 1000
    assert body["reference"] == f"INC-{body['number']}"


async def test_references_are_distinct(client: httpx.AsyncClient, headers) -> None:
    first = await create_incident(client, headers)
    second = await create_incident(client, headers)
    assert first["reference"] != second["reference"]


async def test_an_incident_defaults_to_open_and_unknown(
    client: httpx.AsyncClient, headers
) -> None:
    body = await create_incident(client, headers)

    assert body["status"] == IncidentStatus.OPEN.value
    assert body["severity"] == Severity.MEDIUM.value
    assert body["attack_type"] == AttackType.UNKNOWN.value
    assert body["priority"] == "p3"


async def test_status_cannot_be_set_at_creation(client: httpx.AsyncClient, headers) -> None:
    """Every transition must go through the audited update path."""
    response = await client.post(
        INCIDENTS, headers=headers, json={**MINIMAL, "status": "resolved"}
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {},  # no title
        {"title": "ab"},  # too short
        {"title": "A valid title", "severity": "catastrophic"},
        {"title": "A valid title", "attack_type": "not-a-real-attack"},
        {"title": "A valid title", "resolved_at": "2026-08-12T00:00:00Z"},
        {"title": "A valid title", "number": 5},
    ],
)
async def test_invalid_creation_payloads_are_rejected(
    client: httpx.AsyncClient, headers, payload: dict
) -> None:
    """Timestamps and the reference number are the server's to set."""
    response = await client.post(INCIDENTS, headers=headers, json=payload)
    assert response.status_code == 422


async def test_an_unknown_assignee_is_rejected(client: httpx.AsyncClient, headers) -> None:
    response = await client.post(
        INCIDENTS, headers=headers, json={**MINIMAL, "assigned_to_id": str(uuid.uuid4())}
    )
    assert response.status_code == 422


# --- Retrieval -------------------------------------------------------------


async def test_an_incident_can_be_fetched(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)

    response = await client.get(f"{INCIDENTS}/{created['id']}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["anomalies"] == []
    assert body["notes"] == []


async def test_incidents_can_be_listed(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)

    response = await client.get(INCIDENTS, headers=headers)

    assert response.status_code == 200
    assert created["id"] in [item["id"] for item in response.json()]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", IncidentStatus.OPEN.value),
        ("severity", Severity.CRITICAL.value),
        ("attack_type", AttackType.RANSOMWARE.value),
    ],
)
async def test_incidents_can_be_filtered(
    client: httpx.AsyncClient, headers, field: str, value: str
) -> None:
    await create_incident(
        client, headers, severity=Severity.CRITICAL.value, attack_type=AttackType.RANSOMWARE.value
    )

    response = await client.get(INCIDENTS, headers=headers, params={field: value})

    assert response.status_code == 200
    assert response.json()
    assert all(item[field] == value for item in response.json())


async def test_filtering_by_assignee(client: httpx.AsyncClient, headers, analyst) -> None:
    await create_incident(client, headers, assigned_to_id=str(analyst.id))

    response = await client.get(
        INCIDENTS, headers=headers, params={"assigned_to_id": str(analyst.id)}
    )

    assert response.json()
    assert all(item["assigned_to_id"] == str(analyst.id) for item in response.json())


async def test_an_unknown_incident_is_not_found(client: httpx.AsyncClient, headers) -> None:
    response = await client.get(f"{INCIDENTS}/{uuid.uuid4()}", headers=headers)
    assert response.status_code == 404


# --- Updates ---------------------------------------------------------------


async def test_fields_can_be_updated(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)

    response = await client.patch(
        f"{INCIDENTS}/{created['id']}",
        headers=headers,
        json={"severity": Severity.CRITICAL.value, "attack_type": AttackType.MALWARE.value},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["severity"] == Severity.CRITICAL.value
    assert body["attack_type"] == AttackType.MALWARE.value
    assert body["title"] == created["title"]  # untouched


async def test_an_empty_update_changes_nothing(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)

    response = await client.patch(f"{INCIDENTS}/{created['id']}", headers=headers, json={})

    assert response.status_code == 200
    assert response.json()["severity"] == created["severity"]


async def test_moving_to_investigating_stamps_acknowledged(
    client: httpx.AsyncClient, headers
) -> None:
    created = await create_incident(client, headers)
    assert created["acknowledged_at"] is None

    body = (
        await client.patch(
            f"{INCIDENTS}/{created['id']}",
            headers=headers,
            json={"status": IncidentStatus.INVESTIGATING.value},
        )
    ).json()

    assert body["status"] == IncidentStatus.INVESTIGATING.value
    assert body["acknowledged_at"] is not None
    assert body["resolved_at"] is None


async def test_resolving_stamps_resolved_at(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)

    body = (
        await client.patch(
            f"{INCIDENTS}/{created['id']}",
            headers=headers,
            json={"status": IncidentStatus.RESOLVED.value},
        )
    ).json()

    assert body["status"] == IncidentStatus.RESOLVED.value
    assert body["resolved_at"] is not None
    # Resolved without an explicit investigating step: still acknowledged.
    assert body["acknowledged_at"] is not None


async def test_reopening_clears_the_resolution_timestamp(
    client: httpx.AsyncClient, headers
) -> None:
    """A stale resolved_at would corrupt any time-to-resolve figure."""
    created = await create_incident(client, headers)
    await client.patch(
        f"{INCIDENTS}/{created['id']}",
        headers=headers,
        json={"status": IncidentStatus.RESOLVED.value},
    )

    reopened = (
        await client.patch(
            f"{INCIDENTS}/{created['id']}",
            headers=headers,
            json={"status": IncidentStatus.OPEN.value},
        )
    ).json()

    assert reopened["status"] == IncidentStatus.OPEN.value
    assert reopened["resolved_at"] is None
    # The acknowledgement stands: it did happen.
    assert reopened["acknowledged_at"] is not None


async def test_a_status_change_leaves_a_note_on_the_incident(
    client: httpx.AsyncClient, headers
) -> None:
    """Visible without opening the audit log."""
    created = await create_incident(client, headers)

    body = (
        await client.patch(
            f"{INCIDENTS}/{created['id']}",
            headers=headers,
            json={"status": IncidentStatus.INVESTIGATING.value},
        )
    ).json()

    system_notes = [note for note in body["notes"] if note["is_system"]]
    assert len(system_notes) == 1
    assert "open" in system_notes[0]["body"]
    assert "investigating" in system_notes[0]["body"]


async def test_reassignment_is_accepted(client: httpx.AsyncClient, headers, admin) -> None:
    created = await create_incident(client, headers)

    body = (
        await client.patch(
            f"{INCIDENTS}/{created['id']}", headers=headers, json={"assigned_to_id": str(admin.id)}
        )
    ).json()

    assert body["assigned_to_id"] == str(admin.id)


async def test_updating_an_unknown_incident_is_not_found(
    client: httpx.AsyncClient, headers
) -> None:
    response = await client.patch(
        f"{INCIDENTS}/{uuid.uuid4()}", headers=headers, json={"severity": "high"}
    )
    assert response.status_code == 404


async def test_unexpected_update_fields_are_rejected(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)
    response = await client.patch(
        f"{INCIDENTS}/{created['id']}", headers=headers, json={"resolved_at": None}
    )
    assert response.status_code == 422


# --- Notes -----------------------------------------------------------------


async def test_an_analyst_can_add_a_note(client: httpx.AsyncClient, headers, analyst) -> None:
    created = await create_incident(client, headers)

    response = await client.post(
        f"{INCIDENTS}/{created['id']}/notes",
        headers=headers,
        json={"body": "Confirmed the source address belongs to a decommissioned host."},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["author_username"] == analyst.username
    assert body["is_system"] is False
    assert body["created_at"]


async def test_notes_are_listed_oldest_first(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)
    for text in ("first observation", "second observation", "third observation"):
        await client.post(
            f"{INCIDENTS}/{created['id']}/notes", headers=headers, json={"body": text}
        )

    response = await client.get(f"{INCIDENTS}/{created['id']}/notes", headers=headers)

    assert response.status_code == 200
    bodies = [note["body"] for note in response.json() if not note["is_system"]]
    assert bodies == ["first observation", "second observation", "third observation"]


async def test_notes_appear_on_the_incident(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)
    await client.post(
        f"{INCIDENTS}/{created['id']}/notes", headers=headers, json={"body": "An observation."}
    )

    body = (await client.get(f"{INCIDENTS}/{created['id']}", headers=headers)).json()
    assert [note["body"] for note in body["notes"]] == ["An observation."]


async def test_an_empty_note_is_rejected(client: httpx.AsyncClient, headers) -> None:
    created = await create_incident(client, headers)
    response = await client.post(
        f"{INCIDENTS}/{created['id']}/notes", headers=headers, json={"body": "   "}
    )
    assert response.status_code == 422


# --- Linking anomalies -----------------------------------------------------


async def test_anomalies_can_be_linked_at_creation(
    client: httpx.AsyncClient, headers, make_anomaly
) -> None:
    first = await make_anomaly("Repeated failed logins")
    second = await make_anomaly("Password spraying")

    body = await create_incident(
        client, headers, anomaly_ids=[str(first.id), str(second.id)]
    )

    assert {a["id"] for a in body["anomalies"]} == {str(first.id), str(second.id)}
    assert body["anomalies"][0]["detector"] == "rule.brute_force"


async def test_several_anomalies_can_be_linked_to_one_incident(
    client: httpx.AsyncClient, session: AsyncSession, headers, make_anomaly
) -> None:
    """The many-to-one shape: one investigation, several pieces of evidence."""
    created = await create_incident(client, headers)
    anomalies = [await make_anomaly(f"Finding {i}") for i in range(4)]

    response = await client.post(
        f"{INCIDENTS}/{created['id']}/anomalies",
        headers=headers,
        json={"anomaly_ids": [str(a.id) for a in anomalies]},
    )

    assert response.status_code == 200
    assert len(response.json()["anomalies"]) == 4

    for anomaly in anomalies:
        await session.refresh(anomaly)
        assert str(anomaly.incident_id) == created["id"]


async def test_linking_is_idempotent(
    client: httpx.AsyncClient, headers, make_anomaly
) -> None:
    created = await create_incident(client, headers)
    anomaly = await make_anomaly()
    payload = {"anomaly_ids": [str(anomaly.id)]}

    await client.post(f"{INCIDENTS}/{created['id']}/anomalies", headers=headers, json=payload)
    second = await client.post(
        f"{INCIDENTS}/{created['id']}/anomalies", headers=headers, json=payload
    )

    assert len(second.json()["anomalies"]) == 1


async def test_linking_moves_an_anomaly_between_incidents(
    client: httpx.AsyncClient, headers, make_anomaly
) -> None:
    """An anomaly belongs to at most one incident."""
    first = await create_incident(client, headers, title="First investigation opened")
    second = await create_incident(client, headers, title="Second investigation opened")
    anomaly = await make_anomaly()

    await client.post(
        f"{INCIDENTS}/{first['id']}/anomalies",
        headers=headers,
        json={"anomaly_ids": [str(anomaly.id)]},
    )
    await client.post(
        f"{INCIDENTS}/{second['id']}/anomalies",
        headers=headers,
        json={"anomaly_ids": [str(anomaly.id)]},
    )

    first_body = (await client.get(f"{INCIDENTS}/{first['id']}", headers=headers)).json()
    second_body = (await client.get(f"{INCIDENTS}/{second['id']}", headers=headers)).json()
    assert first_body["anomalies"] == []
    assert len(second_body["anomalies"]) == 1


async def test_an_anomaly_can_be_unlinked(
    client: httpx.AsyncClient, session: AsyncSession, headers, make_anomaly
) -> None:
    anomaly = await make_anomaly()
    created = await create_incident(client, headers, anomaly_ids=[str(anomaly.id)])

    response = await client.delete(
        f"{INCIDENTS}/{created['id']}/anomalies/{anomaly.id}", headers=headers
    )

    assert response.status_code == 200
    assert response.json()["anomalies"] == []
    await session.refresh(anomaly)
    assert anomaly.incident_id is None


async def test_unlinking_an_unrelated_anomaly_conflicts(
    client: httpx.AsyncClient, headers, make_anomaly
) -> None:
    created = await create_incident(client, headers)
    anomaly = await make_anomaly()

    response = await client.delete(
        f"{INCIDENTS}/{created['id']}/anomalies/{anomaly.id}", headers=headers
    )
    assert response.status_code == 409


async def test_linking_an_unknown_anomaly_is_rejected(
    client: httpx.AsyncClient, headers
) -> None:
    """A mistyped id must not silently link a subset."""
    created = await create_incident(client, headers)
    response = await client.post(
        f"{INCIDENTS}/{created['id']}/anomalies",
        headers=headers,
        json={"anomaly_ids": [str(uuid.uuid4())]},
    )
    assert response.status_code == 422


async def test_creating_with_an_unknown_anomaly_is_rejected(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    response = await client.post(
        INCIDENTS, headers=headers, json={**MINIMAL, "anomaly_ids": [str(uuid.uuid4())]}
    )

    assert response.status_code == 422
    # The incident must not have been left behind by the failed link.
    remaining = await session.execute(
        select(Incident).where(Incident.title == MINIMAL["title"])
    )
    assert remaining.scalars().all() == []


async def test_deleting_an_incident_leaves_its_anomalies(
    client: httpx.AsyncClient, session: AsyncSession, admin_headers, make_anomaly
) -> None:
    """Evidence outlives the investigation it was attached to."""
    anomaly = await make_anomaly()
    created = await create_incident(client, admin_headers, anomaly_ids=[str(anomaly.id)])

    response = await client.delete(f"{INCIDENTS}/{created['id']}", headers=admin_headers)

    assert response.status_code == 204
    await session.refresh(anomaly)
    assert anomaly.incident_id is None


# --- Authorization ---------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("post", INCIDENTS, MINIMAL),
        ("get", INCIDENTS, None),
    ],
)
async def test_incident_routes_require_authentication(
    client: httpx.AsyncClient, method: str, path: str, body: dict | None
) -> None:
    response = await client.request(method.upper(), path, json=body)
    assert response.status_code == 401


async def test_a_viewer_can_read_but_not_create(
    client: httpx.AsyncClient, headers, viewer_headers
) -> None:
    created = await create_incident(client, headers)

    assert (await client.get(INCIDENTS, headers=viewer_headers)).status_code == 200
    assert (
        await client.get(f"{INCIDENTS}/{created['id']}", headers=viewer_headers)
    ).status_code == 200
    assert (
        await client.post(INCIDENTS, headers=viewer_headers, json=MINIMAL)
    ).status_code == 403


async def test_a_viewer_cannot_update_or_annotate(
    client: httpx.AsyncClient, headers, viewer_headers, make_anomaly
) -> None:
    created = await create_incident(client, headers)
    anomaly = await make_anomaly()

    assert (
        await client.patch(
            f"{INCIDENTS}/{created['id']}", headers=viewer_headers, json={"severity": "high"}
        )
    ).status_code == 403
    assert (
        await client.post(
            f"{INCIDENTS}/{created['id']}/notes", headers=viewer_headers, json={"body": "no"}
        )
    ).status_code == 403
    assert (
        await client.post(
            f"{INCIDENTS}/{created['id']}/anomalies",
            headers=viewer_headers,
            json={"anomaly_ids": [str(anomaly.id)]},
        )
    ).status_code == 403


async def test_a_viewer_can_read_notes(
    client: httpx.AsyncClient, headers, viewer_headers
) -> None:
    created = await create_incident(client, headers)
    await client.post(
        f"{INCIDENTS}/{created['id']}/notes", headers=headers, json={"body": "An observation."}
    )

    response = await client.get(f"{INCIDENTS}/{created['id']}/notes", headers=viewer_headers)
    assert response.status_code == 200
    assert len(response.json()) == 1


async def test_deletion_is_reserved_for_admins(
    client: httpx.AsyncClient, headers, viewer_headers, admin_headers
) -> None:
    created = await create_incident(client, headers)

    assert (
        await client.delete(f"{INCIDENTS}/{created['id']}", headers=viewer_headers)
    ).status_code == 403
    assert (
        await client.delete(f"{INCIDENTS}/{created['id']}", headers=headers)
    ).status_code == 403
    assert (
        await client.delete(f"{INCIDENTS}/{created['id']}", headers=admin_headers)
    ).status_code == 204


async def test_an_admin_has_full_access(
    client: httpx.AsyncClient, admin_headers, make_anomaly
) -> None:
    anomaly = await make_anomaly()
    created = await create_incident(client, admin_headers)

    assert (
        await client.patch(
            f"{INCIDENTS}/{created['id']}", headers=admin_headers, json={"status": "investigating"}
        )
    ).status_code == 200
    assert (
        await client.post(
            f"{INCIDENTS}/{created['id']}/anomalies",
            headers=admin_headers,
            json={"anomaly_ids": [str(anomaly.id)]},
        )
    ).status_code == 200
    assert (
        await client.delete(f"{INCIDENTS}/{created['id']}", headers=admin_headers)
    ).status_code == 204


# --- Audit trail -----------------------------------------------------------


async def test_creation_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, headers, analyst
) -> None:
    created = await create_incident(client, headers, severity=Severity.HIGH.value)

    entries = await audit_entries(session, created["id"], AuditAction.CREATE)

    assert len(entries) == 1
    assert entries[0].actor_id == analyst.id
    assert entries[0].context["reference"] == created["reference"]
    assert entries[0].context["severity"] == Severity.HIGH.value


async def test_updates_are_audited_with_before_and_after(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    created = await create_incident(client, headers)

    await client.patch(
        f"{INCIDENTS}/{created['id']}", headers=headers, json={"severity": Severity.CRITICAL.value}
    )

    entries = await audit_entries(session, created["id"], AuditAction.UPDATE)
    assert len(entries) == 1
    assert entries[0].changes["severity"] == {"from": "medium", "to": "critical"}


async def test_status_changes_are_audited_separately(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    """"Who resolved this?" should not need digging out of a generic update."""
    created = await create_incident(client, headers)

    await client.patch(
        f"{INCIDENTS}/{created['id']}",
        headers=headers,
        json={"status": IncidentStatus.RESOLVED.value},
    )

    status_entries = await audit_entries(session, created["id"], AuditAction.STATUS_CHANGE)
    assert len(status_entries) == 1
    assert status_entries[0].changes["status"] == {"from": "open", "to": "resolved"}
    assert created["reference"] in status_entries[0].description

    # A status move is not also recorded as an ordinary field update.
    assert await audit_entries(session, created["id"], AuditAction.UPDATE) == []


async def test_an_unchanged_field_is_not_audited(
    client: httpx.AsyncClient, session: AsyncSession, headers
) -> None:
    """Setting a field to the value it already holds is not a change."""
    created = await create_incident(client, headers, severity=Severity.HIGH.value)

    await client.patch(
        f"{INCIDENTS}/{created['id']}", headers=headers, json={"severity": Severity.HIGH.value}
    )

    assert await audit_entries(session, created["id"], AuditAction.UPDATE) == []
    assert await audit_entries(session, created["id"], AuditAction.STATUS_CHANGE) == []


async def test_notes_and_links_are_audited(
    client: httpx.AsyncClient, session: AsyncSession, headers, make_anomaly
) -> None:
    created = await create_incident(client, headers)
    anomaly = await make_anomaly()

    await client.post(
        f"{INCIDENTS}/{created['id']}/notes", headers=headers, json={"body": "An observation."}
    )
    await client.post(
        f"{INCIDENTS}/{created['id']}/anomalies",
        headers=headers,
        json={"anomaly_ids": [str(anomaly.id)]},
    )

    entries = await audit_entries(session, created["id"], AuditAction.UPDATE)
    descriptions = " ".join(entry.description or "" for entry in entries)
    assert "note added" in descriptions
    assert "linked 1 anomaly" in descriptions


async def test_deletion_is_audited(
    client: httpx.AsyncClient, session: AsyncSession, admin_headers, admin
) -> None:
    created = await create_incident(client, admin_headers)

    await client.delete(f"{INCIDENTS}/{created['id']}", headers=admin_headers)

    entries = await audit_entries(session, created["id"], AuditAction.DELETE)
    assert len(entries) == 1
    assert entries[0].actor_id == admin.id
    assert entries[0].context["reference"] == created["reference"]
