"""Incident lifecycle rules.

Kept out of the endpoint layer so the transitions and their side effects are
testable without HTTP, and so the audit entry is written in the same transaction
as the change it describes.

A status change is audited separately from an ordinary field edit. "Who moved
this to resolved, and when" is the question asked after the fact, and it should
not have to be dug out of a generic update record.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.anomaly import Anomaly
from app.models.enums import AuditAction, IncidentStatus
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.user import User
from app.services import audit

logger = get_logger(__name__)


class AnomalyNotFoundError(Exception):
    """One or more anomaly ids do not exist."""

    def __init__(self, missing: list[uuid.UUID]) -> None:
        self.missing = missing
        super().__init__(f"unknown anomaly id(s): {', '.join(str(item) for item in missing)}")


@dataclass(frozen=True, slots=True)
class FieldChange:
    """One field's before and after, for the audit trail."""

    field: str
    before: Any
    after: Any

    def as_dict(self) -> dict[str, Any]:
        return {
            "from": _jsonable(self.before),
            "to": _jsonable(self.after),
        }


def _jsonable(value: Any) -> Any:
    """Enums and datetimes are not JSON; store what they represent."""
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return getattr(value, "value", str(value))


def apply_status(incident: Incident, new_status: IncidentStatus) -> None:
    """Move an incident to a new state and stamp the timeline.

    Reopening clears ``resolved_at``: leaving the old timestamp behind would
    make an incident look resolved while it is being worked again, and would
    corrupt any time-to-resolve figure computed from it.
    """
    if incident.status == new_status:
        return

    now = datetime.now(UTC)
    incident.status = new_status

    if new_status is IncidentStatus.INVESTIGATING and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    elif new_status is IncidentStatus.RESOLVED:
        # An incident resolved without ever being marked investigating was still
        # picked up by someone; record that it was acknowledged.
        if incident.acknowledged_at is None:
            incident.acknowledged_at = now
        incident.resolved_at = now
    elif new_status is IncidentStatus.OPEN:
        incident.resolved_at = None


async def create(
    session: AsyncSession,
    *,
    values: dict[str, Any],
    actor: User,
    anomaly_ids: list[uuid.UUID] | None = None,
    request: Request | None = None,
) -> Incident:
    """Open an incident, optionally linking anomalies as its evidence.

    The anomaly ids are resolved *before* the incident is written. Creating it
    first and failing on a bad id would leave an empty incident behind for a
    request that returned an error.
    """
    evidence = await _resolve_anomalies(session, anomaly_ids or [])

    incident = Incident(**values, created_by_id=actor.id)
    session.add(incident)
    await session.flush()

    for anomaly in evidence:
        anomaly.incident_id = incident.id
    if evidence:
        await session.flush()

    linked = evidence
    await session.refresh(incident)
    await audit.record(
        session,
        action=AuditAction.CREATE,
        resource_type="incident",
        actor=actor,
        resource_id=incident.id,
        description=f"opened incident {incident.reference}: {incident.title}",
        context={
            "reference": incident.reference,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "attack_type": incident.attack_type.value,
            "linked_anomalies": len(linked),
        },
        request=request,
    )
    return incident


async def update(
    session: AsyncSession,
    incident: Incident,
    *,
    updates: dict[str, Any],
    actor: User,
    request: Request | None = None,
) -> list[FieldChange]:
    """Apply an update, auditing the status change apart from the rest.

    Returns the fields that actually changed; setting a field to the value it
    already holds is not a change and is not recorded.
    """
    new_status: IncidentStatus | None = updates.pop("status", None)
    changes: list[FieldChange] = []

    for field, value in updates.items():
        before = getattr(incident, field)
        if before == value:
            continue
        setattr(incident, field, value)
        changes.append(FieldChange(field=field, before=before, after=value))

    status_change: FieldChange | None = None
    if new_status is not None and incident.status != new_status:
        status_change = FieldChange(
            field="status", before=incident.status, after=new_status
        )
        apply_status(incident, new_status)

    if not changes and status_change is None:
        return []

    await session.flush()

    if changes:
        await audit.record(
            session,
            action=AuditAction.UPDATE,
            resource_type="incident",
            actor=actor,
            resource_id=incident.id,
            description=(
                f"updated {incident.reference}: "
                f"{', '.join(change.field for change in changes)}"
            ),
            changes={change.field: change.as_dict() for change in changes},
            request=request,
        )

    if status_change is not None:
        await audit.record(
            session,
            action=AuditAction.STATUS_CHANGE,
            resource_type="incident",
            actor=actor,
            resource_id=incident.id,
            description=(
                f"{incident.reference} moved from "
                f"{_jsonable(status_change.before)} to {_jsonable(status_change.after)}"
            ),
            changes={"status": status_change.as_dict()},
            context={"reference": incident.reference},
            request=request,
        )
        # A system note keeps the transition visible on the incident itself, not
        # only in the audit log an analyst may never open.
        session.add(
            IncidentNote(
                incident_id=incident.id,
                author_id=actor.id,
                author_username=actor.username,
                body=(
                    f"Status changed from {_jsonable(status_change.before)} to "
                    f"{_jsonable(status_change.after)}."
                ),
                is_system=True,
            )
        )
        await session.flush()
        changes.append(status_change)

    return changes


async def _resolve_anomalies(
    session: AsyncSession, anomaly_ids: list[uuid.UUID]
) -> list[Anomaly]:
    """Fetch every id, or raise naming the ones that do not exist.

    All-or-nothing rather than linking whatever happened to match: a caller that
    mistyped an id should hear about it, not receive a partial link it did not
    ask for.
    """
    if not anomaly_ids:
        return []

    unique = list(dict.fromkeys(anomaly_ids))
    found = list(
        (await session.execute(select(Anomaly).where(Anomaly.id.in_(unique)))).scalars()
    )
    if len(found) != len(unique):
        present = {anomaly.id for anomaly in found}
        raise AnomalyNotFoundError([item for item in unique if item not in present])
    return found


async def link_anomalies(
    session: AsyncSession,
    incident: Incident,
    anomaly_ids: list[uuid.UUID],
) -> list[Anomaly]:
    """Attach anomalies to an incident.

    An anomaly belongs to at most one incident, so linking one that is already
    attached elsewhere moves it.
    """
    found = await _resolve_anomalies(session, anomaly_ids)
    for anomaly in found:
        anomaly.incident_id = incident.id
    if found:
        await session.flush()
    return found


async def unlink_anomaly(
    session: AsyncSession, incident: Incident, anomaly: Anomaly
) -> bool:
    """Detach one anomaly. Returns False when it was not attached here."""
    if anomaly.incident_id != incident.id:
        return False
    anomaly.incident_id = None
    await session.flush()
    return True


async def add_note(
    session: AsyncSession,
    incident: Incident,
    *,
    body: str,
    actor: User,
    request: Request | None = None,
) -> IncidentNote:
    """Record an analyst's note against an incident."""
    note = IncidentNote(
        incident_id=incident.id,
        author_id=actor.id,
        author_username=actor.username,
        body=body,
        is_system=False,
    )
    session.add(note)
    await session.flush()

    await audit.record(
        session,
        action=AuditAction.UPDATE,
        resource_type="incident",
        actor=actor,
        resource_id=incident.id,
        description=f"note added to {incident.reference}",
        context={"note_id": str(note.id)},
        request=request,
    )
    return note
