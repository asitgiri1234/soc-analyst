"""Incident management.

Authorization follows the platform's three tiers: VIEWER reads, ANALYST creates
and works incidents, ADMIN additionally deletes them. Deletion is the one
operation reserved for ADMIN -- it destroys an investigation record along with
its notes, which is not something a shift analyst should be able to do by
accident.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import RequireAdmin, RequireAnalyst, RequireViewer, SessionDep
from app.models.anomaly import Anomaly
from app.models.enums import AttackType, AuditAction, IncidentStatus, Severity
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.incident_report import IncidentReport
from app.models.user import User
from app.schemas.analysis import AnalyzeRequest, ReportRead
from app.schemas.incident import (
    AnomalyLink,
    IncidentCreate,
    IncidentRead,
    IncidentSummary,
    IncidentUpdate,
    NoteCreate,
    NoteRead,
)
from app.services import ai, audit
from app.services import incidents as service

router = APIRouter(prefix="/incidents", tags=["incidents"])


async def _load(session: SessionDep, incident_id: uuid.UUID) -> Incident:
    """Fetch an incident with its anomalies and notes, or 404.

    Eager-loaded: the detail response renders both, and lazy loading them would
    be two extra round trips per request under async SQLAlchemy.
    """
    result = await session.execute(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.anomalies), selectinload(Incident.notes))
        # Without this the identity map hands back the instance loaded earlier in
        # the request, whose collections predate the write we just made.
        .execution_options(populate_existing=True)
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


async def _check_assignee(session: SessionDep, assignee_id: uuid.UUID | None) -> None:
    if assignee_id is not None and await session.get(User, assignee_id) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="assigned_to_id does not match a user",
        )


@router.post(
    "", response_model=IncidentRead, status_code=status.HTTP_201_CREATED, summary="Open an incident"
)
async def create_incident(
    payload: IncidentCreate,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> IncidentRead:
    """Open an incident. Requires the analyst role or higher."""
    await _check_assignee(session, payload.assigned_to_id)

    values = payload.model_dump(exclude={"anomaly_ids"})
    try:
        incident = await service.create(
            session,
            values=values,
            actor=analyst,
            anomaly_ids=payload.anomaly_ids,
            request=request,
        )
    except service.AnomalyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    await session.commit()
    return IncidentRead.model_validate(await _load(session, incident.id))


@router.get("", response_model=list[IncidentSummary], summary="List incidents")
async def list_incidents(
    session: SessionDep,
    _viewer: RequireViewer,
    incident_status: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Annotated[Severity | None, Query()] = None,
    attack_type: Annotated[AttackType | None, Query()] = None,
    assigned_to_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[IncidentSummary]:
    """Incidents, most recently detected first."""
    query = select(Incident).order_by(Incident.detected_at.desc())

    if incident_status is not None:
        query = query.where(Incident.status == incident_status)
    if severity is not None:
        query = query.where(Incident.severity == severity)
    if attack_type is not None:
        query = query.where(Incident.attack_type == attack_type)
    if assigned_to_id is not None:
        query = query.where(Incident.assigned_to_id == assigned_to_id)

    result = await session.execute(query.limit(limit).offset(offset))
    return [IncidentSummary.model_validate(incident) for incident in result.scalars()]


@router.get("/{incident_id}", response_model=IncidentRead, summary="Fetch an incident")
async def get_incident(
    incident_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> IncidentRead:
    """One incident with its linked anomalies and notes."""
    return IncidentRead.model_validate(await _load(session, incident_id))


@router.patch("/{incident_id}", response_model=IncidentRead, summary="Update an incident")
async def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> IncidentRead:
    """Change an incident's fields or move it to a new status.

    A status change is audited separately from an ordinary edit and leaves a
    note on the incident, so the transition is visible without opening the audit
    log.
    """
    incident = await _load(session, incident_id)
    updates = payload.model_dump(exclude_unset=True)
    await _check_assignee(session, updates.get("assigned_to_id"))

    await service.update(session, incident, updates=updates, actor=analyst, request=request)
    await session.commit()
    return IncidentRead.model_validate(await _load(session, incident_id))


@router.delete(
    "/{incident_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete an incident (admin)"
)
async def delete_incident(
    incident_id: uuid.UUID,
    session: SessionDep,
    request: Request,
    admin: RequireAdmin,
) -> Response:
    """Delete an incident and its notes. Linked anomalies survive, unlinked."""
    incident = await _load(session, incident_id)
    reference = incident.reference

    await audit.record(
        session,
        action=AuditAction.DELETE,
        resource_type="incident",
        actor=admin,
        resource_id=incident.id,
        description=f"deleted incident {reference}",
        context={"reference": reference, "title": incident.title},
        request=request,
    )
    await session.delete(incident)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Notes -----------------------------------------------------------------


@router.post(
    "/{incident_id}/notes",
    response_model=NoteRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note",
)
async def add_note(
    incident_id: uuid.UUID,
    payload: NoteCreate,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> NoteRead:
    incident = await _load(session, incident_id)
    note = await service.add_note(
        session, incident, body=payload.body, actor=analyst, request=request
    )
    await session.commit()
    await session.refresh(note)
    return NoteRead.model_validate(note)


@router.get("/{incident_id}/notes", response_model=list[NoteRead], summary="List notes")
async def list_notes(
    incident_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> list[NoteRead]:
    """Notes oldest first, so the investigation reads in order."""
    await _load(session, incident_id)
    result = await session.execute(
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at)
    )
    return [NoteRead.model_validate(note) for note in result.scalars()]


# --- Linked anomalies ------------------------------------------------------


@router.post(
    "/{incident_id}/anomalies", response_model=IncidentRead, summary="Link anomalies"
)
async def link_anomalies(
    incident_id: uuid.UUID,
    payload: AnomalyLink,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> IncidentRead:
    """Attach one or more anomalies as evidence.

    An anomaly belongs to at most one incident, so linking one already attached
    elsewhere moves it.
    """
    incident = await _load(session, incident_id)
    try:
        linked = await service.link_anomalies(session, incident, payload.anomaly_ids)
    except service.AnomalyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    await audit.record(
        session,
        action=AuditAction.UPDATE,
        resource_type="incident",
        actor=analyst,
        resource_id=incident.id,
        description=f"linked {len(linked)} anomaly(s) to {incident.reference}",
        context={"anomaly_ids": [str(anomaly.id) for anomaly in linked]},
        request=request,
    )
    await session.commit()
    return IncidentRead.model_validate(await _load(session, incident_id))


@router.delete(
    "/{incident_id}/anomalies/{anomaly_id}",
    response_model=IncidentRead,
    summary="Unlink an anomaly",
)
async def unlink_anomaly(
    incident_id: uuid.UUID,
    anomaly_id: uuid.UUID,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> IncidentRead:
    incident = await _load(session, incident_id)
    anomaly = await session.get(Anomaly, anomaly_id)
    if anomaly is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")

    if not await service.unlink_anomaly(session, incident, anomaly):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That anomaly is not linked to this incident",
        )

    await audit.record(
        session,
        action=AuditAction.UPDATE,
        resource_type="incident",
        actor=analyst,
        resource_id=incident.id,
        description=f"unlinked anomaly from {incident.reference}",
        context={"anomaly_id": str(anomaly_id)},
        request=request,
    )
    await session.commit()
    return IncidentRead.model_validate(await _load(session, incident_id))


# --- AI analysis -----------------------------------------------------------


@router.post(
    "/{incident_id}/analyze",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an AI incident report",
    responses={
        502: {"description": "The model answered, but not with a usable analysis"},
        503: {"description": "The model provider is unavailable"},
    },
)
async def analyze_incident(
    incident_id: uuid.UUID,
    payload: AnalyzeRequest,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> ReportRead:
    """Analyse an incident and store the result as a new report version.

    Gathers the incident, its linked anomalies, the log evidence behind them,
    and knowledge-base guidance retrieved for the case, then asks the model for
    a structured analysis. The answer is validated against a schema before
    anything is written, so a malformed response produces an error rather than
    a half-populated report.

    Requires the analyst role or higher: generating a report costs money and
    writes to the incident record. Viewers can read the results.
    """
    incident = await _load(session, incident_id)

    try:
        report, analysis, context = await ai.analyze_incident(
            session,
            incident,
            provider=ai.get_provider(),
            author_id=analyst.id,
            include_knowledge=payload.include_knowledge,
            max_log_entries=payload.max_log_entries,
            publish=payload.publish,
        )
    except ai.LLMConfigurationError as exc:
        # Not transient: no amount of retrying supplies an API key. The message
        # names the missing setting and never its value.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"The analysis provider is misconfigured: {exc}",
        ) from exc
    except ai.LLMResponseError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"The model did not return a usable analysis: {exc}",
        ) from exc
    except ai.LLMError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"The analysis provider is unavailable: {exc}",
        ) from exc

    await audit.record(
        session,
        action=AuditAction.CREATE,
        resource_type="incident_report",
        actor=analyst,
        resource_id=report.id,
        description=f"generated AI report v{report.version} for {incident.reference}",
        context={
            "incident_id": str(incident.id),
            "version": report.version,
            "provider": report.generation_metadata.get("provider"),
            "model": report.generation_metadata.get("model"),
            "assessed_severity": analysis.severity.value,
            "assessed_attack_type": analysis.attack_type.value,
            "confidence": analysis.confidence,
            **context.counts,
        },
        request=request,
    )
    await session.commit()
    await session.refresh(report)
    return ReportRead.model_validate(report)


@router.get(
    "/{incident_id}/reports",
    response_model=list[ReportRead],
    summary="List an incident's reports",
)
async def list_reports(
    incident_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> list[ReportRead]:
    """Reports for an incident, newest version first. Readable by viewers."""
    await _load(session, incident_id)
    result = await session.execute(
        select(IncidentReport)
        .where(IncidentReport.incident_id == incident_id)
        .order_by(IncidentReport.version.desc())
    )
    return [ReportRead.model_validate(report) for report in result.scalars()]


@router.get(
    "/{incident_id}/reports/{report_id}",
    response_model=ReportRead,
    summary="Fetch one report",
)
async def get_report(
    incident_id: uuid.UUID,
    report_id: uuid.UUID,
    session: SessionDep,
    _viewer: RequireViewer,
) -> ReportRead:
    report = await session.get(IncidentReport, report_id)
    if report is None or report.incident_id != incident_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return ReportRead.model_validate(report)
