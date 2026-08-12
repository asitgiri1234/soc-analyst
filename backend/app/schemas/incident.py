"""Incident payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.enums import (
    AnomalyType,
    AttackType,
    IncidentPriority,
    IncidentStatus,
    Severity,
)

Title = Annotated[str, StringConstraints(min_length=3, max_length=255, strip_whitespace=True)]
# strip_whitespace first, so a note of only spaces fails the minimum length
# rather than being stored as blank.
NoteBody = Annotated[
    str, StringConstraints(min_length=1, max_length=10_000, strip_whitespace=True)
]


class IncidentCreate(BaseModel):
    """Open an incident.

    ``status`` is not settable: an incident is opened OPEN and moved with an
    update, so every transition goes through one audited path.
    """

    model_config = ConfigDict(extra="forbid")

    title: Title
    summary: str | None = Field(default=None, max_length=4000)
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    priority: IncidentPriority = IncidentPriority.P3
    attack_type: AttackType = AttackType.UNKNOWN
    assigned_to_id: uuid.UUID | None = None
    sla_due_at: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    affected_assets: list[dict[str, Any]] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    # Evidence can be attached at the moment the incident is raised, which is
    # when an analyst is looking at the anomalies that prompted it.
    anomaly_ids: list[uuid.UUID] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    """Change an incident. Only the fields present are touched.

    Timestamps are not settable: ``resolved_at`` and ``acknowledged_at`` are
    stamped by the status transition, so they cannot disagree with the status.
    """

    model_config = ConfigDict(extra="forbid")

    title: Title | None = None
    summary: str | None = Field(default=None, max_length=4000)
    description: str | None = None
    status: IncidentStatus | None = None
    severity: Severity | None = None
    priority: IncidentPriority | None = None
    attack_type: AttackType | None = None
    assigned_to_id: uuid.UUID | None = None
    sla_due_at: datetime | None = None
    tags: list[str] | None = None
    affected_assets: list[dict[str, Any]] | None = None
    indicators: list[dict[str, Any]] | None = None
    mitre_techniques: list[str] | None = None
    context: dict[str, Any] | None = None


class NoteCreate(BaseModel):
    """Add an analyst note."""

    model_config = ConfigDict(extra="forbid")

    body: NoteBody


class NoteRead(BaseModel):
    """A note, attributed and timestamped."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    author_id: uuid.UUID | None
    author_username: str | None
    body: str
    is_system: bool
    created_at: datetime


class AnomalyLink(BaseModel):
    """Attach anomalies to an incident."""

    model_config = ConfigDict(extra="forbid")

    anomaly_ids: list[uuid.UUID] = Field(min_length=1)


class LinkedAnomalyRead(BaseModel):
    """An anomaly as it appears on its incident.

    A summary rather than the full anomaly: the evidence and feature blobs stay
    behind ``/anomalies/{id}`` so an incident with fifty linked anomalies does
    not return a megabyte of JSON.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    anomaly_type: AnomalyType
    severity: Severity
    score: float
    detector: str
    detected_at: datetime


class IncidentSummary(BaseModel):
    """An incident in a list."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    number: int
    reference: str
    title: str
    summary: str | None
    status: IncidentStatus
    severity: Severity
    priority: IncidentPriority
    attack_type: AttackType
    assigned_to_id: uuid.UUID | None
    created_by_id: uuid.UUID | None
    detected_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    sla_due_at: datetime | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class IncidentRead(IncidentSummary):
    """One incident in full, with its evidence and its notes."""

    description: str | None
    affected_assets: list[dict[str, Any]]
    indicators: list[dict[str, Any]]
    mitre_techniques: list[str]
    context: dict[str, Any]
    anomalies: list[LinkedAnomalyRead]
    notes: list[NoteRead]
