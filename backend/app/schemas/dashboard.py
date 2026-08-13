"""Read models for the SOC dashboard.

Two things the dashboard needs that no earlier phase exposed:

*Log evidence.* Anomalies carry the log entry they were argued from, but the
entries themselves were only ever read server-side by the AI analyzer. An
analyst looking at an incident needs to see the same rows the model saw.

*Aggregates.* The charts count incidents by severity, by day, and anomalies by
type. Those counts must be computed in SQL over the whole table: counting a
paginated page in the browser would report the composition of the first fifty
rows and label it the composition of the estate.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import Severity


class LogEntryRead(BaseModel):
    """One normalised event.

    ``raw`` and ``embedding`` are deliberately absent: the raw line can carry
    material the normalised fields have already had trimmed to length, and the
    vector is machinery rather than evidence.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    log_source_id: uuid.UUID
    event_timestamp: datetime
    ingested_at: datetime
    severity: Severity
    category: str | None
    event_type: str | None
    action: str | None
    outcome: str | None
    message: str
    host: str | None
    process: str | None
    username: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    attributes: dict[str, Any]


class CountByKey(BaseModel):
    """A labelled count, used by every chart on the overview."""

    key: str
    count: int


class CountByDay(BaseModel):
    """Incidents opened on one day."""

    day: date
    count: int


class DashboardStats(BaseModel):
    """Everything the overview page charts, counted server-side."""

    incidents_total: int
    incidents_open: int
    incidents_investigating: int
    incidents_resolved: int
    anomalies_total: int
    log_sources_total: int
    log_entries_total: int
    incidents_by_severity: list[CountByKey]
    incidents_by_attack_type: list[CountByKey]
    incidents_over_time: list[CountByDay]
    anomalies_by_type: list[CountByKey]
    anomalies_by_severity: list[CountByKey]
