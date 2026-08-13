"""Aggregate counts for the SOC overview.

Every figure here is a ``GROUP BY`` executed by the database over the whole
table. The alternative -- fetching a page of incidents and tallying it in the
browser -- would produce a chart describing the first fifty rows while claiming
to describe the estate, which is worse than no chart.

Read-only and viewer-accessible: these are counts of security data, which is
exactly what the VIEWER tier is for.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, TypeVar

from fastapi import APIRouter, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequireViewer, SessionDep
from app.models.anomaly import Anomaly
from app.models.enums import IncidentStatus
from app.models.incident import Incident
from app.models.log_entry import LogEntry
from app.models.log_source import LogSource
from app.schemas.dashboard import CountByDay, CountByKey, DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# `Select` is invariant in its row type, so the grouped-count helper is generic
# over the enum column rather than taking `object`.
EnumT = TypeVar("EnumT", bound=StrEnum)


async def _count(session: AsyncSession, statement: Select[tuple[int]]) -> int:
    return (await session.execute(statement)).scalar_one()


async def _group(
    session: AsyncSession, statement: Select[tuple[EnumT, int]]
) -> list[CountByKey]:
    """Run a grouped count, rendering enum members by value."""
    rows = (await session.execute(statement)).all()
    return [
        CountByKey(key=getattr(key, "value", None) or str(key), count=count)
        for key, count in rows
    ]


@router.get("/stats", response_model=DashboardStats, summary="Overview counts")
async def stats(
    session: SessionDep,
    _viewer: RequireViewer,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> DashboardStats:
    """Counts backing the overview charts, over a trailing window."""
    since = datetime.now(UTC) - timedelta(days=days)

    incidents_total = await _count(session, select(func.count()).select_from(Incident))

    async def status_count(value: IncidentStatus) -> int:
        return await _count(
            session,
            select(func.count()).select_from(Incident).where(Incident.status == value),
        )

    # `detected_at` rather than `created_at`: the chart is about when incidents
    # happened, not when someone got round to recording them.
    day = func.date_trunc("day", Incident.detected_at)
    over_time_rows = (
        await session.execute(
            select(day.label("day"), func.count().label("count"))
            .where(Incident.detected_at >= since)
            .group_by(day)
            .order_by(day)
        )
    ).all()

    return DashboardStats(
        incidents_total=incidents_total,
        incidents_open=await status_count(IncidentStatus.OPEN),
        incidents_investigating=await status_count(IncidentStatus.INVESTIGATING),
        incidents_resolved=await status_count(IncidentStatus.RESOLVED),
        anomalies_total=await _count(session, select(func.count()).select_from(Anomaly)),
        log_sources_total=await _count(
            session, select(func.count()).select_from(LogSource)
        ),
        log_entries_total=await _count(
            session, select(func.count()).select_from(LogEntry)
        ),
        incidents_by_severity=await _group(
            session,
            select(Incident.severity, func.count()).group_by(Incident.severity),
        ),
        incidents_by_attack_type=await _group(
            session,
            select(Incident.attack_type, func.count()).group_by(Incident.attack_type),
        ),
        incidents_over_time=[
            CountByDay(day=row.day.date(), count=row.count) for row in over_time_rows
        ],
        anomalies_by_type=await _group(
            session,
            select(Anomaly.anomaly_type, func.count()).group_by(Anomaly.anomaly_type),
        ),
        anomalies_by_severity=await _group(
            session,
            select(Anomaly.severity, func.count()).group_by(Anomaly.severity),
        ),
    )
