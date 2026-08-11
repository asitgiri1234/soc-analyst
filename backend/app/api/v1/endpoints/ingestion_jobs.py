"""Ingestion status lookup, across all sources."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import RequireViewer, SessionDep
from app.models.enums import IngestionStatus
from app.models.ingestion_job import IngestionJob
from app.schemas.ingestion import IngestionJobRead

router = APIRouter(prefix="/ingestion-jobs", tags=["log sources"])


@router.get("", response_model=list[IngestionJobRead], summary="List ingestion jobs")
async def list_jobs(
    session: SessionDep,
    _viewer: RequireViewer,
    job_status: Annotated[IngestionStatus | None, Query(alias="status")] = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[IngestionJobRead]:
    """Recent uploads, newest first, optionally filtered by status."""
    query = select(IngestionJob).order_by(IngestionJob.created_at.desc())
    if job_status is not None:
        query = query.where(IngestionJob.status == job_status)

    result = await session.execute(query.limit(limit).offset(offset))
    return [IngestionJobRead.model_validate(job) for job in result.scalars()]


@router.get("/{job_id}", response_model=IngestionJobRead, summary="Fetch an ingestion job")
async def get_job(
    job_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> IngestionJobRead:
    job = await session.get(IngestionJob, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Ingestion job not found"
        )
    return IngestionJobRead.model_validate(job)
