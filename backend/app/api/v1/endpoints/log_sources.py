"""Log source registration and file ingestion."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Query, Request, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import RequireAnalyst, RequireViewer, SessionDep
from app.core.config import settings
from app.models.enums import AuditAction, IngestionStatus
from app.models.ingestion_job import IngestionJob
from app.models.log_source import LogSource
from app.schemas.ingestion import IngestionJobRead
from app.schemas.log_source import LogSourceCreate, LogSourceRead
from app.services import audit
from app.services.ingestion import parsers, pipeline

router = APIRouter(prefix="/log-sources", tags=["log sources"])

# Read in chunks so an oversized upload is abandoned partway rather than being
# fully buffered before the size is checked.
CHUNK_BYTES = 64 * 1024


@router.post(
    "",
    response_model=LogSourceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a log source",
)
async def create_log_source(
    payload: LogSourceCreate,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> LogSourceRead:
    """Register a collector. Requires the analyst role or higher."""
    source = LogSource(**payload.model_dump(), created_by_id=analyst.id)
    session.add(source)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A log source named {payload.name!r} already exists",
        ) from exc

    await audit.record(
        session,
        action=AuditAction.CREATE,
        resource_type="log_source",
        actor=analyst,
        resource_id=source.id,
        description=f"registered log source {source.name!r}",
        context={"source_type": source.source_type.value},
        request=request,
    )
    await session.commit()
    await session.refresh(source)
    return LogSourceRead.model_validate(source)


@router.get("", response_model=list[LogSourceRead], summary="List log sources")
async def list_log_sources(
    session: SessionDep,
    _viewer: RequireViewer,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[LogSourceRead]:
    result = await session.execute(
        select(LogSource).order_by(LogSource.created_at.desc()).limit(limit).offset(offset)
    )
    return [LogSourceRead.model_validate(source) for source in result.scalars()]


@router.get("/{source_id}", response_model=LogSourceRead, summary="Fetch a log source")
async def get_log_source(
    source_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> LogSourceRead:
    source = await session.get(LogSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found")
    return LogSourceRead.model_validate(source)


async def _read_within_limit(upload: UploadFile) -> bytes:
    """Read an upload, refusing anything over the configured size.

    The declared Content-Length is checked first as a cheap rejection, but it is
    not trusted: the body is counted as it arrives.
    """
    limit = settings.MAX_UPLOAD_BYTES
    chunks: list[bytes] = []
    total = 0

    while chunk := await upload.read(CHUNK_BYTES):
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"File exceeds the {limit} byte upload limit",
            )
        chunks.append(chunk)

    if total == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty"
        )
    return b"".join(chunks)


@router.post(
    "/{source_id}/ingest",
    response_model=IngestionJobRead,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a CSV or JSON log file",
    responses={
        413: {"description": "File exceeds the upload limit"},
        415: {"description": "Unsupported file type"},
        422: {"description": "Parsed, but no record could be stored"},
    },
)
async def ingest_file(
    source_id: uuid.UUID,
    session: SessionDep,
    request: Request,
    response: Response,
    analyst: RequireAnalyst,
    file: Annotated[UploadFile, File(description="A .csv, .json, .jsonl or .ndjson log file")],
) -> IngestionJobRead:
    """Ingest a log file into a source. Requires the analyst role or higher.

    Malformed records are rejected individually and reported in ``errors``; the
    records around them are still stored. The response is 201 when anything was
    stored and 422 when nothing was, and either way a job record is written.
    """
    source = await session.get(LogSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found")

    filename = file.filename or "upload"
    fmt = parsers.detect_format(filename, file.content_type)
    if fmt is None:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                "Unsupported file type. Upload .csv, .json, .jsonl or .ndjson, "
                "or send a matching content type."
            ),
        )

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds the {settings.MAX_UPLOAD_BYTES} byte upload limit",
        )

    payload = await _read_within_limit(file)

    job = await pipeline.ingest_upload(
        session,
        log_source=source,
        payload=payload,
        filename=filename,
        content_type=file.content_type,
        fmt=fmt,
        actor_id=analyst.id,
    )

    await audit.record(
        session,
        action=AuditAction.CREATE,
        resource_type="ingestion_job",
        actor=analyst,
        resource_id=job.id,
        description=f"ingested {filename!r} into {source.name!r}",
        context={
            "status": job.status.value,
            "accepted": job.accepted_records,
            "rejected": job.rejected_records,
        },
        request=request,
        success=job.status is not IngestionStatus.FAILED,
    )
    await session.commit()
    await session.refresh(job)

    if job.status is IngestionStatus.FAILED:
        response.status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    return IngestionJobRead.model_validate(job)


@router.get(
    "/{source_id}/ingestions",
    response_model=list[IngestionJobRead],
    summary="Ingestion history for a source",
)
async def list_ingestions(
    source_id: uuid.UUID,
    session: SessionDep,
    _viewer: RequireViewer,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[IngestionJobRead]:
    source = await session.get(LogSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found")

    result = await session.execute(
        select(IngestionJob)
        .where(IngestionJob.log_source_id == source_id)
        .order_by(IngestionJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [IngestionJobRead.model_validate(job) for job in result.scalars()]
