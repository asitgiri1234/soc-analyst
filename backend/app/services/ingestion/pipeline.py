"""Driving a file through parse, normalise and insert.

Rows are inserted in batches with a Core ``insert``: one statement per batch
rather than one per row, and no ORM instances built for objects nobody will
touch again. A file of a hundred thousand events is a few hundred statements.

Malformed rows never reach the database. They are counted and reported, and the
batch around them is still committed -- a single bad line in a log export must
not cost the operator the other ten thousand.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import IngestionFormat, IngestionStatus, LogSourceStatus
from app.models.ingestion_job import IngestionJob
from app.models.log_entry import LogEntry
from app.models.log_source import LogSource
from app.services.ingestion import normalizer, parsers
from app.services.ingestion.types import (
    IngestionOutcome,
    RawRecord,
    RowError,
    UnreadableFileError,
)

logger = get_logger(__name__)


def _batches(rows: list[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


async def ingest_upload(
    session: AsyncSession,
    *,
    log_source: LogSource,
    payload: bytes,
    filename: str,
    content_type: str | None,
    fmt: IngestionFormat,
    actor_id: uuid.UUID | None = None,
) -> IngestionJob:
    """Ingest one uploaded file and return its job record.

    The job is written whatever the outcome, including for a file that could not
    be read at all, so every upload leaves a trace.
    """
    job = IngestionJob(
        log_source_id=log_source.id,
        created_by_id=actor_id,
        filename=filename,
        content_type=content_type,
        size_bytes=len(payload),
        format=fmt,
        status=IngestionStatus.RUNNING,
        started_at=datetime.now(UTC),
    )
    session.add(job)
    await session.flush()

    try:
        text = parsers.decode(payload)
        records, outcome = _collect(text, fmt)
    except UnreadableFileError as exc:
        # The file itself is unusable; nothing to salvage row by row.
        job.status = IngestionStatus.FAILED
        job.error_detail = str(exc)
        job.finished_at = datetime.now(UTC)
        await _mark_source_error(session, log_source, str(exc))
        await session.flush()
        logger.warning("ingestion failed for %s: %s", filename, exc)
        return job

    rows = _normalize(records, outcome)
    if rows:
        await _insert(session, log_source.id, rows)
        outcome.accepted = len(rows)

    _finish(job, outcome)
    await _update_source(session, log_source, outcome)
    await session.flush()

    logger.info(
        "ingested %s into %s: %d accepted, %d rejected",
        filename,
        log_source.name,
        outcome.accepted,
        outcome.rejected,
    )
    return job


def _collect(text: str, fmt: IngestionFormat) -> tuple[list[RawRecord], IngestionOutcome]:
    """Split the parser's output into usable records and parse failures."""
    outcome = IngestionOutcome()
    records: list[RawRecord] = []

    for item in parsers.parse(text, fmt):
        outcome.total += 1
        if isinstance(item, RowError):
            outcome.rejected += 1
            _report(outcome, item)
        else:
            records.append(item)
    return records, outcome


def _normalize(records: list[RawRecord], outcome: IngestionOutcome) -> list[dict[str, Any]]:
    """Map records onto columns, setting aside the ones that cannot be mapped."""
    rows: list[dict[str, Any]] = []
    for record in records:
        values, error = normalizer.normalize(record)
        if values is None:
            outcome.rejected += 1
            if error is not None:
                _report(outcome, error)
            continue
        rows.append(values)
    return rows


def _report(outcome: IngestionOutcome, error: RowError) -> None:
    """Keep a bounded sample of failures."""
    if len(outcome.errors) < settings.INGEST_MAX_REPORTED_ERRORS:
        outcome.errors.append(error)


async def _insert(
    session: AsyncSession, log_source_id: uuid.UUID, rows: list[dict[str, Any]]
) -> None:
    for batch in _batches(rows, settings.INGEST_BATCH_SIZE):
        await session.execute(
            insert(LogEntry),
            [{**row, "log_source_id": log_source_id} for row in batch],
        )


def _finish(job: IngestionJob, outcome: IngestionOutcome) -> None:
    job.total_records = outcome.total
    job.accepted_records = outcome.accepted
    job.rejected_records = outcome.rejected
    job.errors = [error.as_dict() for error in outcome.errors]
    job.finished_at = datetime.now(UTC)

    if outcome.accepted == 0:
        job.status = IngestionStatus.FAILED
    elif outcome.rejected:
        job.status = IngestionStatus.PARTIAL
    else:
        job.status = IngestionStatus.COMPLETED


async def _update_source(
    session: AsyncSession, log_source: LogSource, outcome: IngestionOutcome
) -> None:
    """Advance the source's counters.

    The running total is incremented in SQL rather than read-modify-written, so
    two concurrent uploads cannot lose each other's count.
    """
    if outcome.accepted == 0:
        return
    await session.execute(
        update(LogSource)
        .where(LogSource.id == log_source.id)
        .values(
            events_ingested=LogSource.events_ingested + outcome.accepted,
            last_ingested_at=func.now(),
            status=LogSourceStatus.ACTIVE,
            last_error=None,
        )
    )


async def _mark_source_error(
    session: AsyncSession, log_source: LogSource, detail: str
) -> None:
    await session.execute(
        update(LogSource)
        .where(LogSource.id == log_source.id)
        .values(status=LogSourceStatus.ERROR, last_error=detail[:1000])
    )
