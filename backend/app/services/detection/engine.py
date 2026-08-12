"""Running the detectors over a window and persisting what they find.

This is the only part of detection that touches the database. Detectors stay
pure; the engine loads their input, runs them, and turns findings into Anomaly
rows.

Re-analysing an overlapping window is expected -- a scheduled job and an analyst
will both do it -- so persistence is idempotent. Each finding carries a
fingerprint over what it is about rather than what it scored, and insertion
skips fingerprints already stored.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.models.anomaly import Anomaly
from app.models.enums import AnomalyStatus
from app.models.log_entry import LogEntry
from app.services.detection import registry
from app.services.detection.types import DetectionContext, Finding

logger = get_logger(__name__)


@dataclass(slots=True)
class AnalysisResult:
    """What one analysis run did."""

    window_start: datetime
    window_end: datetime
    entries_analysed: int
    detectors_run: list[str]
    findings: list[Finding] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)
    duplicates_skipped: int = 0
    truncated: bool = False


async def load_entries(
    session: AsyncSession,
    *,
    window_start: datetime,
    window_end: datetime,
    log_source_id: uuid.UUID | None = None,
    limit: int | None = None,
) -> list[LogEntry]:
    """Fetch the entries in a window, oldest first.

    Capped by ``DETECTION_MAX_ENTRIES``: detectors hold their input in memory,
    so an unbounded window would be an easy way to exhaust the process.
    """
    cap = limit or settings.DETECTION_MAX_ENTRIES
    query = (
        select(LogEntry)
        .where(
            LogEntry.event_timestamp >= window_start,
            LogEntry.event_timestamp <= window_end,
        )
        .order_by(LogEntry.event_timestamp)
        .limit(cap)
    )
    if log_source_id is not None:
        query = query.where(LogEntry.log_source_id == log_source_id)

    result = await session.execute(query)
    return list(result.scalars())


async def analyze(
    session: AsyncSession,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    log_source_id: uuid.UUID | None = None,
    detector_names: list[str] | None = None,
    persist: bool = True,
    limit: int | None = None,
) -> AnalysisResult:
    """Run the detectors over a window of log entries.

    With ``persist=False`` nothing is written, which lets an analyst try a
    tuning change against real traffic without filling the queue with anomalies
    they are about to discard.
    """
    window_end = window_end or datetime.now(UTC)
    window_start = window_start or window_end - timedelta(
        hours=settings.DETECTION_WINDOW_HOURS
    )
    if window_start > window_end:
        raise ValueError("window_start must not be after window_end")

    detectors = registry.resolve(detector_names)
    cap = limit or settings.DETECTION_MAX_ENTRIES
    entries = await load_entries(
        session,
        window_start=window_start,
        window_end=window_end,
        log_source_id=log_source_id,
        limit=cap,
    )

    context = DetectionContext(
        entries=entries,
        window_start=window_start,
        window_end=window_end,
        log_source_id=log_source_id,
    )

    findings: list[Finding] = []
    for detector in detectors:
        found = detector.detect(context)
        logger.debug("%s produced %d finding(s)", detector.name, len(found))
        findings.extend(found)

    # Worst first: the response is read top-down.
    findings.sort(key=lambda finding: finding.score, reverse=True)

    result = AnalysisResult(
        window_start=window_start,
        window_end=window_end,
        entries_analysed=len(entries),
        detectors_run=[detector.name for detector in detectors],
        findings=findings,
        truncated=len(entries) >= cap,
    )
    if result.truncated:
        logger.warning(
            "analysis hit the %d entry cap; narrow the window for full coverage", cap
        )

    if persist and findings:
        result.anomalies, result.duplicates_skipped = await persist_findings(
            session, findings, log_source_id=log_source_id
        )
    return result


async def persist_findings(
    session: AsyncSession,
    findings: list[Finding],
    *,
    log_source_id: uuid.UUID | None = None,
) -> tuple[list[Anomaly], int]:
    """Store findings, skipping any already recorded.

    ``ON CONFLICT DO NOTHING`` on the fingerprint makes this safe to run
    concurrently: two overlapping analyses cannot race a duplicate in between a
    check and an insert.

    An existing anomaly keeps the evidence it was first stored with, rather than
    being overwritten by the later run. That is deliberate -- the row may
    already be under investigation, and its score and evidence should not shift
    beneath the analyst reading it. The current view is always in the response's
    ``findings``.
    """
    rows = []
    for finding in findings:
        fingerprint = finding.fingerprint(log_source_id)
        rows.append(
            {
                "fingerprint": fingerprint,
                "log_entry_id": finding.log_entry_id,
                "log_source_id": log_source_id,
                "title": finding.title[:255],
                "description": finding.reason,
                "anomaly_type": finding.anomaly_type,
                "severity": finding.severity,
                "status": AnomalyStatus.NEW,
                "score": finding.score,
                "confidence": finding.confidence,
                "detector": finding.detector,
                "detector_version": finding.detector_version,
                "detected_at": datetime.now(UTC),
                "evidence": finding.evidence,
                "features": finding.features,
                "mitre_techniques": finding.mitre_techniques,
            }
        )

    statement = (
        pg_insert(Anomaly)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["fingerprint"])
        .returning(Anomaly.id)
    )
    inserted = set((await session.execute(statement)).scalars())
    await session.flush()

    fingerprints = [row["fingerprint"] for row in rows]
    stored = (
        await session.execute(select(Anomaly).where(Anomaly.fingerprint.in_(fingerprints)))
    ).scalars()
    anomalies = sorted(stored, key=lambda anomaly: anomaly.score, reverse=True)

    return anomalies, len(rows) - len(inserted)
