"""Running detection and reading what it found."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from app.api.deps import RequireAnalyst, RequireViewer, SessionDep
from app.models.anomaly import Anomaly
from app.models.enums import AnomalyStatus, AuditAction, Severity
from app.models.log_source import LogSource
from app.schemas.detection import (
    AnalysisSummary,
    AnalyzeRequest,
    AnalyzeResponse,
    AnomalyRead,
    DetectorInfo,
    FindingRead,
)
from app.services import audit
from app.services.detection import engine, registry

router = APIRouter(tags=["detection"])


@router.get("/detectors", response_model=list[DetectorInfo], summary="List detectors")
async def list_detectors(_viewer: RequireViewer) -> list[DetectorInfo]:
    """The detectors currently registered, and their versions."""
    return [
        DetectorInfo(name=name, version=getattr(registry.get(name), "version", "unknown"))
        for name in registry.available()
    ]


@router.post(
    "/detection/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse logs for anomalies",
)
async def analyze(
    payload: AnalyzeRequest,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> AnalyzeResponse:
    """Run the detectors over a window of log entries.

    Returns every finding and, unless ``persist`` is false, stores them. Storage
    is idempotent: re-analysing an overlapping window recognises what it already
    wrote rather than duplicating it, and reports the skips.

    Requires the analyst role or higher, since it writes to the anomaly queue.
    """
    if payload.log_source_id is not None:
        source = await session.get(LogSource, payload.log_source_id)
        if source is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found"
            )

    try:
        result = await engine.analyze(
            session,
            window_start=payload.window_start,
            window_end=payload.window_end,
            log_source_id=payload.log_source_id,
            detector_names=payload.detectors,
            persist=payload.persist,
            limit=payload.limit,
        )
    except KeyError as exc:
        # An unknown detector name is a client mistake, not a server fault.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{exc.args[0]}. Registered: {', '.join(registry.available())}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    by_severity = Counter(finding.severity.value for finding in result.findings)

    await audit.record(
        session,
        action=AuditAction.CREATE if payload.persist else AuditAction.READ,
        resource_type="anomaly_analysis",
        actor=analyst,
        resource_id=payload.log_source_id,
        description=(
            f"analysed {result.entries_analysed} log entries, "
            f"{len(result.findings)} finding(s)"
        ),
        context={
            "detectors": result.detectors_run,
            "findings": len(result.findings),
            "persisted": len(result.anomalies),
            "persist": payload.persist,
            "truncated": result.truncated,
        },
        request=request,
    )
    await session.commit()

    return AnalyzeResponse(
        window_start=result.window_start,
        window_end=result.window_end,
        log_source_id=payload.log_source_id,
        detectors_run=result.detectors_run,
        summary=AnalysisSummary(
            entries_analysed=result.entries_analysed,
            findings=len(result.findings),
            persisted=len(result.anomalies),
            duplicates_skipped=result.duplicates_skipped,
            by_severity=dict(by_severity),
            truncated=result.truncated,
        ),
        findings=[
            FindingRead(
                detector=finding.detector,
                detector_version=finding.detector_version,
                anomaly_type=finding.anomaly_type,
                severity=finding.severity,
                score=finding.score,
                confidence=finding.confidence,
                title=finding.title,
                reason=finding.reason,
                evidence=finding.evidence,
                features=finding.features,
                mitre_techniques=finding.mitre_techniques,
                log_entry_id=finding.log_entry_id,
            )
            for finding in result.findings
        ],
        anomalies=[AnomalyRead.model_validate(anomaly) for anomaly in result.anomalies],
    )


@router.get("/anomalies", response_model=list[AnomalyRead], summary="List anomalies")
async def list_anomalies(
    session: SessionDep,
    _viewer: RequireViewer,
    log_source_id: uuid.UUID | None = None,
    severity: Annotated[Severity | None, Query()] = None,
    anomaly_status: Annotated[AnomalyStatus | None, Query(alias="status")] = None,
    detector: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AnomalyRead]:
    """Stored anomalies, highest scoring first."""
    query = select(Anomaly).order_by(Anomaly.score.desc(), Anomaly.detected_at.desc())

    if log_source_id is not None:
        query = query.where(Anomaly.log_source_id == log_source_id)
    if severity is not None:
        query = query.where(Anomaly.severity == severity)
    if anomaly_status is not None:
        query = query.where(Anomaly.status == anomaly_status)
    if detector is not None:
        query = query.where(Anomaly.detector == detector)

    result = await session.execute(query.limit(limit).offset(offset))
    return [AnomalyRead.model_validate(anomaly) for anomaly in result.scalars()]


@router.get("/anomalies/{anomaly_id}", response_model=AnomalyRead, summary="Fetch an anomaly")
async def get_anomaly(
    anomaly_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> AnomalyRead:
    anomaly = await session.get(Anomaly, anomaly_id)
    if anomaly is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyRead.model_validate(anomaly)
