"""Analysis request and anomaly payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import AnomalyStatus, AnomalyType, Severity


class AnalyzeRequest(BaseModel):
    """Ask for a window of logs to be analysed.

    Every field is optional: an empty body analyses the default recent window
    with every registered detector, which is the common case.
    """

    model_config = ConfigDict(extra="forbid")

    log_source_id: uuid.UUID | None = Field(
        default=None, description="Restrict analysis to one source; omit for all."
    )
    window_start: datetime | None = Field(
        default=None, description="Defaults to DETECTION_WINDOW_HOURS before the end."
    )
    window_end: datetime | None = Field(default=None, description="Defaults to now.")
    detectors: list[str] | None = Field(
        default=None, description="Detector names to run; omit for all registered."
    )
    persist: bool = Field(
        default=True,
        description="Store the findings. False previews a tuning change without writing.",
    )
    limit: int | None = Field(
        default=None, ge=1, le=1_000_000, description="Cap on entries loaded."
    )

    @model_validator(mode="after")
    def _check_window(self) -> AnalyzeRequest:
        if (
            self.window_start is not None
            and self.window_end is not None
            and self.window_start > self.window_end
        ):
            raise ValueError("window_start must not be after window_end")
        return self


class AnomalyRead(BaseModel):
    """A detected anomaly, with the argument for it.

    ``description`` is the reason in words and ``evidence`` the data behind it;
    ``features`` holds the numbers the score was computed from, so the
    arithmetic can be checked without re-running the detector.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    log_source_id: uuid.UUID | None
    log_entry_id: uuid.UUID | None
    title: str
    description: str | None
    anomaly_type: AnomalyType
    severity: Severity
    status: AnomalyStatus
    score: float
    confidence: float | None
    detector: str
    detector_version: str | None
    detected_at: datetime
    evidence: dict[str, Any]
    features: dict[str, Any]
    mitre_techniques: list[str]
    created_at: datetime


class FindingRead(BaseModel):
    """What a detector argued for, before -- or without -- being stored.

    Always returned, so ``persist=false`` still shows the analyst what was
    found. The persisted rows come back separately in ``anomalies``.
    """

    detector: str
    detector_version: str
    anomaly_type: AnomalyType
    severity: Severity
    score: float
    confidence: float | None
    title: str
    reason: str
    evidence: dict[str, Any]
    features: dict[str, Any]
    mitre_techniques: list[str]
    log_entry_id: uuid.UUID | None


class DetectorInfo(BaseModel):
    """A registered detector."""

    name: str
    version: str


class AnalysisSummary(BaseModel):
    """Counts describing one analysis run."""

    entries_analysed: int
    findings: int
    persisted: int
    duplicates_skipped: int
    by_severity: dict[str, int]
    truncated: bool = Field(
        description="True when the entry cap was hit and coverage is partial."
    )


class AnalyzeResponse(BaseModel):
    """The result of an analysis run.

    ``findings`` is what the detectors argued for and is always present.
    ``anomalies`` is what was written, and is empty when ``persist`` was false or
    when everything found had already been recorded by an earlier run.
    """

    window_start: datetime
    window_end: datetime
    log_source_id: uuid.UUID | None
    detectors_run: list[str]
    summary: AnalysisSummary
    findings: list[FindingRead]
    anomalies: list[AnomalyRead]
