"""The contract between the engine and its detectors.

A detector receives a ``DetectionContext`` -- a window of normalised log entries
-- and returns ``Finding`` objects. It does not touch the database, the session
or HTTP. That is what keeps the set of detectors swappable: an ML model added
later implements the same protocol and the engine, the endpoint and the stored
shape of an anomaly are unchanged.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from app.models.enums import AnomalyType, Severity
from app.models.log_entry import LogEntry

# Score bands. A finding starts at the detector's threshold and climbs from
# there, so every band is reachable and the mapping is the same for all
# detectors -- a HIGH from one means what it means from another.
CRITICAL_AT = 0.85
HIGH_AT = 0.70
MEDIUM_AT = 0.50

# The floor a finding is emitted at: exactly at threshold, nothing above it.
BASE_SCORE = 0.40


def severity_for(score: float) -> Severity:
    """Map a 0-1 score onto the platform's severity scale."""
    if score >= CRITICAL_AT:
        return Severity.CRITICAL
    if score >= HIGH_AT:
        return Severity.HIGH
    if score >= MEDIUM_AT:
        return Severity.MEDIUM
    return Severity.LOW


def scale_score(observed: float, threshold: float, saturation: float) -> float:
    """Score an observation between the threshold and full confidence.

    At the threshold the score is ``BASE_SCORE`` (LOW); at ``saturation`` and
    beyond it is 1.0 (CRITICAL). Linear in between, so the number a detector
    reports can be read straight off the count that produced it.
    """
    if saturation <= threshold:
        return 1.0
    ratio = (observed - threshold) / (saturation - threshold)
    ratio = min(max(ratio, 0.0), 1.0)
    return round(BASE_SCORE + (1.0 - BASE_SCORE) * ratio, 4)


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """The window a detector reasons over."""

    entries: Sequence[LogEntry]
    window_start: datetime
    window_end: datetime
    log_source_id: uuid.UUID | None = None

    @property
    def duration_seconds(self) -> float:
        return max((self.window_end - self.window_start).total_seconds(), 1.0)


@dataclass(frozen=True, slots=True)
class Finding:
    """One anomaly a detector is prepared to argue for.

    ``reason`` is the plain-language argument; ``evidence`` is the data behind
    it, and ``features`` the numbers the score was computed from. Together they
    are what makes a V1 detection explainable: an analyst can check the
    arithmetic without rerunning anything.
    """

    detector: str
    detector_version: str
    anomaly_type: AnomalyType
    title: str
    reason: str
    score: float
    evidence: dict[str, Any] = field(default_factory=dict)
    features: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    # The entry that best represents the finding; the rest are in evidence.
    log_entry_id: uuid.UUID | None = None
    # Identifies what the finding is about (an IP, an account, a time bucket),
    # so re-running the analysis recognises it rather than duplicating it.
    entity: str = ""
    window_key: str = ""

    @property
    def severity(self) -> Severity:
        return severity_for(self.score)

    def fingerprint(self, log_source_id: uuid.UUID | None) -> str:
        """Stable identity for this finding.

        Deliberately excludes the score: the same brute-force burst re-analysed
        with a slightly different window should update nothing and insert
        nothing, not appear twice with two scores.
        """
        parts = [
            self.detector,
            str(log_source_id or ""),
            self.entity,
            self.window_key,
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


@runtime_checkable
class Detector(Protocol):
    """What the engine requires of a detector.

    Implementations are synchronous and pure: given the same context they
    return the same findings, which is what makes them testable in isolation.

    ``name`` and ``version`` are read-only, so a frozen dataclass -- which is
    what the built-in detectors are -- satisfies the protocol.
    """

    @property
    def name(self) -> str:
        """Stable identifier, used to select and register the detector."""
        ...

    @property
    def version(self) -> str:
        """Recorded on every anomaly, so a finding can be traced to its logic."""
        ...

    def detect(self, context: DetectionContext) -> list[Finding]:
        """Examine the window and return whatever it can justify."""
        ...
