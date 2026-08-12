"""The shape an AI analysis must take.

This model is the contract with the LLM. The provider is asked for JSON, the
JSON is validated here, and anything that does not fit is rejected -- there is
no regex, no "find the first sentence", no free-form text parsing to drift out
of sync with the prompt.

Validation is also a containment boundary. ``severity`` and ``attack_type`` are
enums, so a model that has been talked into inventing a category by an injected
log line produces a validation error rather than a novel value in the database.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.models.enums import AttackType, ReportStatus, Severity

Sentence = Annotated[str, StringConstraints(min_length=1, max_length=4000, strip_whitespace=True)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=1000, strip_whitespace=True)]


class RecommendedAction(BaseModel):
    """One thing an analyst should do next."""

    model_config = ConfigDict(extra="ignore")

    action: ShortText
    priority: Annotated[str, StringConstraints(strip_whitespace=True)] = "medium"
    rationale: str | None = Field(default=None, max_length=2000)

    @field_validator("priority", mode="before")
    @classmethod
    def _normalise_priority(cls, value: object) -> object:
        """Accept the vocabulary models actually use, then constrain it."""
        if not isinstance(value, str):
            return "medium"
        cleaned = value.strip().lower()
        if cleaned in {"urgent", "immediate", "p0", "p1"}:
            return "high"
        if cleaned in {"low", "medium", "high", "critical"}:
            return cleaned
        return "medium"


class IncidentAnalysis(BaseModel):
    """The structured analysis an LLM must produce.

    ``extra="ignore"`` rather than ``forbid``: a model that adds a stray field
    has still answered the question, and discarding the extra is friendlier
    than failing the whole analysis over it. Unknown *values* for the
    constrained fields are still rejected.
    """

    model_config = ConfigDict(extra="ignore")

    summary: Sentence
    attack_type: AttackType
    severity: Severity
    evidence: list[ShortText] = Field(default_factory=list, max_length=25)
    likely_cause: Sentence
    recommended_actions: list[RecommendedAction] = Field(default_factory=list, max_length=15)
    # The model's own confidence in the analysis, not the platform's confidence
    # in the model. Recorded so a low-confidence report can be flagged for
    # closer human review rather than read as settled fact.
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("attack_type", mode="before")
    @classmethod
    def _coerce_attack_type(cls, value: object) -> object:
        """Map common spellings onto the enum before validation rejects them."""
        if not isinstance(value, str):
            return value
        cleaned = value.strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {
            "bruteforce": "brute_force",
            "brute_force_attack": "brute_force",
            "credential_stuffing": "credential_access",
            "password_spraying": "brute_force",
            "sql_injection": "other",
            "xss": "other",
            "web_attack": "other",
            "exfiltration": "data_exfiltration",
            "dos": "denial_of_service",
            "ddos": "denial_of_service",
            "scanning": "reconnaissance",
            "port_scan": "reconnaissance",
            "recon": "reconnaissance",
            "malware_infection": "malware",
            "none": "unknown",
        }
        return aliases.get(cleaned, cleaned)

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        cleaned = value.strip().lower()
        aliases = {"informational": "info", "warning": "medium", "moderate": "medium",
                   "severe": "critical", "urgent": "critical", "none": "info"}
        return aliases.get(cleaned, cleaned)

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: object) -> object:
        """Accept a percentage where a fraction was asked for.

        Bounded to 1 < value <= 100 so a genuinely out-of-range number is
        rejected by the field constraint rather than silently rescaled.
        """
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if 1 < value <= 100:
                return float(value) / 100.0
            return value
        if isinstance(value, str):
            text = value.strip().rstrip("%")
            try:
                number = float(text)
            except ValueError:
                return value
            return number / 100.0 if 1 < number <= 100 else number
        return value


def analysis_json_schema() -> dict[str, Any]:
    """The JSON schema handed to providers that support constrained decoding."""
    return IncidentAnalysis.model_json_schema()


# --- API payloads ----------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Ask for an incident to be analysed."""

    model_config = ConfigDict(extra="forbid")

    include_knowledge: bool = Field(
        default=True, description="Retrieve knowledge-base context before analysing."
    )
    max_log_entries: int | None = Field(default=None, ge=0, le=500)
    publish: bool = Field(
        default=False,
        description="Mark the generated report published rather than leaving it a draft.",
    )


class ReportRead(BaseModel):
    """A stored incident report."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    author_id: uuid.UUID | None
    title: str
    version: int
    status: ReportStatus
    format: str
    executive_summary: str | None
    content: str
    sections: dict[str, Any]
    recommendations: list[dict[str, Any]]
    is_ai_generated: bool
    generation_metadata: dict[str, Any]
    published_at: datetime | None
    created_at: datetime
