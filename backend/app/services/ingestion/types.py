"""Shared types for the ingestion stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class UnreadableFileError(Exception):
    """The file as a whole could not be read: bad encoding or bad structure.

    Distinct from a row failing to parse, which is recorded and skipped.
    """


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One record as it came out of the file, before any field mapping.

    ``line`` is 1-based and points at the source file, so an error message sends
    the operator to the right place: the row number for CSV, the array index for
    JSON, the physical line for NDJSON.
    """

    line: int
    data: dict[str, Any]
    raw: str


@dataclass(frozen=True, slots=True)
class RowError:
    """Why one record was rejected."""

    line: int
    reason: str
    field: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"line": self.line, "field": self.field, "reason": self.reason}


@dataclass(slots=True)
class IngestionOutcome:
    """What happened to a file."""

    total: int = 0
    accepted: int = 0
    rejected: int = 0
    errors: list[RowError] = field(default_factory=list)
