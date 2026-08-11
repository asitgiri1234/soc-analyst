"""Ingestion result payloads."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import IngestionFormat, IngestionStatus


class RowErrorRead(BaseModel):
    """One rejected record, identified by its position in the uploaded file."""

    line: int
    field: str | None = None
    reason: str


class IngestionJobRead(BaseModel):
    """The outcome of an upload.

    ``status`` is the field to check: COMPLETED means every record was stored,
    PARTIAL that some were rejected and the rest kept, FAILED that none were.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    log_source_id: uuid.UUID
    filename: str
    content_type: str | None
    size_bytes: int
    format: IngestionFormat
    status: IngestionStatus
    total_records: int
    accepted_records: int
    rejected_records: int
    errors: list[RowErrorRead]
    error_detail: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
