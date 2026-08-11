"""Log source registration payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.enums import LogSourceStatus, LogSourceType

SourceName = Annotated[
    str, StringConstraints(min_length=1, max_length=128, strip_whitespace=True)
]


class LogSourceCreate(BaseModel):
    """Register a collector.

    ``status`` and the ingest counters are not settable: they describe what has
    happened to the source, which is the server's account to keep.
    """

    model_config = ConfigDict(extra="forbid")

    name: SourceName
    source_type: LogSourceType
    description: str | None = Field(default=None, max_length=2000)
    vendor: str | None = Field(default=None, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = None
    timezone: str = Field(default="UTC", max_length=64)
    is_enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class LogSourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    source_type: LogSourceType
    status: LogSourceStatus
    vendor: str | None
    hostname: str | None
    ip_address: str | None
    timezone: str
    is_enabled: bool
    config: dict[str, Any]
    tags: list[str]
    events_ingested: int
    last_ingested_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime
