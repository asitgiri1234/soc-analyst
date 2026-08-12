"""Knowledge base payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.enums import DocumentType

Title = Annotated[str, StringConstraints(min_length=3, max_length=255, strip_whitespace=True)]
Content = Annotated[str, StringConstraints(min_length=1, max_length=1_000_000)]
Query = Annotated[str, StringConstraints(min_length=1, max_length=2000, strip_whitespace=True)]


class DocumentCreate(BaseModel):
    """Add a document to the knowledge base.

    ``checksum`` is not settable: it is derived from the content and is what
    de-duplicates re-uploads, so a client-supplied value would defeat it.
    """

    model_config = ConfigDict(extra="forbid")

    title: Title
    document_type: DocumentType
    content: Content
    summary: str | None = Field(default=None, max_length=4000)
    source_url: str | None = Field(default=None, max_length=2048)
    language: str = Field(default="en", max_length=16)
    version: str | None = Field(default=None, max_length=32)
    tags: list[str] = Field(default_factory=list)
    doc_metadata: dict[str, Any] = Field(default_factory=dict)
    published_at: datetime | None = None


class DocumentSummary(BaseModel):
    """A document in a list, without its body."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    document_type: DocumentType
    summary: str | None
    source_url: str | None
    language: str
    version: str | None
    is_active: bool
    tags: list[str]
    checksum: str | None
    created_at: datetime
    updated_at: datetime


class DocumentRead(DocumentSummary):
    """One document in full, with indexing status."""

    content: str
    doc_metadata: dict[str, Any]
    published_at: datetime | None
    chunk_count: int
    embedded_chunks: int
    embedding_model: str | None


class IndexResponse(BaseModel):
    """The result of indexing or re-indexing a document."""

    document: DocumentRead
    chunks_created: int
    embedded: int
    provider: str
    model: str


class SearchRequest(BaseModel):
    """A similarity search over the knowledge base."""

    model_config = ConfigDict(extra="forbid")

    query: Query
    top_k: int | None = Field(default=None, ge=1, le=50)
    min_similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    document_types: list[DocumentType] | None = None
    tags: list[str] | None = None


class SearchHit(BaseModel):
    """One retrieved passage, with enough context to cite it."""

    chunk_id: uuid.UUID
    document_id: uuid.UUID
    document_title: str
    document_type: DocumentType
    chunk_index: int
    content: str
    similarity: float
    source_url: str | None
    tags: list[str]


class SearchResponse(BaseModel):
    """Search results, most relevant first."""

    query: str
    results: list[SearchHit]
    count: int
    provider: str
    model: str


class ProviderInfo(BaseModel):
    """The embedding provider currently configured."""

    name: str
    model: str
    dimensions: int
