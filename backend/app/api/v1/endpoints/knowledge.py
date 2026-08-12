"""The security knowledge base: documents in, passages out.

Embedding failures surface as 503 rather than 500: the request was valid and
retrying it later may well work, which is a different thing from the server
being broken. A missing API key is 500 instead, because it is a deployment
fault no amount of retrying fixes.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.deps import RequireAdmin, RequireAnalyst, RequireViewer, SessionDep
from app.models.document_chunk import DocumentChunk
from app.models.enums import AuditAction, DocumentType
from app.models.security_document import SecurityDocument
from app.schemas.knowledge import (
    DocumentCreate,
    DocumentRead,
    DocumentSummary,
    IndexResponse,
    ProviderInfo,
    SearchHit,
    SearchRequest,
    SearchResponse,
)
from app.services import audit
from app.services.rag import ingestion, retrieval
from app.services.rag.embeddings import (
    EmbeddingConfigurationError,
    EmbeddingError,
    get_provider,
)

router = APIRouter(prefix="/knowledge", tags=["knowledge base"])


def _embedding_failure(exc: EmbeddingError) -> HTTPException:
    """Map a provider failure onto the status that describes it."""
    if isinstance(exc, EmbeddingConfigurationError):
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Embedding provider is misconfigured: {exc}",
        )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=f"Embedding provider is unavailable: {exc}",
    )


async def _load(session: SessionDep, document_id: uuid.UUID) -> SecurityDocument:
    result = await session.execute(
        select(SecurityDocument)
        .where(SecurityDocument.id == document_id)
        .options(selectinload(SecurityDocument.chunks))
        .execution_options(populate_existing=True)
    )
    document = result.scalar_one_or_none()
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    return document


def _to_read(document: SecurityDocument) -> DocumentRead:
    """Render a document plus its indexing status."""
    chunks = document.chunks
    embedded = [chunk for chunk in chunks if chunk.embedding is not None]
    return DocumentRead(
        **DocumentSummary.model_validate(document).model_dump(),
        content=document.content,
        doc_metadata=document.doc_metadata,
        published_at=document.published_at,
        chunk_count=len(chunks),
        embedded_chunks=len(embedded),
        embedding_model=embedded[0].embedding_model if embedded else None,
    )


@router.get("/provider", response_model=ProviderInfo, summary="Embedding provider in use")
async def provider_info(_viewer: RequireViewer) -> ProviderInfo:
    """Which provider and model the corpus is embedded with."""
    provider = get_provider()
    return ProviderInfo(
        name=provider.name, model=provider.model, dimensions=provider.dimensions
    )


@router.post(
    "/documents",
    response_model=IndexResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add and index a document",
    responses={
        409: {"description": "Identical content is already stored"},
        503: {"description": "The embedding provider is unavailable"},
    },
)
async def create_document(
    payload: DocumentCreate,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> IndexResponse:
    """Store a document, chunk it, embed the chunks, and index them.

    Nothing is written if embedding fails, so the corpus never contains a
    document that silently cannot be retrieved.
    """
    try:
        result = await ingestion.create_document(
            session, values=payload.model_dump(), uploaded_by_id=analyst.id
        )
    except ingestion.EmptyDocumentError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except ingestion.DuplicateDocumentError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A document with identical content already exists ({exc.existing_id})",
        ) from exc
    except EmbeddingError as exc:
        await session.rollback()
        raise _embedding_failure(exc) from exc

    await audit.record(
        session,
        action=AuditAction.CREATE,
        resource_type="security_document",
        actor=analyst,
        resource_id=result.document.id,
        description=f"indexed knowledge document {result.document.title!r}",
        context={
            "chunks": result.chunks_created,
            "provider": result.provider,
            "model": result.model,
        },
        request=request,
    )
    await session.commit()

    return IndexResponse(
        document=_to_read(await _load(session, result.document.id)),
        chunks_created=result.chunks_created,
        embedded=result.embedded,
        provider=result.provider,
        model=result.model,
    )


@router.get("/documents", response_model=list[DocumentSummary], summary="List documents")
async def list_documents(
    session: SessionDep,
    _viewer: RequireViewer,
    document_type: Annotated[DocumentType | None, Query()] = None,
    is_active: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[DocumentSummary]:
    query = select(SecurityDocument).order_by(SecurityDocument.created_at.desc())
    if document_type is not None:
        query = query.where(SecurityDocument.document_type == document_type)
    if is_active is not None:
        query = query.where(SecurityDocument.is_active.is_(is_active))

    result = await session.execute(query.limit(limit).offset(offset))
    return [DocumentSummary.model_validate(doc) for doc in result.scalars()]


@router.get("/documents/{document_id}", response_model=DocumentRead, summary="Fetch a document")
async def get_document(
    document_id: uuid.UUID, session: SessionDep, _viewer: RequireViewer
) -> DocumentRead:
    return _to_read(await _load(session, document_id))


@router.post(
    "/documents/{document_id}/reindex",
    response_model=IndexResponse,
    summary="Re-chunk and re-embed a document",
)
async def reindex_document(
    document_id: uuid.UUID,
    session: SessionDep,
    request: Request,
    analyst: RequireAnalyst,
) -> IndexResponse:
    """Rebuild a document's chunks and vectors.

    Needed after a provider or chunk-size change: vectors from a different
    model are not comparable, and stale chunks would silently drop out of
    search results rather than erroring.
    """
    document = await _load(session, document_id)
    try:
        result = await ingestion.index_document(session, document)
    except ingestion.EmptyDocumentError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except EmbeddingError as exc:
        await session.rollback()
        raise _embedding_failure(exc) from exc

    await audit.record(
        session,
        action=AuditAction.UPDATE,
        resource_type="security_document",
        actor=analyst,
        resource_id=document.id,
        description=f"re-indexed {document.title!r}",
        context={"chunks": result.chunks_created, "model": result.model},
        request=request,
    )
    await session.commit()

    return IndexResponse(
        document=_to_read(await _load(session, document_id)),
        chunks_created=result.chunks_created,
        embedded=result.embedded,
        provider=result.provider,
        model=result.model,
    )


@router.delete(
    "/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a document (admin)",
)
async def delete_document(
    document_id: uuid.UUID,
    session: SessionDep,
    request: Request,
    admin: RequireAdmin,
) -> Response:
    """Delete a document and its chunks."""
    document = await _load(session, document_id)
    title = document.title

    await audit.record(
        session,
        action=AuditAction.DELETE,
        resource_type="security_document",
        actor=admin,
        resource_id=document.id,
        description=f"deleted knowledge document {title!r}",
        request=request,
    )
    await session.delete(document)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/search",
    response_model=SearchResponse,
    summary="Find the most relevant passages",
    responses={503: {"description": "The embedding provider is unavailable"}},
)
async def search(
    payload: SearchRequest,
    session: SessionDep,
    _viewer: RequireViewer,
) -> SearchResponse:
    """Retrieve the passages most similar to a query.

    Read-only, so a viewer may call it. Returns passages and their similarity
    scores; it does not generate an answer -- that belongs to the analysis
    phase.
    """
    provider = get_provider()
    try:
        hits = await retrieval.search(
            session,
            payload.query,
            top_k=payload.top_k,
            min_similarity=payload.min_similarity,
            document_types=payload.document_types,
            tags=payload.tags,
            provider=provider,
        )
    except EmbeddingError as exc:
        raise _embedding_failure(exc) from exc

    return SearchResponse(
        query=payload.query,
        # asdict, not vars: RetrievedChunk uses __slots__ and has no __dict__.
        results=[SearchHit(**asdict(hit)) for hit in hits],
        count=len(hits),
        provider=provider.name,
        model=provider.model,
    )


@router.get(
    "/stats",
    summary="Corpus size and indexing coverage",
)
async def stats(session: SessionDep, _viewer: RequireViewer) -> dict[str, int | str]:
    """How much of the corpus is indexed, and with which model."""
    documents = (
        await session.execute(select(func.count()).select_from(SecurityDocument))
    ).scalar_one()
    chunks = (
        await session.execute(select(func.count()).select_from(DocumentChunk))
    ).scalar_one()
    embedded = (
        await session.execute(
            select(func.count())
            .select_from(DocumentChunk)
            .where(DocumentChunk.embedding.is_not(None))
        )
    ).scalar_one()

    provider = get_provider()
    return {
        "documents": documents,
        "chunks": chunks,
        "embedded_chunks": embedded,
        "provider": provider.name,
        "model": provider.model,
    }
