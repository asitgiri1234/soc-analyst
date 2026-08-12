"""Security knowledge base: chunking, embedding, storage, retrieval.

The layering keeps the embedding provider swappable and keeps retrieval
independent of any future LLM analyzer:

``embeddings/``  the provider protocol and its implementations
``chunking``     splitting documents into passages
``ingestion``    chunk -> embed -> store
``retrieval``    embed a query, search pgvector by cosine distance

Nothing here generates text. Retrieval hands back passages; deciding what to do
with them belongs to the analysis phase, which can fail or be absent without
taking search down with it.
"""

from app.services.rag.ingestion import (
    DuplicateDocumentError,
    EmptyDocumentError,
    create_document,
    index_document,
)
from app.services.rag.retrieval import RetrievedChunk, search

__all__ = [
    "DuplicateDocumentError",
    "EmptyDocumentError",
    "RetrievedChunk",
    "create_document",
    "index_document",
    "search",
]
