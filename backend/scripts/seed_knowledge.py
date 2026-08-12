"""Load the seed knowledge base into the corpus.

    python -m scripts.seed_knowledge            # add anything missing
    python -m scripts.seed_knowledge --reindex  # also re-embed what is present

Idempotent: documents are matched on the checksum of their content, so running
it twice adds nothing the second time. Use ``--reindex`` after changing the
embedding provider or the chunk size, when the stored vectors are no longer
comparable to newly generated ones.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models.security_document import SecurityDocument
from app.services.rag import ingestion
from app.services.rag.embeddings import EmbeddingError, get_provider

SEED_DIR = pathlib.Path(__file__).resolve().parent.parent / "seed_data" / "knowledge"


async def _seed(session: AsyncSession, *, reindex: bool) -> tuple[int, int, int]:
    added = reindexed = skipped = 0

    for path in sorted(SEED_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        digest = ingestion.checksum(payload["content"])

        existing = (
            await session.execute(
                select(SecurityDocument).where(SecurityDocument.checksum == digest)
            )
        ).scalar_one_or_none()

        if existing is None:
            result = await ingestion.create_document(session, values=payload)
            print(f"  added     {payload['title']}  ({result.chunks_created} chunks)")
            added += 1
        elif reindex:
            result = await ingestion.index_document(session, existing)
            print(f"  reindexed {payload['title']}  ({result.chunks_created} chunks)")
            reindexed += 1
        else:
            print(f"  present   {payload['title']}")
            skipped += 1

    return added, reindexed, skipped


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reindex",
        action="store_true",
        help="re-chunk and re-embed documents that are already stored",
    )
    args = parser.parse_args()

    provider = get_provider()
    print(f"Embedding with {provider.name}/{provider.model} ({provider.dimensions}d)")

    engine = create_async_engine(settings.database_url)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            added, reindexed, skipped = await _seed(session, reindex=args.reindex)
            await session.commit()
    except EmbeddingError as exc:
        sys.exit(f"Embedding provider failed: {exc}")
    finally:
        await engine.dispose()

    print(f"\n{added} added, {reindexed} reindexed, {skipped} already present.")


if __name__ == "__main__":
    asyncio.run(main())
