"""Splitting a document into passages worth embedding separately.

Two rules shape this:

*Split on structure where possible.* A chunk that begins mid-sentence embeds
badly and reads worse when it is quoted back to an analyst as evidence, so the
splitter prefers a paragraph break, then a sentence end, then whitespace, and
only cuts mid-word when a single "word" is longer than the whole chunk.

*Overlap the seam.* A procedure that straddles a boundary would otherwise be
retrievable from neither side; carrying the tail of each chunk into the next
means a passage near a seam still appears whole somewhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.config import settings

# Boundaries in descending order of preference. The paragraph break is the
# strongest signal a document gives about where one idea ends.
_PARAGRAPH = re.compile(r"\n\s*\n")
_SENTENCE = re.compile(r"(?<=[.!?])\s")
_WHITESPACE = re.compile(r"\s")

# How far back from the hard limit the splitter will look for a nicer boundary.
# Beyond this the chunks become too uneven to be worth the tidier seam.
_LOOKBACK_FRACTION = 0.35


@dataclass(frozen=True, slots=True)
class Chunk:
    """One passage, with its position in the document."""

    index: int
    content: str

    @property
    def char_count(self) -> int:
        return len(self.content)


def normalise(text: str) -> str:
    """Collapse line-ending and trailing-whitespace noise.

    Done before splitting so that a document uploaded with CRLF endings chunks
    identically to the same document with LF, and so its checksum matches.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    return text.strip()


def _boundary(text: str, start: int, hard_end: int) -> int:
    """Find the nicest place to end a chunk at or before ``hard_end``."""
    window_start = max(start + int((hard_end - start) * (1 - _LOOKBACK_FRACTION)), start + 1)
    window = text[window_start:hard_end]

    for pattern in (_PARAGRAPH, _SENTENCE, _WHITESPACE):
        matches = list(pattern.finditer(window))
        if matches:
            return window_start + matches[-1].end()

    # A single unbroken run longer than the chunk size: cut it.
    return hard_end


def chunk_text(
    text: str,
    *,
    chunk_size: int | None = None,
    overlap: int | None = None,
) -> list[Chunk]:
    """Split text into overlapping chunks.

    Sizes default to ``RAG_CHUNK_SIZE`` / ``RAG_CHUNK_OVERLAP`` but are
    arguments so a caller can tune per corpus -- short alert templates and long
    policy documents do not want the same shape.
    """
    size = chunk_size if chunk_size is not None else settings.RAG_CHUNK_SIZE
    lap = overlap if overlap is not None else settings.RAG_CHUNK_OVERLAP

    if size <= 0:
        raise ValueError("chunk_size must be positive")
    if lap < 0:
        raise ValueError("overlap must not be negative")
    if lap >= size:
        # Without this the cursor never advances and the loop runs forever.
        raise ValueError("overlap must be smaller than chunk_size")

    cleaned = normalise(text)
    if not cleaned:
        return []
    if len(cleaned) <= size:
        return [Chunk(index=0, content=cleaned)]

    chunks: list[Chunk] = []
    cursor = 0
    while cursor < len(cleaned):
        hard_end = min(cursor + size, len(cleaned))
        end = hard_end if hard_end == len(cleaned) else _boundary(cleaned, cursor, hard_end)

        piece = cleaned[cursor:end].strip()
        if piece:
            chunks.append(Chunk(index=len(chunks), content=piece))

        if end >= len(cleaned):
            break

        # Step forward by at least one character even if the overlap would
        # otherwise put the cursor back where it started.
        cursor = max(end - lap, cursor + 1)

    return chunks
