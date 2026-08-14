"""Turning an uploaded file into text an analyst and a model can read.

Text formats only. A PDF or a .docx needs a parser, and every document parser
is a large dependency with a history of memory-safety bugs that would then be
processing attacker-influenced files. Nothing here interprets structure: the
bytes are decoded and stored.

The decoded text is bounded twice. Once at storage, so one upload cannot fill
a column, and again at prompt assembly, because the context window is a shared
budget and a long attachment must not crowd out log evidence. Truncation is
recorded rather than silent -- an analysis performed on the first four thousand
characters of a document should say so.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings

# Extension -> the content type recorded for it. Everything here is plain text
# in some dialect; the mapping exists so a caller sending
# application/octet-stream still gets a useful label.
ALLOWED_EXTENSIONS: dict[str, str] = {
    ".txt": "text/plain",
    ".log": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".ndjson": "application/x-ndjson",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".xml": "application/xml",
    ".conf": "text/plain",
    ".ini": "text/plain",
}

# A NUL byte in the first block is the usual, cheap tell that a file is binary
# whatever its extension claims.
_BINARY_SNIFF_BYTES = 8192


class AttachmentError(ValueError):
    """The upload cannot be stored as an attachment."""


@dataclass(frozen=True, slots=True)
class ExtractedText:
    """What was read out of an upload."""

    content: str
    truncated: bool
    content_type: str


def extension_of(filename: str) -> str:
    _, _, suffix = filename.rpartition(".")
    return f".{suffix.lower()}" if suffix and suffix != filename else ""


def is_supported(filename: str) -> bool:
    return extension_of(filename) in ALLOWED_EXTENSIONS


def extract(payload: bytes, *, filename: str, declared_type: str | None) -> ExtractedText:
    """Decode an upload to text, or explain why it cannot be.

    Rejects on extension rather than on the declared content type: the type is
    chosen by the client and a browser will happily send
    application/octet-stream for a .log file. The extension is equally
    client-controlled, but it is what the analyst sees and can correct.
    """
    extension = extension_of(filename)
    if extension not in ALLOWED_EXTENSIONS:
        raise AttachmentError(
            f"{extension or 'that file type'} is not supported. Attach a text "
            f"document: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    if not payload:
        raise AttachmentError("The file is empty.")

    if b"\x00" in payload[:_BINARY_SNIFF_BYTES]:
        raise AttachmentError(
            "The file looks binary. Attachments are stored as text, so only text "
            "documents can be read."
        )

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AttachmentError(
            f"The file is not valid UTF-8 (byte {exc.start}); re-encode it as UTF-8."
        ) from exc

    text = text.replace("\r\n", "\n").strip()
    if not text:
        raise AttachmentError("The file contains no text.")

    cap = settings.ATTACHMENT_MAX_TEXT_CHARS
    truncated = len(text) > cap
    if truncated:
        text = text[:cap]

    return ExtractedText(
        content=text,
        truncated=truncated,
        # The extension decides, since that is what was validated against.
        content_type=ALLOWED_EXTENSIONS[extension],
    )
