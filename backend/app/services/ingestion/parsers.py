"""Turning an uploaded file into numbered records.

Each parser yields ``RawRecord`` for rows it could read and ``RowError`` for
rows it could not, so one unreadable line never stops the file. Only a failure
that makes the whole document unreadable -- a bad encoding, or JSON that is not
valid JSON -- raises ``UnreadableFileError``.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from typing import Any

from app.models.enums import IngestionFormat
from app.services.ingestion.types import RawRecord, RowError, UnreadableFileError

# Keys a JSON document might wrap its list of events in.
ENVELOPE_KEYS = ("events", "logs", "records", "entries", "data", "results")

# csv fields default to a 128 KB cap; a single log line will not exceed it, and
# raising the limit process-wide would be a denial-of-service foothold.
MAX_CSV_FIELD_BYTES = 131072

EXTENSIONS: dict[str, IngestionFormat] = {
    ".csv": IngestionFormat.CSV,
    ".json": IngestionFormat.JSON,
    ".jsonl": IngestionFormat.NDJSON,
    ".ndjson": IngestionFormat.NDJSON,
    ".log": IngestionFormat.NDJSON,
}


def decode(payload: bytes) -> str:
    """Decode an upload as UTF-8.

    ``utf-8-sig`` strips the byte-order mark that spreadsheet exports prepend,
    which would otherwise become part of the first column's name.
    """
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UnreadableFileError(
            f"file is not valid UTF-8 (byte {exc.start}); re-encode it as UTF-8"
        ) from exc


def detect_format(filename: str, content_type: str | None) -> IngestionFormat | None:
    """Work out the format from the filename, falling back to the content type.

    Returns None when neither identifies a format the parser supports; the
    caller turns that into a 415.
    """
    lowered = filename.lower()
    for extension, fmt in EXTENSIONS.items():
        if lowered.endswith(extension):
            return fmt

    match (content_type or "").split(";")[0].strip().lower():
        case "text/csv" | "application/csv":
            return IngestionFormat.CSV
        case "application/json":
            return IngestionFormat.JSON
        case "application/x-ndjson" | "application/jsonl":
            return IngestionFormat.NDJSON
        case _:
            return None


def parse(text: str, fmt: IngestionFormat) -> Iterator[RawRecord | RowError]:
    """Dispatch to the parser for a format."""
    match fmt:
        case IngestionFormat.CSV:
            yield from _parse_csv(text)
        case IngestionFormat.JSON:
            yield from _parse_json(text)
        case IngestionFormat.NDJSON:
            yield from _parse_ndjson(text)


def _sniff_delimiter(sample: str) -> str:
    """Guess the column separator, defaulting to a comma."""
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def _parse_csv(text: str) -> Iterator[RawRecord | RowError]:
    if not text.strip():
        raise UnreadableFileError("file is empty")

    csv.field_size_limit(MAX_CSV_FIELD_BYTES)
    delimiter = _sniff_delimiter(text[:8192])
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)

    if not reader.fieldnames:
        raise UnreadableFileError("CSV file has no header row")
    if all(not (name or "").strip() for name in reader.fieldnames):
        raise UnreadableFileError("CSV header row is blank")

    columns = len(reader.fieldnames)
    while True:
        # Line 1 is the header, so the first data row is line 2.
        line = reader.line_num + 1
        try:
            row = next(reader)
        except StopIteration:
            return
        except csv.Error as exc:
            yield RowError(line=line, reason=f"malformed CSV row: {exc}")
            continue

        if all(value in (None, "") for value in row.values()):
            continue  # blank line

        # DictReader parks surplus columns under None and pads missing ones.
        extra = row.pop(None, None)
        if extra:
            yield RowError(
                line=line,
                reason=f"row has more fields than the {columns}-column header",
            )
            continue
        if any(value is None for value in row.values()):
            yield RowError(
                line=line,
                reason=f"row has fewer fields than the {columns}-column header",
            )
            continue

        cleaned = {key.strip(): value for key, value in row.items() if key}
        yield RawRecord(line=line, data=cleaned, raw=_render(cleaned))


def _parse_json(text: str) -> Iterator[RawRecord | RowError]:
    if not text.strip():
        raise UnreadableFileError("file is empty")

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UnreadableFileError(
            f"file is not valid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}"
        ) from exc

    records = _unwrap(document)
    for index, item in enumerate(records, start=1):
        if isinstance(item, dict):
            yield RawRecord(line=index, data=item, raw=_render(item))
        else:
            yield RowError(
                line=index,
                reason=f"expected a JSON object, found {type(item).__name__}",
            )


def _unwrap(document: Any) -> list[Any]:
    """Find the list of events in a JSON document.

    Accepts a bare array, a single object, or an object wrapping the array under
    a conventional key such as ``events``.
    """
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ENVELOPE_KEYS:
            value = document.get(key)
            if isinstance(value, list):
                return value
        return [document]
    raise UnreadableFileError(
        f"expected a JSON array or object, found {type(document).__name__}"
    )


def _parse_ndjson(text: str) -> Iterator[RawRecord | RowError]:
    seen = False
    for line, content in enumerate(text.splitlines(), start=1):
        if not content.strip():
            continue
        seen = True
        try:
            item = json.loads(content)
        except json.JSONDecodeError as exc:
            yield RowError(line=line, reason=f"invalid JSON: {exc.msg}")
            continue

        if isinstance(item, dict):
            yield RawRecord(line=line, data=item, raw=content)
        else:
            yield RowError(
                line=line, reason=f"expected a JSON object, found {type(item).__name__}"
            )

    if not seen:
        raise UnreadableFileError("file is empty")


def _render(data: dict[str, Any]) -> str:
    """Compact rendering of a record, kept as ``LogEntry.raw``."""
    return json.dumps(data, separators=(",", ":"), default=str)
