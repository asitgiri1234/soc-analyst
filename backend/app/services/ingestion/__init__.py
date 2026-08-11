"""Log ingestion: parse an uploaded file, normalise it, store it.

The three stages are deliberately separate:

``parsers``     bytes -> numbered raw records, one per row/object
``normalizer``  a raw record -> the columns of a LogEntry
``pipeline``    drives both, batches the inserts and records the outcome

Splitting them keeps the field-mapping rules testable without a database and
without HTTP.
"""

from app.services.ingestion.pipeline import ingest_upload
from app.services.ingestion.types import IngestionOutcome, RowError

__all__ = ["IngestionOutcome", "RowError", "ingest_upload"]
