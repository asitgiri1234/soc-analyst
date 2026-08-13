"""Logging setup for the application.

Two formats, chosen by environment. Locally, a human reads the log in a
terminal, so lines are aligned and plain. Deployed, a log shipper reads it, so
lines are JSON -- one object per line, which every aggregator can parse without
a bespoke grok pattern.

Both carry the request id. A client that reports "I got a 500 and it said
b3c91e4f" can have that traced to the exact line that explains why, which is the
whole reason the id is in the response at all.

*Nothing here formats secrets.* The record's message and arguments are written
as given, so the discipline is at the call site: log identifiers, not
credentials. `GROQ_API_KEY` is a `SecretStr` and the Groq provider scrubs
key-shaped text from its errors, so neither reaches a formatter with anything
to redact.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from typing import Any

from app.core.config import settings

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

# Set by the security middleware for the duration of a request. A ContextVar
# rather than a thread local: the server is async, and many requests share a
# thread while never sharing a context.
request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)

# Attributes LogRecord always carries. Anything else on a record was put there
# deliberately by a caller, so it belongs in the structured output.
_STANDARD_FIELDS = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }
)


class RequestIdFilter(logging.Filter):
    """Attach the current request id to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        # An explicit `extra={"request_id": ...}` wins. The error handler runs
        # outside the middleware that sets the context variable, so it passes
        # the id itself and must not have it overwritten with None here.
        if getattr(record, "request_id", None) is None:
            record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id

        if record.exc_info:
            # The traceback goes to the log and nowhere near a response body.
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in _STANDARD_FIELDS and key != "request_id":
                payload[key] = value

        # `default=str` so an unexpected object logs as its repr instead of
        # raising inside the logger and losing the line entirely.
        return json.dumps(payload, default=str)


class HumanFormatter(logging.Formatter):
    """The aligned local format, with the request id appended when present."""

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        request_id = getattr(record, "request_id", None)
        return f"{line} [{request_id}]" if request_id else line


def configure_logging() -> None:
    """Install a single stdout handler on the root logger.

    Stdout, not a file: containers are expected to log to the stream and let
    the platform collect it. A log file inside a container is one nobody reads
    and nobody rotates.
    """
    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL.upper())

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if settings.LOG_FORMAT == "json" else HumanFormatter(_LOG_FORMAT)
    )
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)

    # Uvicorn installs its own handlers; let them propagate to ours instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
