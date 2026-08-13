"""Structured logging and the request-id trail.

The point of these is that an operator can take the id from a failed response
and find the line that explains it, and that nothing sensitive rides along on
the way.
"""

from __future__ import annotations

import json
import logging
import uuid

import httpx

from app.core.logging import (
    HumanFormatter,
    JsonFormatter,
    RequestIdFilter,
    request_id_var,
)
from app.core.middleware import REQUEST_ID_HEADER
from app.services.rate_limit import KEY_PREFIX


def make_record(message: str = "something happened", **extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="app.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


# --- JSON formatting -------------------------------------------------------


def test_json_formatter_emits_one_object_per_line() -> None:
    rendered = JsonFormatter().format(make_record())
    payload = json.loads(rendered)

    assert "\n" not in rendered
    assert payload["level"] == "INFO"
    assert payload["logger"] == "app.test"
    assert payload["message"] == "something happened"
    assert payload["timestamp"]


def test_json_formatter_includes_custom_fields() -> None:
    """Anything a caller attached deliberately belongs in the output."""
    payload = json.loads(JsonFormatter().format(make_record(incident_id="INC-1", count=3)))

    assert payload["incident_id"] == "INC-1"
    assert payload["count"] == 3


def test_json_formatter_survives_an_unserialisable_field() -> None:
    """A bad value must not take the whole log line down with it."""

    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    payload = json.loads(JsonFormatter().format(make_record(thing=Opaque())))
    assert payload["thing"] == "<opaque>"


def test_json_formatter_puts_the_traceback_in_the_log() -> None:
    """Where it belongs -- never in a response body."""
    try:
        raise ValueError("the cause")
    except ValueError:
        import sys

        record = make_record("failed")
        record.exc_info = sys.exc_info()

    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: the cause" in payload["exception"]
    assert "Traceback" in payload["exception"]


# --- Request id correlation ------------------------------------------------


def test_the_filter_stamps_the_current_request_id() -> None:
    token = request_id_var.set("req-123")
    try:
        record = make_record()
        RequestIdFilter().filter(record)
        assert record.request_id == "req-123"
    finally:
        request_id_var.reset(token)


def test_an_explicit_request_id_is_not_overwritten() -> None:
    """The error handler runs outside the middleware and passes its own."""
    token = request_id_var.set("from-context")
    try:
        record = make_record(request_id="passed-explicitly")
        RequestIdFilter().filter(record)
        assert record.request_id == "passed-explicitly"
    finally:
        request_id_var.reset(token)


def test_the_human_formatter_appends_the_id_when_present() -> None:
    formatter = HumanFormatter("%(message)s")

    plain = make_record()
    plain.request_id = None
    assert formatter.format(plain) == "something happened"

    tagged = make_record()
    tagged.request_id = "req-9"
    assert formatter.format(tagged).endswith("[req-9]")


async def test_a_request_id_is_available_to_handlers(client: httpx.AsyncClient) -> None:
    """End to end: the header on the way out matches what was set on the way in."""
    supplied = str(uuid.uuid4())
    response = await client.get("/api/v1/health", headers={REQUEST_ID_HEADER: supplied})
    assert response.headers[REQUEST_ID_HEADER] == supplied


async def test_the_context_is_cleared_between_requests(client: httpx.AsyncClient) -> None:
    """A leaked id would attribute one request's logs to another."""
    await client.get("/api/v1/health", headers={REQUEST_ID_HEADER: "first"})
    assert request_id_var.get() is None


async def test_two_requests_get_distinct_ids(client: httpx.AsyncClient) -> None:
    first = await client.get("/api/v1/health")
    second = await client.get("/api/v1/health")
    assert first.headers[REQUEST_ID_HEADER] != second.headers[REQUEST_ID_HEADER]


# --- Readiness -------------------------------------------------------------


async def test_readiness_reports_each_dependency(client: httpx.AsyncClient) -> None:
    """Readiness is about dependencies; liveness is about this process."""
    response = await client.get("/api/v1/ready")
    body = response.json()

    assert response.status_code in {200, 503}
    assert set(body) >= {"status", "postgres", "redis"}
    assert body["status"] in {"ready", "degraded"}


async def test_readiness_never_reveals_the_connection_string(
    client: httpx.AsyncClient,
) -> None:
    """A failing dependency must not answer with credentials in the detail."""
    body = (await client.get("/api/v1/ready")).text
    assert "postgresql://" not in body
    assert "@" not in body.replace("\\u0040", "")


async def test_liveness_needs_no_dependencies(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# --- Naming consistency ----------------------------------------------------


def test_rate_limit_keys_share_one_prefix() -> None:
    """So an operator can find, count, or clear them all in one command."""
    assert KEY_PREFIX == "ratelimit"
