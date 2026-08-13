"""HTTP-level defences applied to every response.

Three things live here:

*Security headers.* Cheap, and they close off whole categories of attack that
no amount of endpoint code can. The CSP is strict because this service returns
JSON: it has no scripts, styles or frames of its own to allow, so the policy can
deny nearly everything. The interactive docs are the exception, and are
exempted explicitly rather than by loosening the policy for the whole app.

*A request id.* Correlates a client's report of an error with the log line that
explains it, without the response having to carry the explanation.

*Generic error responses.* An unhandled exception is logged in full, server
side, and answered with a bare 500. A stack trace in an API response tells an
attacker the framework, the file layout, and often the query that failed.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import get_logger, request_id_var

logger = get_logger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

# The API serves JSON to a separate frontend origin. It needs no script, style,
# image or frame source of its own, so everything is denied and `frame-ancestors
# 'none'` stops the responses being framed regardless of X-Frame-Options
# support.
API_CSP = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "sandbox"
)

# Swagger UI and ReDoc load their assets from a CDN and run inline scripts. They
# are developer tools, not part of the API surface, so they get their own policy
# rather than the API's being widened to accommodate them.
DOCS_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "worker-src 'self' blob:; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)

DOCS_PATHS = ("/docs", "/redoc", "/docs/oauth2-redirect")

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # This service has no use for any of these; denying them means a future
    # change has to opt in deliberately.
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
    "magnetometer=(), microphone=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    # Security data must not sit in a shared cache.
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach security headers and a request id to every response."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        # Available to handlers and to the error responder below.
        request.state.request_id = request_id
        # And to every log line emitted while handling this request, so a
        # client's report of an error leads straight to the line explaining it.
        token = request_id_var.set(request_id)

        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)

        for header, value in BASE_HEADERS.items():
            response.headers.setdefault(header, value)

        is_docs = request.url.path in DOCS_PATHS
        response.headers.setdefault(
            "Content-Security-Policy", DOCS_CSP if is_docs else API_CSP
        )

        # HSTS only where TLS is actually in use. Sending it from a plaintext
        # local server would pin a developer's browser to https://localhost.
        if settings.ENVIRONMENT in {"staging", "production"}:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )

        response.headers[REQUEST_ID_HEADER] = request_id
        return response


def install_error_handlers(app: FastAPI) -> None:
    """Answer unhandled exceptions with a generic 500.

    Registered as a handler for `Exception` so that anything not already turned
    into an `HTTPException` is caught. The detail goes to the log with the
    request id; the client gets the id and nothing else, which is enough to ask
    an operator what happened without being told.
    """

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.error(
            "unhandled error on %s %s",
            request.method,
            request.url.path,
            exc_info=exc,
            # Passed explicitly: this handler runs outside the middleware, so
            # the context variable has already been reset by now.
            extra={"request_id": request_id},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "request_id": request_id,
            },
            headers={REQUEST_ID_HEADER: request_id},
        )
