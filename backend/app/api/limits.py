"""Rate-limit dependencies for the HTTP layer.

Kept apart from `deps.py` so the authentication dependencies stay readable, and
apart from `services/rate_limit.py` so the counting logic has no FastAPI import
and can be exercised on its own.

A refused request answers 429 with `Retry-After`, which is the header a
well-behaved client already knows how to obey.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.logging import get_logger
from app.services import rate_limit

logger = get_logger(__name__)


def caller_id(request: Request) -> str:
    """The address a limit is counted against."""
    forwarded = (
        request.headers.get("X-Forwarded-For") if settings.TRUST_PROXY_HEADERS else None
    )
    return rate_limit.client_identifier(
        request.client.host if request.client else None, forwarded
    )


def _refuse(verdict: rate_limit.RateLimitVerdict) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Please slow down and try again later.",
        headers={
            "Retry-After": str(verdict.retry_after),
            "X-RateLimit-Limit": str(verdict.limit),
            "X-RateLimit-Remaining": str(verdict.remaining),
        },
    )


async def enforce(identifier: str, *, scope: str, limit: int, window: int) -> None:
    """Count a request and raise 429 if it puts the caller over the limit."""
    if not settings.RATE_LIMIT_ENABLED:
        return

    verdict = await rate_limit.check(
        identifier, limit=limit, window_seconds=window, scope=scope
    )
    if verdict.exceeded:
        # Logged at warning: sustained 429s on login are an attack signal, and
        # this is the line a SOC would alert on.
        logger.warning("rate limit exceeded for scope=%s id=%s", scope, identifier)
        raise _refuse(verdict)


def limit_by_address(
    *, scope: str, limit: int, window: int
) -> Callable[[Request], Awaitable[None]]:
    """Build a dependency limiting an endpoint by caller address."""

    async def dependency(request: Request) -> None:
        await enforce(caller_id(request), scope=scope, limit=limit, window=window)

    return dependency


LoginRateLimit = limit_by_address(
    scope="login",
    limit=settings.RATE_LIMIT_LOGIN_ATTEMPTS,
    window=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
)

RegisterRateLimit = limit_by_address(
    scope="register",
    limit=settings.RATE_LIMIT_REGISTER_ATTEMPTS,
    window=settings.RATE_LIMIT_REGISTER_WINDOW_SECONDS,
)
