"""Request rate limiting.

A fixed window counted in Redis. Fixed rather than sliding because the failure
mode is understood and cheap: a caller can send up to twice the limit across a
window boundary, which is acceptable for the thing this protects against --
sustained credential guessing and scripted scraping, not a precisely metered
billing quota.

*Login is limited by address and by account, not only by address.* Limiting
purely by IP lets a distributed attacker spray one password across many accounts
from many hosts; limiting purely by account lets one host lock every user out
of the platform by failing their logins deliberately. Both counters run, and
either can refuse.

*Availability decides the failure mode.* The token denylist fails closed, since
an unreadable denylist may be hiding a revoked token. This fails **open**: if
Redis is down, a SOC that cannot authenticate at all during an incident is a
worse outcome than one running briefly without throttling. The choice is logged
so the gap is visible rather than silent.
"""

from __future__ import annotations

from dataclasses import dataclass

from redis.exceptions import RedisError

from app.core.logging import get_logger
from app.db.redis import get_redis

logger = get_logger(__name__)

KEY_PREFIX = "ratelimit"


@dataclass(frozen=True, slots=True)
class RateLimitVerdict:
    """The outcome of one rate-limit check."""

    allowed: bool
    limit: int
    remaining: int
    retry_after: int

    @property
    def exceeded(self) -> bool:
        return not self.allowed


async def check(
    identifier: str,
    *,
    limit: int,
    window_seconds: int,
    scope: str,
) -> RateLimitVerdict:
    """Count one request against ``scope``:``identifier``.

    The counter is incremented first and given a TTL only when it is new, so
    the window starts at the first request rather than sliding forward with
    every subsequent one -- otherwise a steady stream of requests would keep
    resetting the expiry and the window would never close.
    """
    key = f"{KEY_PREFIX}:{scope}:{identifier}"

    try:
        redis = get_redis()
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.ttl(key)
            count, ttl = await pipe.execute()

        if ttl < 0:
            # Either the key was just created or it somehow lost its TTL; in
            # both cases the window starts now.
            await redis.expire(key, window_seconds)
            ttl = window_seconds
    except (OSError, RedisError) as exc:
        # Fail open, loudly. See the module docstring.
        logger.warning("rate limiting unavailable (%s); allowing request", exc)
        return RateLimitVerdict(
            allowed=True, limit=limit, remaining=limit, retry_after=0
        )

    remaining = max(0, limit - int(count))
    return RateLimitVerdict(
        allowed=int(count) <= limit,
        limit=limit,
        remaining=remaining,
        retry_after=int(ttl) if ttl > 0 else window_seconds,
    )


async def reset(identifier: str, *, scope: str) -> None:
    """Clear a counter.

    Called after a successful login so that a user who mistyped a password
    several times is not still carrying those failures into their next session.
    """
    try:
        await get_redis().delete(f"{KEY_PREFIX}:{scope}:{identifier}")
    except (OSError, RedisError) as exc:  # pragma: no cover - best effort
        logger.warning("could not reset rate limit counter: %s", exc)


def client_identifier(client_host: str | None, forwarded_for: str | None) -> str:
    """Identify the caller for rate-limiting purposes.

    ``X-Forwarded-For`` is only consulted when the deployment says a trusted
    proxy sits in front. Otherwise any client could set the header and give
    itself a fresh quota per request, which would make the limit decorative.
    """
    if forwarded_for:
        # Left-most entry is the original client, per convention.
        candidate = forwarded_for.split(",")[0].strip()
        if candidate:
            return candidate
    return client_host or "unknown"
