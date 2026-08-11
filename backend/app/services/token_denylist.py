"""Revocation list for access tokens.

Access tokens are stateless, so signing one out means recording that it must no
longer be honoured. Each revoked token's ``jti`` is stored in Redis with a TTL
matching what was left of its lifetime -- once the token would have expired
anyway, the key disappears on its own and the list stays small.

The check **fails closed**: if Redis cannot be reached, tokens are treated as
potentially revoked and rejected. For a security platform, continuing to accept
credentials that may have been withdrawn is the worse failure. Deployments that
would rather trade that off can set ``AUTH_TOKEN_DENYLIST_ENABLED=false``, which
makes logout audit-only and leaves tokens valid until they expire.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging import get_logger
from app.db.redis import get_redis

logger = get_logger(__name__)

KEY_PREFIX = "auth:revoked-jti:"


class DenylistUnavailableError(Exception):
    """Raised when revocation state cannot be read."""


def _key(jti: str) -> str:
    return f"{KEY_PREFIX}{jti}"


async def revoke(jti: str, expires_at: datetime) -> bool:
    """Mark a token as revoked until it would have expired.

    Returns False when revocation is disabled or Redis is unreachable, so the
    caller can tell the client its token is still live.
    """
    if not settings.AUTH_TOKEN_DENYLIST_ENABLED:
        return False

    ttl = math.ceil((expires_at - datetime.now(UTC)).total_seconds())
    if ttl <= 0:
        # Already expired; the signature check alone will reject it.
        return True

    try:
        await get_redis().set(_key(jti), "1", ex=ttl)
    except RedisError as exc:
        logger.error("could not revoke token %s: %s", jti, exc)
        return False
    return True


async def is_revoked(jti: str) -> bool:
    """Whether a token has been revoked.

    Raises ``DenylistUnavailableError`` rather than guessing when Redis is down.
    """
    if not settings.AUTH_TOKEN_DENYLIST_ENABLED:
        return False

    try:
        return await get_redis().exists(_key(jti)) == 1
    except RedisError as exc:
        logger.error("denylist unavailable: %s", exc)
        raise DenylistUnavailableError(str(exc)) from exc
