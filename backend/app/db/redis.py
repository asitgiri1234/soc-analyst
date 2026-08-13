"""Redis client lifecycle."""

from redis.asyncio import Redis, from_url
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_client: Redis | None = None


def get_redis() -> Redis:
    """Return the process-wide Redis client, creating it on first use."""
    global _client
    if _client is None:
        _client = from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    return _client


async def close_redis() -> None:
    """Close the client and drop it from the cache.

    The cached reference is cleared *before* the close is attempted, so a
    connection whose event loop has already gone away cannot be handed to the
    next caller. A client bound to a dead loop fails on every command with
    "Event loop is closed", which is a far more confusing failure than simply
    reconnecting.
    """
    global _client
    client, _client = _client, None
    if client is None:
        return

    try:
        await client.aclose()
    except (OSError, RedisError, RuntimeError) as exc:
        # RuntimeError covers the closed-loop case above; there is nothing to
        # do about it beyond letting the connection go.
        logger.debug("closing the Redis client failed: %s", exc)
