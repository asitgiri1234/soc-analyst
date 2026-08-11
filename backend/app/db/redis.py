"""Redis client lifecycle."""

from redis.asyncio import Redis, from_url

from app.core.config import settings

_client: Redis | None = None


def get_redis() -> Redis:
    """Return the process-wide Redis client, creating it on first use."""
    global _client
    if _client is None:
        _client = from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    return _client


async def close_redis() -> None:
    """Close the Redis client during application shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
