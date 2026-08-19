import redis
import logging
from typing import Optional
from backend.core.config import settings

logger = logging.getLogger("netvisor.db.redis")

_redis_pool: Optional[redis.ConnectionPool] = None

def get_redis_pool() -> redis.ConnectionPool:
    global _redis_pool
    if _redis_pool is None:
        logger.info("Initializing Redis connection pool: %s:%s", settings.REDIS_HOST, settings.REDIS_PORT)
        _redis_pool = redis.ConnectionPool(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            decode_responses=True,  # Decode bytes to strings automatically
            max_connections=50,
            socket_connect_timeout=0.5,
            socket_timeout=5.0,
        )
    return _redis_pool

def get_redis_connection() -> redis.Redis:
    """Returns a client connection from the shared Redis connection pool."""
    pool = get_redis_pool()
    return redis.Redis(connection_pool=pool)
