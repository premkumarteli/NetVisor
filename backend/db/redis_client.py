import redis
import logging
from typing import Optional
from backend.core.config import settings

logger = logging.getLogger("netvisor.db.redis")

import threading

_redis_pool: Optional[redis.ConnectionPool] = None
_redis_lock = threading.Lock()

def get_redis_pool() -> redis.ConnectionPool:
    global _redis_pool
    if _redis_pool is None:
        with _redis_lock:
            if _redis_pool is None:
                logger.info("Initializing Redis connection pool: %s:%s", settings.REDIS_HOST, settings.REDIS_PORT)
                pool_kwargs = {
                    "host": settings.REDIS_HOST,
                    "port": settings.REDIS_PORT,
                    "decode_responses": True,
                    "max_connections": 50,
                    "socket_connect_timeout": 0.5,
                    "socket_timeout": 5.0,
                }
                if settings.REDIS_PASSWORD:
                    pool_kwargs["password"] = settings.REDIS_PASSWORD
                if settings.REDIS_DB:
                    pool_kwargs["db"] = settings.REDIS_DB
                _redis_pool = redis.ConnectionPool(**pool_kwargs)
    return _redis_pool

def get_redis_connection() -> redis.Redis:
    """Returns a client connection from the shared Redis connection pool."""
    pool = get_redis_pool()
    return redis.Redis(connection_pool=pool)
