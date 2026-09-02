import json
import logging
from typing import Callable, Any

logger = logging.getLogger("netvisor.cache")

def cached_response(cache_key: str, ttl_seconds: int, fetch_fn: Callable[[], Any]) -> Any:
    """
    Tries to fetch cached JSON from Redis by cache_key.
    On cache miss or Redis error, calls fetch_fn(), caches the JSON result if successful, and returns it.
    """
    try:
        from ..db.redis_client import get_redis_connection
        r = get_redis_connection()
        if r:
            cached_bytes = r.get(cache_key)
            if cached_bytes:
                return json.loads(cached_bytes.decode("utf-8"))
    except Exception as exc:
        logger.debug("Redis cache fetch notice for key %s: %s", cache_key, exc)
        r = None

    result = fetch_fn()

    if r and result is not None:
        try:
            r.setex(cache_key, ttl_seconds, json.dumps(result, default=str))
        except Exception as exc:
            logger.debug("Redis cache store notice for key %s: %s", cache_key, exc)

    return result
