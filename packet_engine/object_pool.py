from __future__ import annotations

import queue
import threading
from typing import Generic, List, TypeVar, Optional

T = TypeVar("T")


class ObjectPool(Generic[T]):
    """
    Thread-safe object pool / free-list for recycling objects.
    Eliminates Python garbage collection (GC) allocation overhead under high packet rates.
    """

    __slots__ = ("_pool", "_max_size", "_lock", "_recycled_count", "_borrowed_count")

    def __init__(self, max_size: int = 10_000):
        self._pool: List[T] = []
        self._max_size = max_size
        self._lock = threading.Lock()
        self._recycled_count = 0
        self._borrowed_count = 0

    def borrow() -> T | None:
        with self._lock:
            if self._pool:
                self._borrowed_count += 1
                return self._pool.pop()
            return None

    def recycle(self, obj: T) -> bool:
        with self._lock:
            if len(self._pool) < self._max_size:
                self._pool.append(obj)
                self._recycled_count += 1
                return True
            return False

    @property
    def pool_depth(self) -> int:
        with self._lock:
            return len(self._pool)

    @property
    def metrics(self) -> dict[str, int]:
        with self._lock:
            return {
                "pool_depth": len(self._pool),
                "max_size": self._max_size,
                "recycled_total": self._recycled_count,
                "borrowed_total": self._borrowed_count,
            }


class PacketObservationPool:
    """Global pool for recycling PacketObservation instances."""
    _instance: Optional[ObjectPool] = None

    @classmethod
    def get_pool(cls, max_size: int = 20_000) -> ObjectPool:
        if cls._instance is None:
            cls._instance = ObjectPool(max_size=max_size)
        return cls._instance
