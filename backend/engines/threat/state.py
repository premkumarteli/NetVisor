import threading
from collections import deque, OrderedDict
from datetime import datetime
from typing import Any, Tuple

_MAX_ENTRIES_PER_KEY = 100
_MAX_KEYS = 1000


class SlidingWindowStore:
    """Manages in-memory sliding windows of event histories for stateful detectors.

    Each deque is capped at ``_MAX_ENTRIES_PER_KEY`` entries and the total
    number of distinct keys is capped at ``_MAX_KEYS``. Under sustained
    attack the oldest entries are evicted first in O(1) time via an LRU
    OrderedDict, preventing unbounded memory growth and eliminating eviction cliffs.
    """
    def __init__(self, max_keys: int = _MAX_KEYS, max_entries: int = _MAX_ENTRIES_PER_KEY) -> None:
        self._max_keys = max_keys
        self._max_entries = max_entries
        self._stores: dict[Tuple[Any, ...], deque] = {}
        self._key_order: OrderedDict[Tuple[Any, ...], None] = OrderedDict()
        self._lock = threading.RLock()

    def add(self, key: Tuple[Any, ...], timestamp: datetime, value: Any = None) -> None:
        """Adds an event to the key's sliding window store."""
        with self._lock:
            if len(self._stores) >= self._max_keys and key not in self._stores:
                self._evict_oldest_key()

            entry = (timestamp, value) if value is not None else timestamp
            if key not in self._stores:
                self._stores[key] = deque()
                self._key_order[key] = None
            else:
                self._key_order.move_to_end(key, last=True)

            bucket = self._stores[key]
            bucket.append(entry)
            while len(bucket) > self._max_entries:
                bucket.popleft()

    def get_and_prune(self, key: Tuple[Any, ...], observed_at: datetime, window_seconds: int) -> list:
        """Prunes expired entries outside the time window and returns the active window as a copy."""
        with self._lock:
            bucket = self._stores.get(key)
            if not bucket:
                return []

            if key in self._key_order:
                self._key_order.move_to_end(key, last=True)

            obs_ts = observed_at.replace(tzinfo=None) if observed_at.tzinfo else observed_at

            while bucket:
                head = bucket[0]
                head_ts = head[0] if isinstance(head, tuple) else head
                if not isinstance(head_ts, datetime):
                    break
                head_norm = head_ts.replace(tzinfo=None) if head_ts.tzinfo else head_ts
                if (obs_ts - head_norm).total_seconds() <= window_seconds:
                    break
                bucket.popleft()

            # Prune empty keys to prevent memory leaks
            active_events = list(bucket)
            if not active_events:
                self._stores.pop(key, None)
                self._key_order.pop(key, None)
            return active_events

    def _evict_oldest_key(self) -> None:
        """Remove the least recently added or accessed key in O(1) time."""
        if self._key_order:
            oldest_key, _ = self._key_order.popitem(last=False)
            self._stores.pop(oldest_key, None)

    def clear(self) -> None:
        """Resets all windows."""
        with self._lock:
            self._stores.clear()
            self._key_order.clear()


def get_flow_field(flow: Any, field_name: str, default: Any = None) -> Any:
    """Retrieves a field from a flow dictionary or object."""
    if isinstance(flow, dict):
        return flow.get(field_name, default)
    return getattr(flow, field_name, default)

