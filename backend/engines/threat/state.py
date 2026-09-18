import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Tuple

_MAX_ENTRIES_PER_KEY = 100
_MAX_KEYS = 1000


class SlidingWindowStore:
    """Manages in-memory sliding windows of event histories for stateful detectors.

    Each deque is capped at ``_MAX_ENTRIES_PER_KEY`` entries and the total
    number of distinct keys is capped at ``_MAX_KEYS``.  Under sustained
    attack the oldest entries are evicted first, preventing unbounded memory
    growth.
    """
    def __init__(self) -> None:
        self._stores: defaultdict = defaultdict(deque)
        self._lock = threading.RLock()

    def add(self, key: Tuple[Any, ...], timestamp: datetime, value: Any = None) -> None:
        """Adds an event to the key's sliding window store."""
        with self._lock:
            if len(self._stores) >= _MAX_KEYS and key not in self._stores:
                self._evict_oldest_key()

            entry = (timestamp, value) if value is not None else timestamp
            bucket = self._stores[key]
            bucket.append(entry)
            while len(bucket) > _MAX_ENTRIES_PER_KEY:
                bucket.popleft()

    def get_and_prune(self, key: Tuple[Any, ...], observed_at: datetime, window_seconds: int) -> list:
        """Prunes expired entries outside the time window and returns the active window as a copy."""
        with self._lock:
            bucket = self._stores[key]
            while bucket:
                head = bucket[0]
                head_ts = head[0] if isinstance(head, tuple) else head
                if not isinstance(head_ts, datetime):
                    break
                if (observed_at - head_ts).total_seconds() <= window_seconds:
                    break
                bucket.popleft()

            # Prune empty keys to prevent memory leaks
            active_events = list(bucket)
            if not active_events:
                self._stores.pop(key, None)
            return active_events

    def _evict_oldest_key(self) -> None:
        """Remove the key with the oldest head entry."""
        oldest_key = None
        oldest_ts = None
        for k, v in self._stores.items():
            if not v:
                continue
            head = v[0]
            head_ts = head[0] if isinstance(head, tuple) else head
            if oldest_ts is None or (isinstance(head_ts, datetime) and head_ts < oldest_ts):
                oldest_ts = head_ts
                oldest_key = k
        if oldest_key is not None:
            self._stores.pop(oldest_key, None)

    def clear(self) -> None:
        """Resets all windows."""
        with self._lock:
            self._stores.clear()


def get_flow_field(flow: Any, field_name: str, default: Any = None) -> Any:
    """Retrieves a field from a flow dictionary or object."""
    if isinstance(flow, dict):
        return flow.get(field_name, default)
    return getattr(flow, field_name, default)

