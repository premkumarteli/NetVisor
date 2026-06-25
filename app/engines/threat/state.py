import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Tuple

class SlidingWindowStore:
    """Manages in-memory sliding windows of event histories for stateful detectors."""
    def __init__(self) -> None:
        self._stores = defaultdict(deque)
        self._lock = threading.RLock()

    def add(self, key: Tuple[Any, ...], timestamp: datetime, value: Any = None) -> None:
        """Adds an event to the key's sliding window store."""
        with self._lock:
            if value is not None:
                self._stores[key].append((timestamp, value))
            else:
                self._stores[key].append(timestamp)

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

    def clear(self) -> None:
        """Resets all windows."""
        with self._lock:
            self._stores.clear()


def get_flow_field(flow: Any, field_name: str, default: Any = None) -> Any:
    """Retrieves a field from a flow dictionary or object."""
    if isinstance(flow, dict):
        return flow.get(field_name, default)
    return getattr(flow, field_name, default)

