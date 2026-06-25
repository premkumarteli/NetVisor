import threading
from datetime import datetime
from typing import Dict, Tuple

class SuppressionStore:
    def __init__(self) -> None:
        # Key: (target_ip, identifier) -> last_emitted_datetime
        self._last_emitted: Dict[Tuple[str, str], datetime] = {}
        self._lock = threading.RLock()

    def should_suppress(self, target_ip: str, identifier: str, observed_at: datetime, suppression_window: float) -> bool:
        """
        Check if an alert with the given identifier for a target IP should be suppressed
        based on the suppression window.
        """
        if not target_ip:
            return False
            
        key = (target_ip, identifier)
        with self._lock:
            if key in self._last_emitted:
                last_ts = self._last_emitted[key]
                delta = (observed_at - last_ts).total_seconds()
                if 0 <= delta <= suppression_window:
                    return True
            return False

    def record_emission(self, target_ip: str, identifier: str, observed_at: datetime) -> None:
        """
        Record that an alert was emitted to update its suppression cooldown.
        """
        if not target_ip:
            return
            
        key = (target_ip, identifier)
        with self._lock:
            if key not in self._last_emitted or observed_at > self._last_emitted[key]:
                self._last_emitted[key] = observed_at

    def clear(self) -> None:
        """Clear all emission history."""
        with self._lock:
            self._last_emitted.clear()
