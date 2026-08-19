import threading
from typing import Optional, Literal
from pydantic import BaseModel, Field

class EvidenceSnapshot(BaseModel):
    signals: set[str] = Field(default_factory=set)
    max_severity: Literal["low", "medium", "high", "critical"] = "low"
    last_seen: float

class EvidenceCache:
    """
    A shared, thread-safe cache containing threat signals for hosts.
    Populated asynchronously by detector modules, threat engines, or database sync.
    """
    def __init__(self, max_entries_per_org: int = 50000) -> None:
        self._lock = threading.RLock()
        # (org_id, entity_ip) -> {
        #     "signals": {
        #         signal_name -> {"severity_level": int_val, "expires_at": float}
        #     },
        #     "last_seen": float
        # }
        self._cache: dict[tuple[str, str], dict] = {}
        self._max_entries = max_entries_per_org
        self._severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        self._reverse_severity_map = {0: "low", 1: "medium", 2: "high", 3: "critical"}

    def record(
        self,
        org_id: str,
        entity_ip: str,
        signal: str,
        severity: Literal["low", "medium", "high", "critical"],
        timestamp: float,
        ttl_seconds: float = 300.0,
    ) -> None:
        """
        Record a threat signal for a given host (entity_ip) in an organization.
        Each signal has its own independent expiry time.
        """
        key = (org_id, entity_ip)
        severity_val = self._severity_map.get(severity.lower(), 0)
        expires_at = timestamp + ttl_seconds

        with self._lock:
            # Cleanup expired entries first to free up space
            self.cleanup_expired(timestamp)

            if key not in self._cache:
                # Evict if exceeding limits
                org_keys = [k for k in self._cache.keys() if k[0] == org_id]
                if len(org_keys) >= self._max_entries:
                    # Find key with oldest overall signal expires_at
                    oldest_key = min(
                        org_keys,
                        key=lambda k: min(sig_data["expires_at"] for sig_data in self._cache[k].get("signals", {}).values()) if self._cache[k].get("signals") else 0.0
                    )
                    del self._cache[oldest_key]

                self._cache[key] = {
                    "signals": {},
                    "last_seen": timestamp
                }

            entry = self._cache[key]
            entry["signals"][signal] = {
                "severity_level": severity_val,
                "expires_at": expires_at
            }
            entry["last_seen"] = max(entry["last_seen"], timestamp)

    def get_active(self, org_id: str, entity_ip: str, now: float) -> Optional[EvidenceSnapshot]:
        """
        Retrieve active threat signals for a host. Returns None if expired or no signals exist.
        """
        key = (org_id, entity_ip)
        with self._lock:
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            active_signals = {}
            for sig, sig_data in list(entry["signals"].items()):
                if now <= sig_data["expires_at"]:
                    active_signals[sig] = sig_data
                else:
                    del entry["signals"][sig]
            
            if not active_signals:
                del self._cache[key]
                return None
                
            max_severity_val = max(sig_data["severity_level"] for sig_data in active_signals.values())
            severity_str = self._reverse_severity_map.get(max_severity_val, "low")
            
            return EvidenceSnapshot(
                signals=set(active_signals.keys()),
                max_severity=severity_str,
                last_seen=entry["last_seen"]
            )

    def cleanup_expired(self, now: float) -> None:
        """
        Prunes all expired entries and individual signals from the cache.
        """
        with self._lock:
            empty_keys = []
            for key, entry in list(self._cache.items()):
                for sig, sig_data in list(entry["signals"].items()):
                    if now > sig_data["expires_at"]:
                        del entry["signals"][sig]
                if not entry["signals"]:
                    empty_keys.append(key)
            
            for key in empty_keys:
                del self._cache[key]

    def clear(self) -> None:
        """
        Clear all entries (useful during tests or shutdown).
        """
        with self._lock:
            self._cache.clear()

evidence_cache = EvidenceCache()
