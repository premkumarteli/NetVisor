import threading
from datetime import datetime, timezone
from typing import Dict, Set, Tuple, Any

class WireGuardHeuristicDetector:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Maps (ip_a, ip_b, port_a, port_b) -> { "directions": {direction_tuple: set of sizes}, "last_seen": datetime }
        self._history: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}

    def analyze(self, flow: dict) -> bool:
        """
        Analyze a flow dictionary for WireGuard heuristics.
        Returns:
            bool: True if WireGuard heuristics are matched, False otherwise.
        """
        protocol = str(flow.get("protocol") or "").upper()
        if protocol != "UDP":
            return False

        src_ip = flow.get("src_ip", "0.0.0.0")
        dst_ip = flow.get("dst_ip", "0.0.0.0")
        src_port = int(flow.get("src_port") or 0)
        dst_port = int(flow.get("dst_port") or 0)

        # Extract WireGuard signals from analysis_signals
        signals = flow.get("analysis_signals") or []
        wg_sizes = set()
        for sig in signals:
            if sig.startswith("wg_size_"):
                try:
                    size = int(sig.split("_")[-1])
                    wg_sizes.add(size)
                except ValueError:
                    pass

        if not wg_sizes:
            return False

        # Direction-independent key
        ip_a, ip_b = min(src_ip, dst_ip), max(src_ip, dst_ip)
        port_a, port_b = min(src_port, dst_port), max(src_port, dst_port)
        key = (ip_a, ip_b, port_a, port_b)

        direction = (src_ip, dst_ip)

        # Resolve timestamp
        last_seen = flow.get("last_seen")
        if not last_seen:
            observed_at = datetime.now(timezone.utc)
        elif isinstance(last_seen, datetime):
            observed_at = last_seen
        else:
            try:
                observed_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
                if observed_at.tzinfo is not None:
                    observed_at = observed_at.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                observed_at = datetime.now(timezone.utc)

        with self._lock:
            # Prune old keys in history (TTL = 300s)
            expired_keys = [
                k for k, v in self._history.items()
                if (observed_at - v.get("last_seen", observed_at)).total_seconds() > 300
            ]
            for k in expired_keys:
                self._history.pop(k, None)

            if key not in self._history:
                self._history[key] = {
                    "directions": {},
                    "last_seen": observed_at
                }

            self._history[key]["last_seen"] = observed_at
            directions = self._history[key]["directions"]

            if direction not in directions:
                directions[direction] = set()

            directions[direction].update(wg_sizes)

            # Check if we have seen WireGuard size signals in BOTH directions
            if len(directions) < 2:
                # Only one direction so far, not bidirectional yet
                return False

            # Verify we have at least one valid WireGuard size (148, 92, 32)
            all_sizes = set()
            for dir_sizes in directions.values():
                all_sizes.update(dir_sizes)

            has_handshake = any(size in all_sizes for size in (148, 92, 32))
            return has_handshake

    def clear(self) -> None:
        with self._lock:
            self._history.clear()
