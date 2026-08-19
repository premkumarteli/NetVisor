from datetime import datetime
from typing import Any, Optional
from engine import Finding, Severity
from .state import SlidingWindowStore, get_flow_field
from backend.engines.common.config import EngineConfig

class BruteForceDetector:
    def __init__(self, store: SlidingWindowStore, config: EngineConfig = None) -> None:
        self.store = store
        self.config = config if config is not None else EngineConfig()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        dst_ip = get_flow_field(flow, "dst_ip")
        dst_port = get_flow_field(flow, "dst_port")
        if dst_port is not None:
            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                dst_port = None
        if not src_ip or not dst_ip or not dst_port:
            return None

        try:
            byte_count = float(get_flow_field(flow, "byte_count", 0) or 0)
        except (ValueError, TypeError):
            byte_count = 0.0
            
        try:
            duration = float(get_flow_field(flow, "duration", 0) or 0)
        except (ValueError, TypeError):
            duration = 0.0

        # Check if flow matches brute force signature
        if duration < self.config.brute_force_duration_threshold and byte_count < self.config.brute_force_bytes_threshold and dst_port in self.config.brute_force_ports:
            # Unique key for same source, same destination, and same service (port)
            key = (src_ip, dst_ip, dst_port, "brute_force")
            self.store.add(key, observed_at)

            # Prune and check window (sliding window)
            bucket = self.store.get_and_prune(key, observed_at, self.config.brute_force_window)

            if len(bucket) >= self.config.brute_force_attempts_threshold:
                return Finding(
                    engine="threat",
                    finding_type="brute_force",
                    severity=Severity.CRITICAL,
                    confidence=0.90,
                    evidence=[f"Potential Brute Force Attack: {len(bucket)} failed logins on port {dst_port} from {src_ip} to {dst_ip} in {self.config.brute_force_window}s"],
                    timestamp=observed_at,
                    target_ip=src_ip,
                    details={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "failed_attempts": len(bucket)
                    }
                )
        return None

