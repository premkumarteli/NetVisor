from datetime import datetime
from typing import Any, Optional
from engine import Finding, Severity
from .state import SlidingWindowStore, get_flow_field
from app.engines.common.config import EngineConfig

class PortScanDetector:
    def __init__(self, store: SlidingWindowStore, config: EngineConfig = None) -> None:
        self.store = store
        self.config = config if config is not None else EngineConfig()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        if not src_ip:
            return None

        dst_port = get_flow_field(flow, "dst_port", 0)

        # Record connection attempt to sliding window
        self.store.add((src_ip, "port_scan"), observed_at, dst_port)

        # Retrieve and prune sliding window (configured threshold)
        bucket = self.store.get_and_prune((src_ip, "port_scan"), observed_at, self.config.port_scan_window)
        unique_ports = {port for _, port in bucket}

        if len(unique_ports) >= self.config.port_scan_threshold:
            return Finding(
                engine="threat",
                finding_type="port_scan",
                severity=Severity.HIGH,
                confidence=0.90,
                evidence=[f"Port Scanning Detected: {len(unique_ports)} unique ports scanned from {src_ip} in {self.config.port_scan_window}s"],
                timestamp=observed_at,
                target_ip=src_ip,
                details={"src_ip": src_ip, "unique_ports_scanned": len(unique_ports)}
            )
        return None

