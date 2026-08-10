from datetime import datetime
from typing import Any, Optional
from engine import Finding, Severity
from .state import get_flow_field
from app.engines.common.config import EngineConfig

class ExfiltrationDetector:
    def __init__(self, config: EngineConfig = None) -> None:
        self.config = config if config is not None else EngineConfig()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        dst_ip = get_flow_field(flow, "dst_ip")
        bytes_out = get_flow_field(flow, "bytes_out")
        if bytes_out is not None:
            try:
                bytes_out = int(bytes_out)
            except (ValueError, TypeError):
                bytes_out = 0
        else:
            bytes_out = 0

        if not src_ip or not dst_ip:
            return None

        # Large upload threshold (configured threshold)
        if bytes_out > self.config.large_upload_threshold:
            mb_uploaded = round(bytes_out / 1000000.0, 1)
            return Finding(
                engine="threat",
                finding_type="large_upload",
                severity=Severity.HIGH,
                confidence=0.90,
                evidence=[f"Large Upload Detected: {mb_uploaded}MB uploaded from {src_ip} to {dst_ip}"],
                timestamp=observed_at,
                target_ip=src_ip,
                details={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "bytes_out": bytes_out,
                    "mb_uploaded": mb_uploaded
                }
            )
        return None

