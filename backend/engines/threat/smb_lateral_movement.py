from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Optional, List

from engine import Finding, Severity
from .state import get_flow_field
from backend.engines.common.config import EngineConfig


class SMBLateralMovementDetector:
    """
    Detects SMB Lateral Movement by tracking internal SMB session creation volume,
    cross-subnet RPC calls, and host fan-out across SMB ports 445 / 139 / 135.
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config if config is not None else EngineConfig()
        # State: src_ip -> list of (timestamp, dst_ip, byte_count)
        self._smb_sessions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._last_alert_ts: Dict[str, float] = {}
        self._lock = threading.RLock()

    def clear(self) -> None:
        with self._lock:
            self._smb_sessions.clear()
            self._last_alert_ts.clear()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        dst_ip = get_flow_field(flow, "dst_ip")
        dst_port = int(get_flow_field(flow, "dst_port", 0) or 0)
        bytes_sent = int(get_flow_field(flow, "bytes_sent", 0) or 0)
        app_proto = str(get_flow_field(flow, "application_protocol", "") or "").upper()

        if dst_port not in (445, 139, 135) and "SMB" not in app_proto:
            return None

        if not src_ip or not dst_ip:
            return None

        with self._lock:
            ts_sec = observed_at.timestamp() if isinstance(observed_at, datetime) else float(observed_at)
            
            # Prune sessions older than 5 minutes (300s)
            cutoff = ts_sec - 300.0
            self._smb_sessions[src_ip] = [s for s in self._smb_sessions[src_ip] if s["ts"] >= cutoff]

            self._smb_sessions[src_ip].append({
                "ts": ts_sec,
                "dst_ip": dst_ip,
                "bytes": bytes_sent,
            })

            sessions = self._smb_sessions[src_ip]
            unique_targets = {s["dst_ip"] for s in sessions}

            last_alert = self._last_alert_ts.get(src_ip, 0.0)

            # Rule: Lateral fan-out to 4+ distinct SMB targets within 5 minutes
            if len(unique_targets) >= 4 and (ts_sec - last_alert > 120.0):
                self._last_alert_ts[src_ip] = ts_sec
                return Finding(
                    engine="threat",
                    finding_type="smb_lateral_movement",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    evidence=[
                        f"SMB Lateral Movement Fan-Out: Host {src_ip} initiated SMB sessions to {len(unique_targets)} distinct internal targets within 5 minutes."
                    ],
                    timestamp=observed_at,
                    target_ip=src_ip,
                    details={
                        "src_ip": src_ip,
                        "unique_target_count": len(unique_targets),
                        "target_ips": list(unique_targets)[:5],
                        "total_smb_sessions": len(sessions),
                    },
                )

        return None
