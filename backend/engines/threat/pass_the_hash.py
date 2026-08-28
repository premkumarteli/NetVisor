from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Optional, Set

from engine import Finding, Severity
from .state import get_flow_field
from backend.engines.common.config import EngineConfig


class PassTheHashDetector:
    """
    Detects Pass-the-Hash (PtH) attacks and unauthorized administrative SMB access by monitoring:
    1. Direct SMB administrative share access (C$, ADMIN$, IPC$, SYSVOL).
    2. Rapid NTLM session reuse across multiple distinct destination host IPs from a single source host.
    3. Remote execution pipe calls (svcctl, winreg, wmiexec, psexec).
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config if config is not None else EngineConfig()
        # State: src_ip -> set of destination IPs authenticated over SMB/NTLM
        self._smb_authentications: Dict[str, Set[str]] = defaultdict(set)
        self._last_alert_ts: Dict[str, float] = {}
        self._lock = threading.RLock()

    def clear(self) -> None:
        with self._lock:
            self._smb_authentications.clear()
            self._last_alert_ts.clear()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        dst_ip = get_flow_field(flow, "dst_ip")
        dst_port = int(get_flow_field(flow, "dst_port", 0) or 0)
        app_proto = str(get_flow_field(flow, "application_protocol", "") or "").upper()
        signals = get_flow_field(flow, "analysis_signals") or ()
        
        is_smb = dst_port in (445, 139, 135) or "SMB" in app_proto or "smb" in str(signals).lower()

        if not is_smb or not src_ip or not dst_ip:
            return None

        flow_str = f"{app_proto} {signals}".upper()
        
        # Check for administrative shares or remote service execution pipe signatures
        is_admin_share = any(s in flow_str for s in ("C$", "ADMIN$", "IPC$", "SYSVOL", "PSEXEC", "WMIEXEC", "SVCCTL"))
        is_ntlm = "NTLM" in flow_str or "NTLMSSP" in flow_str or dst_port == 445

        with self._lock:
            ts_sec = observed_at.timestamp() if isinstance(observed_at, datetime) else float(observed_at)
            
            # Record SMB authentication destination IP
            self._smb_authentications[src_ip].add(dst_ip)
            target_count = len(self._smb_authentications[src_ip])

            last_alert = self._last_alert_ts.get(src_ip, 0.0)

            # Rule 1: High severity if admin share access (C$, ADMIN$, IPC$, PSEXEC) detected
            if is_admin_share and (ts_sec - last_alert > 60.0):
                self._last_alert_ts[src_ip] = ts_sec
                return Finding(
                    engine="threat",
                    finding_type="pass_the_hash",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    evidence=[
                        f"Pass-the-Hash / Admin Share Access Detected: Source {src_ip} accessed administrative share or RPC pipe on {dst_ip}:{dst_port}."
                    ],
                    timestamp=observed_at,
                    target_ip=src_ip,
                    details={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "admin_share_detected": True,
                        "target_count": target_count,
                    },
                )

            # Rule 2: Multi-host NTLM authentication reuse (PtH lateral propagation)
            if is_ntlm and target_count >= 3 and (ts_sec - last_alert > 60.0):
                self._last_alert_ts[src_ip] = ts_sec
                return Finding(
                    engine="threat",
                    finding_type="pass_the_hash",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    evidence=[
                        f"Pass-the-Hash Lateral Authentication Reuse: Source {src_ip} established SMB/NTLM sessions with {target_count} distinct internal hosts."
                    ],
                    timestamp=observed_at,
                    target_ip=src_ip,
                    details={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "target_count": target_count,
                        "target_ips": list(self._smb_authentications[src_ip])[:5],
                    },
                )

        return None
