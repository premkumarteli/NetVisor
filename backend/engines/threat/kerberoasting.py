from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from engine import Finding, Severity
from .state import get_flow_field
from backend.engines.common.config import EngineConfig


class KerberoastingDetector:
    """
    Detects Kerberoasting activity by tracking:
    1. TGS-REQ requests specifying RC4-HMAC (etype 23 / 0x17) encryption.
    2. High volume of TGS-REQ ticket requests targeting multiple Service Principal Names (SPNs) from a single host.
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config if config is not None else EngineConfig()
        # State: src_ip -> list of (timestamp, spn, etype)
        self._tgs_requests: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._lock = threading.RLock()

    def clear(self) -> None:
        with self._lock:
            self._tgs_requests.clear()

    def analyze(self, flow: Any, observed_at: datetime) -> Optional[Finding]:
        src_ip = get_flow_field(flow, "src_ip")
        dst_port = int(get_flow_field(flow, "dst_port", 0) or 0)
        app_proto = str(get_flow_field(flow, "application_protocol", "") or "").upper()
        svc_name = str(get_flow_field(flow, "service_name", "") or "").upper()
        signals = get_flow_field(flow, "analysis_signals") or ()

        is_kerberos = dst_port == 88 or "KERBEROS" in app_proto or "KRB" in svc_name or "kerberos" in signals

        if not is_kerberos or not src_ip:
            return None

        # Extract SPN or etype signals if present
        domain = str(get_flow_field(flow, "domain", "") or "").lower()
        sni = str(get_flow_field(flow, "sni", "") or "").lower()
        spn = domain or sni or "krbtgt"
        
        # Check for RC4-HMAC weak encryption type indicator (etype 23 / 0x17)
        is_weak_etype = "rc4" in str(signals).lower() or "etype_23" in str(signals).lower() or "0x17" in str(signals).lower()

        with self._lock:
            ts_sec = observed_at.timestamp() if isinstance(observed_at, datetime) else float(observed_at)
            
            # Prune entries older than 10 minutes (600s)
            cutoff = ts_sec - 600.0
            self._tgs_requests[src_ip] = [r for r in self._tgs_requests[src_ip] if r["ts"] >= cutoff]

            self._tgs_requests[src_ip].append({
                "ts": ts_sec,
                "spn": spn,
                "weak_etype": is_weak_etype,
            })

            requests = self._tgs_requests[src_ip]
            unique_spns = {r["spn"] for r in requests if r["spn"] != "krbtgt"}
            weak_count = sum(1 for r in requests if r["weak_etype"])

            # Rule 1: High frequency TGS-REQ burst targeting 3+ distinct SPNs
            if len(unique_spns) >= 3 or weak_count >= 2 or (len(requests) >= 5 and is_weak_etype):
                return Finding(
                    engine="threat",
                    finding_type="kerberoasting",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    evidence=[
                        f"Kerberoasting Activity Detected from {src_ip}: {len(requests)} TGS requests targeting {len(unique_spns)} SPNs in 10m window.",
                    ],
                    timestamp=observed_at,
                    target_ip=src_ip,
                    details={
                        "src_ip": src_ip,
                        "tgs_request_count": len(requests),
                        "unique_spn_count": len(unique_spns),
                        "weak_etype_count": weak_count,
                        "spn_list": list(unique_spns)[:5],
                    },
                )

        return None
