import time
import threading
from datetime import datetime, timezone
from typing import List
from shared.engine import BaseEngine, EngineResult, Finding

from .state import SlidingWindowStore
from .port_scan import PortScanDetector
from .brute_force import BruteForceDetector
from .beaconing import BeaconingDetector
from .dns_tunneling import DNSTunnelingDetector
from .exfiltration import ExfiltrationDetector
from app.engines.common.config import EngineConfig

class ThreatEngine(BaseEngine):
    def __init__(self, config: EngineConfig = None) -> None:
        self._executions = 0
        self._findings_generated = 0
        self._total_time_ms = 0.0

        # Load engine configuration instance
        self.config = config if config is not None else EngineConfig()

        # Shared state store
        self.store = SlidingWindowStore()

        # Initialize detectors with the config instance
        self.port_scan_detector = PortScanDetector(self.store, self.config)
        self.brute_force_detector = BruteForceDetector(self.store, self.config)
        self.beaconing_detector = BeaconingDetector(self.store, self.config)
        self.dns_tunneling_detector = DNSTunnelingDetector(self.config)
        self.exfiltration_detector = ExfiltrationDetector(self.config)

        self._lock = threading.RLock()


    @property
    def name(self) -> str:
        return "threat"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_contexts(self) -> list[str]:
        return ["flow"]

    def clear_state(self) -> None:
        """Resets the state of all detectors and the state store."""
        with self._lock:
            self.store.clear()
            self.dns_tunneling_detector.clear()

    def analyze(self, context: dict) -> EngineResult:
        start_time = time.perf_counter()
        with self._lock:
            self._executions += 1

        # Parse observed_at timestamp
        last_seen = context.get("last_seen") if isinstance(context, dict) else getattr(context, "last_seen", None)
        if not last_seen:
            observed_at = datetime.utcnow()
        elif isinstance(last_seen, datetime):
            observed_at = last_seen
        else:
            observed_at = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    observed_at = datetime.strptime(last_seen, fmt)
                    break
                except ValueError:
                    continue
            if observed_at is None:
                try:
                    observed_at = datetime.fromisoformat(last_seen)
                except ValueError:
                    observed_at = datetime.utcnow()

        # Strip tzinfo to ensure timezone-naive datetime comparison
        if observed_at.tzinfo is not None:
            observed_at = observed_at.astimezone(timezone.utc).replace(tzinfo=None)

        findings: List[Finding] = []

        # Run all detectors
        for detector in [
            self.port_scan_detector,
            self.brute_force_detector,
            self.beaconing_detector,
            self.dns_tunneling_detector,
            self.exfiltration_detector
        ]:
            finding = detector.analyze(context, observed_at)
            if finding:
                findings.append(finding)

        res = EngineResult(findings=findings)

        duration = (time.perf_counter() - start_time) * 1000.0
        with self._lock:
            self._total_time_ms += duration
            self._findings_generated += len(res.findings)

        return res

    def metrics(self) -> dict:
        with self._lock:
            avg_time = (self._total_time_ms / self._executions) if self._executions > 0 else 0.0
            return {
                "executions": self._executions,
                "findings_generated": self._findings_generated,
                "avg_execution_ms": round(avg_time, 2)
            }
