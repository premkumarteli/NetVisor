import time
import threading
from engine import BaseEngine, EngineResult, Finding, Severity

from .pipeline import DevicePipeline

from backend.engines.common.config import EngineConfig

class DeviceEngine(BaseEngine):
    def __init__(self, config: EngineConfig = None) -> None:
        self._executions = 0
        self._findings_generated = 0
        self._total_time_ms = 0.0
        self.config = config if config is not None else EngineConfig()
        self.pipeline = DevicePipeline(self.config)
        self._lock = threading.RLock()

    @property
    def name(self) -> str:
        return "device"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_contexts(self) -> list[str]:
        return ["device"]

    def analyze(self, context: dict) -> EngineResult:
        start_time = time.perf_counter()
        with self._lock:
            self._executions += 1

        # Run the new modular pipeline (Phase 4C.2)
        profile = self.pipeline.run(context)

        # Build standard Finding with human-readable evidence strings
        evidence_strings = []
        for ev in profile.evidence_sources:
            if ev.source == "oui":
                evidence_strings.append(f"Vendor OUI match: {ev.value}")
            elif ev.source == "hostname":
                evidence_strings.append(f"Hostname resolved: {ev.value}")
            elif ev.source == "dhcp":
                evidence_strings.append(f"DHCP fingerprint matched OS Family: {ev.value}")
            elif ev.source == "mdns":
                evidence_strings.append(f"mDNS services: {ev.value}")
            elif ev.source == "ssdp":
                evidence_strings.append(f"SSDP friendly name: {ev.value}")
            elif ev.source == "active_probe":
                evidence_strings.append(f"Active probe matched type: {ev.value}")

        findings = [
            Finding(
                engine="device",
                finding_type="device_profiled",
                severity=Severity.INFO,
                confidence=profile.confidence,
                evidence=evidence_strings,
                target_ip=profile.ip,
                target_mac=profile.mac,
                details={
                    "hostname": profile.hostname,
                    "vendor": profile.vendor,
                    "device_type": profile.device_type,
                    "confidence_level": profile.confidence_level,
                    "evidence_sources": [
                        {
                            "source": ev.source,
                            "value": ev.value,
                            "weight": ev.weight
                        }
                        for ev in profile.evidence_sources
                    ]
                }
            )
        ]

        res = EngineResult(
            findings=findings,
            metadata={
                "device_type": profile.device_type,
                "confidence": profile.confidence_level
            }
        )

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
