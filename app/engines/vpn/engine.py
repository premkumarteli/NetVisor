import time
import threading
from shared.engine import BaseEngine, EngineResult, Finding, Severity
from .pipeline import VPNPipeline

class VPNEngine(BaseEngine):
    def __init__(self) -> None:
        self._executions = 0
        self._findings_generated = 0
        self._total_time_ms = 0.0
        self._lock = threading.RLock()
        self.pipeline = VPNPipeline()

    @property
    def name(self) -> str:
        return "vpn"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_contexts(self) -> list[str]:
        return ["flow"]

    def clear_state(self) -> None:
        with self._lock:
            self.pipeline.clear()

    def analyze(self, context: dict) -> EngineResult:
        start_time = time.perf_counter()
        with self._lock:
            self._executions += 1

        pipeline_res = self.pipeline.run(context)
        
        findings = []
        if pipeline_res["is_vpn"]:
            conf = pipeline_res["confidence"]
            # Map severity: critical for very high, high, or medium
            if conf >= 0.70:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
                
            dst_ip = context.get("dst_ip") or context.get("ip") or "0.0.0.0"
            evidence_list = pipeline_res["evidence"]
            if not evidence_list:
                evidence_list = ["VPN characteristics detected"]
                
            findings.append(
                Finding(
                    engine="vpn",
                    finding_type="vpn_detected",
                    severity=severity,
                    confidence=conf,
                    evidence=evidence_list,
                    target_ip=dst_ip,
                    details={
                        "provider": pipeline_res["provider"],
                        "vpn_type": pipeline_res["vpn_type"],
                        "score": int(conf * 100),
                        "reasons": evidence_list
                    }
                )
            )

        duration = (time.perf_counter() - start_time) * 1000.0
        with self._lock:
            self._total_time_ms += duration
            self._findings_generated += len(findings)

        # Include metadata similar to legacy wrapper
        metadata = {
            "score": int(pipeline_res["confidence"] * 100),
            "provider": pipeline_res["provider"],
            "vpn_type": pipeline_res["vpn_type"]
        }

        return EngineResult(findings=findings, metadata=metadata)

    def metrics(self) -> dict:
        with self._lock:
            avg_time = (self._total_time_ms / self._executions) if self._executions > 0 else 0.0
            return {
                "executions": self._executions,
                "findings_generated": self._findings_generated,
                "avg_execution_ms": round(avg_time, 2)
            }
