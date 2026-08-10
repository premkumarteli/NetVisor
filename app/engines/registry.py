from typing import Dict, List, Optional
from engine import BaseEngine, EngineResult, Finding
from app.engines.common.config import EngineConfig
from app.engines.device.engine import DeviceEngine
from app.engines.threat.engine import ThreatEngine
from app.engines.application.engine import ApplicationEngine
from app.engines.vpn.engine import VPNEngine
from app.engines.risk.engine import RiskEngine
from app.engines.ai.engine import AIEngine

class EngineRegistry:
    def __init__(self, config: EngineConfig = None) -> None:
        self.config = config if config is not None else EngineConfig()
        self._engines: Dict[str, BaseEngine] = {}

        # Register default engines dynamically
        self.register(DeviceEngine(self.config))
        self.register(ThreatEngine(self.config))
        self.register(ApplicationEngine())
        self.register(VPNEngine())
        self.register(RiskEngine(self.config, registry=self))
        self.register(AIEngine(self.config))


    def register(self, engine: BaseEngine) -> None:
        """Register an engine instance. Throws ValueError if name is a duplicate."""
        if not engine:
            raise ValueError("Engine instance cannot be None.")
        name = engine.name
        if name in self._engines:
            raise ValueError(f"Engine with name '{name}' is already registered.")
        self._engines[name] = engine

    def get(self, name: str) -> BaseEngine:
        """Retrieve a registered engine by name."""
        if name not in self._engines:
            raise KeyError(f"Engine '{name}' is not registered.")
        return self._engines[name]

    def list_engines(self) -> List[str]:
        """List the names of all registered engines."""
        return list(self._engines.keys())

    def clear(self) -> None:
        """Clear all registered engines."""
        self._engines.clear()

    def analyze_selective(self, context: dict, engine_names: Optional[List[str]] = None) -> EngineResult:
        """Run only the specified engines (or all if None) and combine results."""
        if engine_names is None:
            selected_names = list(self._engines.keys())
        else:
            selected_names = list(engine_names)

        # Validate that all requested engines are actually registered
        for name in selected_names:
            if name not in self._engines:
                raise ValueError(f"Unknown engine: '{name}'. Cannot execute selective analysis.")

        # Enforce execution ordering: other engines -> 'risk' -> 'ai'
        has_risk = "risk" in selected_names
        has_ai = "ai" in selected_names
        selected_names = [name for name in selected_names if name not in ("risk", "ai")]
        if has_risk:
            selected_names.append("risk")
        if has_ai:
            selected_names.append("ai")

        all_findings: List[Finding] = []
        engine_results_meta = {}

        for name in selected_names:
            engine = self._engines[name]
            
            # Prepare context. If running 'risk' or 'ai', inject findings from prior engines
            curr_context = context
            if name in ("risk", "ai"):
                curr_context = dict(context)
                curr_context["_findings"] = all_findings
                curr_context["_engine_results"] = engine_results_meta

            import time
            start_engine_time = time.perf_counter()
            result = engine.analyze(curr_context)
            engine_duration = time.perf_counter() - start_engine_time
            
            try:
                from app.middleware.prometheus_middleware import ENGINE_RUNTIME, DETECTIONS_PER_ENGINE
                ENGINE_RUNTIME.labels(engine=name).observe(engine_duration)
                if result.findings:
                    DETECTIONS_PER_ENGINE.labels(engine=name).inc(len(result.findings))
            except ImportError:
                pass

            # Accumulate findings
            all_findings.extend(result.findings)

            # Preserve individual engine result metadata and findings
            engine_results_meta[name] = {
                "findings": [self._serialize_finding(f) for f in result.findings],
                "metadata": result.metadata
            }

        return EngineResult(
            findings=all_findings,
            metadata={
                "executed_engines": selected_names,
                "engine_results": engine_results_meta
            }
        )


    def metrics(self) -> Dict[str, dict]:
        """Return aggregated runtime metrics across all registered engines."""
        return {name: engine.metrics() for name, engine in self._engines.items()}

    def analyze(self, sanitized_flow, timestamp) -> dict:
        """Backward compatibility helper for single-flow threat & risk analysis."""
        # Convert flow object to dict context
        context = {
            "src_ip": getattr(sanitized_flow, "src_ip", None),
            "dst_ip": getattr(sanitized_flow, "dst_ip", None),
            "src_port": getattr(sanitized_flow, "src_port", None),
            "dst_port": getattr(sanitized_flow, "dst_port", None),
            "protocol": getattr(sanitized_flow, "protocol", None),
            "domain": getattr(sanitized_flow, "domain", None),
            "sni": getattr(sanitized_flow, "sni", None),
            "src_mac": getattr(sanitized_flow, "src_mac", None),
            "dst_mac": getattr(sanitized_flow, "dst_mac", None),
            "packet_count": getattr(sanitized_flow, "packet_count", 0),
            "byte_count": getattr(sanitized_flow, "byte_count", 0),
            "duration": getattr(sanitized_flow, "duration", 0.0),
            "last_seen": timestamp,
            "internal_device_ip": getattr(sanitized_flow, "internal_device_ip", None),
            "external_ip": getattr(sanitized_flow, "external_ip", None),
        }
        
        # Run all registered engines
        result = self.analyze_selective(context)
        
        # Extract risk_summary details to build the legacy report
        score = 0
        severity = "INFO"
        reasons = []
        
        for finding in result.findings:
            if finding.engine == "risk" and finding.finding_type == "risk_summary":
                score = finding.details.get("risk_score", 0)
                severity = finding.severity.name if hasattr(finding.severity, "name") else str(finding.severity)
                # Parse reasons from evidence list
                reasons = [finding.evidence[0]] if finding.evidence else ["Risk evaluated"]
                break
                
        return {
            "score": score,
            "severity": severity,
            "reasons": reasons,
            "breakdown": {
                "findings": [self._serialize_finding(f) for f in result.findings if f.finding_type != "risk_summary"]
            }
        }

    def _serialize_finding(self, finding: Finding) -> dict:
        """Convert a Finding contract into a standard dictionary representation."""
        severity_name = finding.severity.name if hasattr(finding.severity, "name") else str(finding.severity)
        timestamp_str = finding.timestamp.isoformat() if hasattr(finding.timestamp, "isoformat") else str(finding.timestamp)
        return {
            "engine": finding.engine,
            "finding_type": finding.finding_type,
            "severity": severity_name,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "timestamp": timestamp_str,
            "ttl": finding.ttl,
            "target_ip": finding.target_ip,
            "target_mac": finding.target_mac,
            "mitre_attack_id": finding.mitre_attack_id,
            "details": finding.details
        }
