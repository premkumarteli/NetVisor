import time
import threading
from datetime import datetime, timezone
from typing import Dict, List
from engine import BaseEngine, EngineResult, Finding, Severity
from backend.engines.common.config import EngineConfig
from backend.engines.ai.analyzer import AIAnalyzer
from backend.engines.ai.summary_engine import AISummaryEngine
from backend.engines.ai.recommendation_engine import AIRecommendationEngine

class AIEngine(BaseEngine):
    def __init__(self, config: EngineConfig = None, mode: str = "template") -> None:
        self.config = config if config is not None else EngineConfig()
        self.mode = mode
        
        self.analyzer = AIAnalyzer()
        self.summary_engine = AISummaryEngine()
        self.recommendation_engine = AIRecommendationEngine()
        
        # Metrics tracking
        self._executions = 0
        self._findings_generated = 0
        self._total_time_ms = 0.0
        self._lock = threading.RLock()

    @property
    def name(self) -> str:
        return "ai"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_contexts(self) -> List[str]:
        return ["analysis"]

    def clear_state(self) -> None:
        """Reset internal engine states if any."""
        pass

    def analyze(self, context: dict) -> EngineResult:
        start_time = time.perf_counter()
        with self._lock:
            self._executions += 1
        
        # 1. Structure the findings into an AnalysisModel
        model = self.analyzer.analyze_context(context)
        
        # 2. Generate summary, recommendations, MITRE, and confidence explanation
        summary = self.summary_engine.generate_summary(model)
        confidence_explanation = self.summary_engine.generate_confidence_explanation(model)
        recommendations = self.recommendation_engine.generate_recommendations(model)
        mitre_details = self.recommendation_engine.generate_mitre_details(model)
        
        # Map severity string back to Severity enum
        severity_map = {
            "INFO": Severity.INFO,
            "LOW": Severity.LOW,
            "MEDIUM": Severity.MEDIUM,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL
        }
        severity_enum = severity_map.get(model.severity, Severity.INFO)
        
        # Construct evidence list (high-level bullet points for dashboards)
        evidence = [
            f"AI Security Summary: {summary}",
            f"Confidence Detail: {confidence_explanation}"
        ]
        if recommendations:
            evidence.append("Top Priority Remediation Actions:")
            for rec in recommendations[:3]:  # Top 3 actions
                evidence.append(f"  - Priority {rec['priority']}: {rec['action']} (Source: {rec['source']})")
                
        # Resolve target IP
        target_ip = model.target_ip
        
        # Parse observed_at timestamp from context or default to utcnow
        last_seen = context.get("last_seen")
        if isinstance(last_seen, datetime):
            observed_at = last_seen
        else:
            observed_at = datetime.now(timezone.utc)
            
        # 3. Create the structured Finding
        ai_finding = Finding(
            engine="ai",
            finding_type="ai_analysis",
            severity=severity_enum,
            confidence=1.0,
            evidence=evidence,
            timestamp=observed_at,
            target_ip=target_ip,
            details={
                "summary": summary,
                "recommendations": recommendations,
                "mitre": mitre_details,
                "risk_score": model.risk_score,
                "severity": model.severity,
                "confidence_explanation": confidence_explanation,
                "mode": self.mode
            }
        )
        
        duration = (time.perf_counter() - start_time) * 1000.0
        with self._lock:
            self._total_time_ms += duration
            self._findings_generated += 1
        
        return EngineResult(findings=[ai_finding])

    def metrics(self) -> dict:
        with self._lock:
            avg_time = (self._total_time_ms / self._executions) if self._executions > 0 else 0.0
            return {
                "executions": self._executions,
                "findings_generated": self._findings_generated,
                "avg_execution_ms": round(avg_time, 2)
            }
