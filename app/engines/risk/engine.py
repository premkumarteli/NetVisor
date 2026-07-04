import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from shared.engine import BaseEngine, EngineResult, Finding, Severity
from app.engines.common.config import EngineConfig
from .decay import calculate_decay
from .suppression import SuppressionStore
from .correlation import Correlator
from .models import FINDING_TYPE_BASE_SCORES, SEVERITY_BASE_SCORES

class RiskEngine(BaseEngine):
    def __init__(self, config: EngineConfig = None, registry: Any = None) -> None:
        self._executions = 0
        self._findings_generated = 0
        self._total_time_ms = 0.0

        # Configuration and registry DI
        self.config = config if config is not None else EngineConfig()
        self.registry = registry

        # Sub-components
        self.correlator = Correlator()
        self.suppression_store = SuppressionStore()

        # Thread-safe findings history: target_ip -> List[Finding]
        self._history = defaultdict(list)
        self._lock = threading.RLock()

    @property
    def name(self) -> str:
        return "risk"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_contexts(self) -> List[str]:
        return ["flow"]

    def clear_state(self) -> None:
        """Reset history, suppression store, and metrics."""
        with self._lock:
            self._history.clear()
            self.suppression_store.clear()

    def analyze(self, context: dict) -> EngineResult:
        start_time = time.perf_counter()
        with self._lock:
            self._executions += 1

        # 1. Resolve target IP
        target_ip = (
            context.get("src_ip")
            or context.get("internal_device_ip")
            or context.get("target_ip")
        )
        if not target_ip:
            # If no target IP can be resolved, return empty result
            return EngineResult()

        # 2. Parse observed_at timestamp
        last_seen = context.get("last_seen")
        if not last_seen:
            observed_at = datetime.utcnow()
        elif isinstance(last_seen, datetime):
            observed_at = last_seen
        else:
            observed_at = None
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f"
            ):
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

        # Ensure observed_at is timezone-naive UTC
        if observed_at.tzinfo is not None:
            observed_at = observed_at.astimezone(timezone.utc).replace(tzinfo=None)

        with self._lock:
            # 3. Retrieve incoming findings
            incoming_findings = context.get("_findings")
            if incoming_findings is None and self.registry is not None:
                # Standalone/Selective execution: query registry for other engines
                # Exclude both risk (to avoid loops) and ai (since AI must run after risk)
                other_engines = [
                    name for name in self.registry.list_engines()
                    if name not in ("risk", "ai")
                ]
                other_result = self.registry.analyze_selective(context, other_engines)
                incoming_findings = other_result.findings

            if incoming_findings:
                # Add incoming findings to target IP history (with deduplication/renewal)
                for finding in incoming_findings:
                    # Filter out any risk-summary findings from history to avoid loops
                    if finding.engine == "risk" and finding.finding_type == "risk_summary":
                        continue
                    
                    # Deduplicate: if an active finding from the same engine/type already exists, remove it
                    # (it will be replaced/renewed by the new finding with the latest timestamp)
                    existing_finding = None
                    for hist_finding in self._history[target_ip]:
                        if (hist_finding.engine == finding.engine and
                            hist_finding.finding_type == finding.finding_type):
                            existing_finding = hist_finding
                            break
                    
                    if existing_finding is not None:
                        self._history[target_ip].remove(existing_finding)

                    self._history[target_ip].append(finding)


            # 4. Prune expired findings and calculate decay for active findings
            active_findings: List[Tuple[Finding, float]] = []
            remaining_findings: List[Finding] = []

            for finding in self._history[target_ip]:
                # Calculate age of finding relative to observed_at
                finding_ts = finding.timestamp
                if finding_ts.tzinfo is not None:
                    finding_ts = finding_ts.astimezone(timezone.utc).replace(tzinfo=None)
                age_seconds = (observed_at - finding_ts).total_seconds()
                if age_seconds < 0:
                    age_seconds = 0.0


                if age_seconds < finding.ttl:
                    # Finding is still active
                    remaining_findings.append(finding)

                    # Calculate decayed score
                    base_score = FINDING_TYPE_BASE_SCORES.get(
                        finding.finding_type,
                        SEVERITY_BASE_SCORES.get(finding.severity, 0.0)
                    )
                    decayed_score = calculate_decay(
                        score=base_score,
                        age_seconds=age_seconds,
                        ttl=finding.ttl,
                        half_life=self.config.risk_decay_half_life
                    )
                    active_findings.append((finding, decayed_score))

            # Update history with only non-expired findings (pop key if empty to avoid leaks)
            if remaining_findings:
                self._history[target_ip] = remaining_findings
            else:
                self._history.pop(target_ip, None)

            # 5. Evaluate Correlation Rules
            correlation_findings = self.correlator.evaluate_rules(
                target_ip=target_ip,
                active_findings=active_findings,
                observed_at=observed_at
            )

            # 6. Apply suppression to correlation findings
            emitted_correlation_findings: List[Finding] = []
            for f in correlation_findings:
                rule_name = f.details.get("rule_name", f.finding_type)
                if self.suppression_store.should_suppress(
                    target_ip=target_ip,
                    identifier=rule_name,
                    observed_at=observed_at,
                    suppression_window=self.config.risk_suppression_window
                ):
                    continue
                
                # Record emission and emit finding
                self.suppression_store.record_emission(target_ip, rule_name, observed_at)
                emitted_correlation_findings.append(f)
                
            if emitted_correlation_findings:
                try:
                    from app.middleware.prometheus_middleware import INCIDENTS_CREATED
                    INCIDENTS_CREATED.inc(len(emitted_correlation_findings))
                except ImportError:
                    pass

            # 7. Aggregate overall risk score
            # Gather all decayed scores from active findings
            scores = [score for _, score in active_findings]
            
            # Plus the base score of any triggered correlation findings (even if suppressed from emission)
            for f in correlation_findings:
                scores.append(FINDING_TYPE_BASE_SCORES.get(f.finding_type, 80.0))


            overall_score = 0
            if scores:
                # Aggregate using: max_score + sum(other_scores * 0.1) capped at 100
                sorted_scores = sorted(scores, reverse=True)
                max_score = sorted_scores[0]
                overall_score = max_score
                if len(sorted_scores) > 1:
                    overall_score += sum(s * 0.1 for s in sorted_scores[1:])
                overall_score = min(100, int(round(overall_score)))

            # Resolve severity level
            if overall_score >= 80:
                overall_severity = Severity.CRITICAL
            elif overall_score >= 60:
                overall_severity = Severity.HIGH
            elif overall_score >= 30:
                overall_severity = Severity.MEDIUM
            elif overall_score > 0:
                overall_severity = Severity.LOW
            else:
                overall_severity = Severity.INFO

            # 8. Construct risk summary finding
            evidence = [
                f"Overall device risk score is evaluated as {overall_score} ({overall_severity.name})."
            ]
            
            # Add breakdown evidence of active findings
            if active_findings:
                evidence.append("Active contributing findings:")
                for f, score in active_findings:
                    f_ev = f.evidence[0] if f.evidence else f"{f.finding_type} detected"
                    evidence.append(f"  - [{f.engine}/{f.finding_type}] {f_ev} (Decayed score: {round(score, 1)})")
            
            if emitted_correlation_findings:
                evidence.append("Newly triggered correlation findings:")
                for f in emitted_correlation_findings:
                    evidence.append(f"  - [correlation/{f.finding_type}] {f.evidence[0]}")

            risk_summary = Finding(
                engine="risk",
                finding_type="risk_summary",
                severity=overall_severity,
                confidence=1.0,
                evidence=evidence,
                timestamp=observed_at,
                target_ip=target_ip,
                details={
                    "risk_score": overall_score,
                    "active_findings_count": len(active_findings),
                    "emitted_correlations_count": len(emitted_correlation_findings),
                    "decayed_scores_breakdown": [
                        {"engine": f.engine, "finding_type": f.finding_type, "decayed_score": round(score, 2)}
                        for f, score in active_findings
                    ]
                }
            )

            # Combine risk summary and unsuppressed correlation findings
            all_findings = [risk_summary] + emitted_correlation_findings

            duration = (time.perf_counter() - start_time) * 1000.0
            self._total_time_ms += duration
            self._findings_generated += len(all_findings)

            return EngineResult(findings=all_findings)

    def metrics(self) -> dict:
        avg_time = (self._total_time_ms / self._executions) if self._executions > 0 else 0.0
        return {
            "executions": self._executions,
            "findings_generated": self._findings_generated,
            "avg_execution_ms": round(avg_time, 2)
        }
