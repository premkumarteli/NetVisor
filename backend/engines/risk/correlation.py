from datetime import datetime
from typing import List, Dict, Tuple
from engine import Finding
from .models import CorrelationRule, DEFAULT_RULES

class Correlator:
    def __init__(self, rules: List[CorrelationRule] = None) -> None:
        self.rules = rules if rules is not None else DEFAULT_RULES

    def evaluate_rules(
        self,
        target_ip: str,
        active_findings: List[Tuple[Finding, float]],  # List of (finding, decayed_score)
        observed_at: datetime
    ) -> List[Finding]:
        """
        Evaluate correlation rules on the active findings for a given target IP.
        Returns a list of correlation Findings.
        """
        correlation_findings: List[Finding] = []
        
        # Build mapping of finding_type -> (finding, decayed_score)
        # In case of duplicates, keep the one with the highest decayed score.
        findings_by_type: Dict[str, Tuple[Finding, float]] = {}
        for finding, decayed_score in active_findings:
            f_type = finding.finding_type
            if f_type not in findings_by_type or decayed_score > findings_by_type[f_type][1]:
                findings_by_type[f_type] = (finding, decayed_score)

        for rule in self.rules:
            # Check if all required finding types are present with positive decayed scores
            match = True
            matched_sources: List[Tuple[Finding, float]] = []
            for req_type in rule.required_findings:
                if req_type in findings_by_type and findings_by_type[req_type][1] > 0:
                    matched_sources.append(findings_by_type[req_type])
                else:
                    match = False
                    break

            if match:
                # Build details and evidence chain
                source_finding_types = [f.finding_type for f, _ in matched_sources]
                evidence = [
                    f"Threat Correlation: {rule.description}",
                ]
                source_details = []
                for f, score in matched_sources:
                    f_ev = f.evidence[0] if f.evidence else f"{f.finding_type} detected"
                    evidence.append(
                        f"  - Source Finding ({f.engine}/{f.finding_type}): "
                        f"{f_ev} (Decayed Score: {round(score, 1)})"
                    )
                    source_details.append({
                        "engine": f.engine,
                        "finding_type": f.finding_type,
                        "severity": f.severity.name if hasattr(f.severity, "name") else str(f.severity),
                        "confidence": f.confidence,
                        "original_timestamp": f.timestamp.isoformat(),
                        "decayed_score": score
                    })

                # Compute average confidence from matched sources
                confidence = sum(f.confidence for f, _ in matched_sources) / len(matched_sources)

                finding = Finding(
                    engine="risk",
                    finding_type=rule.resulting_finding_type,
                    severity=rule.severity,
                    confidence=confidence,
                    evidence=evidence,
                    timestamp=observed_at,
                    target_ip=target_ip,
                    mitre_attack_id=rule.mitre_attack_id,
                    details={
                        "rule_name": rule.name,
                        "correlated_findings": source_finding_types,
                        "sources": source_details
                    }
                )
                correlation_findings.append(finding)

        return correlation_findings
