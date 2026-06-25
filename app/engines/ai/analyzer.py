from typing import Any, Dict, List
from shared.engine import Finding, Severity
from app.engines.ai.models import AnalysisModel
from app.engines.ai.mitre import get_mitre_mapping

class AIAnalyzer:
    def analyze_context(self, context: dict) -> AnalysisModel:
        # Resolve target IP
        target_ip = (
            context.get("src_ip")
            or context.get("internal_device_ip")
            or context.get("target_ip")
            or "0.0.0.0"
        )
        
        findings = context.get("_findings") or []
        
        risk_score = 0
        severity_str = "INFO"
        active_attack_types: List[str] = []
        raw_findings: List[Finding] = []
        mitre_ids: List[str] = []
        
        # Locate risk summary finding first
        risk_summary_finding = None
        for f in findings:
            if f.engine == "risk" and f.finding_type == "risk_summary":
                risk_summary_finding = f
                break
                
        if risk_summary_finding:
            risk_score = risk_summary_finding.details.get("risk_score", 0)
            # severity is a Severity enum or string
            severity_val = risk_summary_finding.severity
            severity_str = severity_val.name if hasattr(severity_val, "name") else str(severity_val)
            
        # Process other findings
        for f in findings:
            if f.engine == "risk" and f.finding_type == "risk_summary":
                continue
            
            raw_findings.append(f)
            f_type = f.finding_type
            if f_type not in active_attack_types:
                active_attack_types.append(f_type)
                
            mitre_map = get_mitre_mapping(f_type)
            mitre_id = mitre_map["id"]
            if mitre_id not in mitre_ids:
                mitre_ids.append(mitre_id)
                
        # If no risk summary was found, we compute a fallback risk score based on findings
        if not risk_summary_finding and raw_findings:
            from app.engines.risk.models import FINDING_TYPE_BASE_SCORES, SEVERITY_BASE_SCORES
            scores = []
            for f in raw_findings:
                score = FINDING_TYPE_BASE_SCORES.get(
                    f.finding_type,
                    SEVERITY_BASE_SCORES.get(f.severity, 0)
                )
                scores.append(score)
            if scores:
                sorted_scores = sorted(scores, reverse=True)
                overall = sorted_scores[0]
                if len(sorted_scores) > 1:
                    overall += sum(s * 0.1 for s in sorted_scores[1:])
                risk_score = min(100, int(round(overall)))
                
            # Compute fallback severity based on score
            if risk_score >= 80:
                severity_str = "CRITICAL"
            elif risk_score >= 60:
                severity_str = "HIGH"
            elif risk_score >= 30:
                severity_str = "MEDIUM"
            elif risk_score > 0:
                severity_str = "LOW"
            else:
                severity_str = "INFO"

        return AnalysisModel(
            target_ip=target_ip,
            risk_score=risk_score,
            severity=severity_str,
            active_attack_types=active_attack_types,
            mitre_ids=mitre_ids,
            raw_findings=raw_findings
        )
