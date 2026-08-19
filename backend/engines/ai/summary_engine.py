from backend.engines.ai.models import AnalysisModel

class AISummaryEngine:
    def generate_summary(self, model: AnalysisModel) -> str:
        if not model.active_attack_types:
            return f"No significant threats detected on host {model.target_ip}. Device is currently evaluated as benign."
        
        threat_labels = []
        for finding_type in model.active_attack_types:
            app_findings = [
                f for f in model.raw_findings
                if f.finding_type == finding_type and f.engine == "application" and f.details and f.details.get("application_name")
            ]
            if app_findings:
                app_name = app_findings[0].details["application_name"]
                if finding_type == "malicious_application_detected":
                    threat_labels.append(f"malicious application ({app_name})")
                elif finding_type == "suspicious_application_detected":
                    threat_labels.append(f"suspicious application ({app_name})")
                else:
                    threat_labels.append(f"application detected ({app_name})")
            else:
                threat_labels.append(finding_type)

        threats_str = ", ".join(threat_labels)
        summary = (
            f"Active threats detected on host {model.target_ip}. "
            f"Cumulative risk score is evaluated as {model.risk_score} ({model.severity}). "
            f"The network analysis engine identified the following indicators: {threats_str}."
        )
        return summary

    def generate_confidence_explanation(self, model: AnalysisModel) -> str:
        if not model.active_attack_types:
            return "The device is currently evaluated as low risk due to a lack of active threat indicators."
            
        max_confidence = 0.0
        if model.raw_findings:
            max_confidence = max(f.confidence for f in model.raw_findings)
            
        explanation = (
            f"The risk evaluation is compiled with a maximum telemetry confidence of {round(max_confidence, 2)}. "
            f"This is based on {len(model.active_attack_types)} active threat and/or behavior signature indicators. "
            f"Individual evidence chains have been analyzed and verified across the NetVisor detection pipeline."
        )
        return explanation
