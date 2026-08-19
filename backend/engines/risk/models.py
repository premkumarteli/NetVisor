from dataclasses import dataclass
from typing import List
from engine import Severity

@dataclass(frozen=True)
class CorrelationRule:
    name: str
    required_findings: List[str]  # list of finding_type strings
    resulting_finding_type: str
    severity: Severity
    mitre_attack_id: str
    description: str

# Default correlation rules as specified by requirements
DEFAULT_RULES = [
    CorrelationRule(
        name="credential_attack",
        required_findings=["vpn_detected", "port_scan"],
        resulting_finding_type="credential_attack",
        severity=Severity.HIGH,
        mitre_attack_id="T1110",
        description="Credential Attack / Automated Reconnaissance: VPN usage correlated with port scanning activity."
    ),
    CorrelationRule(
        name="active_c2",
        required_findings=["beaconing", "dns_tunneling"],
        resulting_finding_type="active_c2",
        severity=Severity.CRITICAL,
        mitre_attack_id="T1071",
        description="Active Command & Control: periodic beaconing coupled with DNS tunneling."
    ),
    CorrelationRule(
        name="suspicious_exfiltration",
        required_findings=["large_upload", "beaconing"],
        resulting_finding_type="suspicious_exfiltration",
        severity=Severity.HIGH,
        mitre_attack_id="T1048",
        description="Suspicious Exfiltration Activity: large upload correlated with beaconing behavior."
    ),
    CorrelationRule(
        name="credential_stuffing",
        required_findings=["brute_force", "vpn_detected"],
        resulting_finding_type="credential_stuffing",
        severity=Severity.CRITICAL,
        mitre_attack_id="T1110",
        description="Credential Stuffing / Attack: brute force attempts originating from a VPN."
    )
]

# Base scores mapping for finding types
FINDING_TYPE_BASE_SCORES = {
    "vpn_detected": 35,
    "port_scan": 70,
    "beaconing": 70,
    "dns_tunneling": 80,
    "brute_force": 85,
    "large_upload": 65,
    "malicious_application_detected": 85,
    "suspicious_application_detected": 55,
    # Correlation findings
    "credential_attack": 80,
    "active_c2": 95,
    "suspicious_exfiltration": 90,
    "credential_stuffing": 95,
}

# Fallback base scores based on finding severity
SEVERITY_BASE_SCORES = {
    Severity.INFO: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90
}
