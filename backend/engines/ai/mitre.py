from typing import Dict, List

MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "vpn_detected": {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use a proxy to direct network traffic to obfuscate their source IP address."
    },
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services on systems to identify potential vulnerabilities."
    },
    "brute_force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force logins to attempt access to local or remote systems."
    },
    "beaconing": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using standard application protocols to blend in with normal traffic."
    },
    "dns_tunneling": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may tunnel custom communication over standard DNS queries to bypass network filters."
    },
    "large_upload": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data over alternative protocols to avoid standard network inspection."
    },
    "credential_attack": {
        "id": "T1110",
        "name": "Brute Force / Automated Reconnaissance",
        "tactic": "Credential Access / Discovery",
        "description": "Coordinated network scanning combined with anonymous proxying to locate and brute-force credentials."
    },
    "active_c2": {
        "id": "T1071",
        "name": "Active Command and Control",
        "tactic": "Command and Control",
        "description": "Established beaconing pattern utilizing stealthy DNS tunneling protocol commands."
    },
    "suspicious_exfiltration": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Massive data transfer outbound following or paired with suspicious beaconing behavior."
    },
    "credential_stuffing": {
        "id": "T1110",
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Automated login attacks using credential dumps originating from anonymized network exit points."
    },
    "malicious_application_detected": {
        "id": "T1071",
        "name": "Application Layer Protocol / Command and Control",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to bypass network detection, e.g. C2 frameworks."
    },
    "suspicious_application_detected": {
        "id": "T1090",
        "name": "Proxy / Anonymization",
        "tactic": "Command and Control",
        "description": "Adversaries may use anonymizers or proxies (such as Tor) to direct network traffic and evade detection."
    }
}

def get_mitre_mapping(finding_type: str) -> Dict[str, str]:
    """Retrieve MITRE ATT&CK technique mapping for a given finding type."""
    # Fallback default if unknown
    return MITRE_MAPPINGS.get(finding_type, {
        "id": "UNKNOWN",
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "description": "No ATT&CK mapping available."
    })
