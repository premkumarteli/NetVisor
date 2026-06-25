from typing import Dict, List

PLAYBOOKS: Dict[str, List[str]] = {
    "credential_attack": [
        "Priority 1: Enforce immediate MFA validation or temporarily disable active user accounts associated with this host's login attempts.",
        "Priority 2: Terminate active VPN/external remote service connections associated with the destination IP.",
        "Priority 3: Audit authentication logs on target systems for successful logins from the compromised IP."
    ],
    "active_c2": [
        "Priority 1: Isolate the source host immediately from the network to prevent further outbound command and control communication.",
        "Priority 2: Block egress DNS queries to the targeted external domain and terminate ongoing tunneling connections.",
        "Priority 3: Run a full malware scan and perform memory/endpoint forensics on the source device."
    ],
    "suspicious_exfiltration": [
        "Priority 1: Terminate the large upload/data transfer connection immediately to stop potential data loss.",
        "Priority 2: Revoke active session tokens and security credentials for the source host.",
        "Priority 3: Restrict egress data rates and inspect the destination external IP/domain for known storage providers."
    ],
    "credential_stuffing": [
        "Priority 1: Rate limit or block the source IP address at the firewall/gateway to halt automated credential stuffing.",
        "Priority 2: Enforce password resets for accounts targeted by brute-force attempts from this source.",
        "Priority 3: Inspect authentication gateway access logs to identify compromised accounts."
    ],
    "vpn_detected": [
        "Priority 1: Monitor host traffic closely as it originates from an anonymizing proxy/VPN.",
        "Priority 2: Verify the legitimacy of the VPN connection (e.g. check corporate VPN policies/authorized users).",
        "Priority 3: Log host session characteristics for telemetry."
    ],
    "port_scan": [
        "Priority 1: Block scanning traffic from this host at internal switch/router level if unauthorized.",
        "Priority 2: Audit local open ports and firewalls on target devices.",
        "Priority 3: Confirm if the port scan is part of a scheduled vulnerability scan."
    ],
    "brute_force": [
        "Priority 1: Lock user accounts experiencing login failures from this source.",
        "Priority 2: Enforce strong passwords and lockout policies.",
        "Priority 3: Review SSH/auth logs on target hosts."
    ],
    "beaconing": [
        "Priority 1: Monitor outbound connections to the target external IP/port for persistence.",
        "Priority 2: Correlate beaconing intervals with known application update/synchronization tasks.",
        "Priority 3: Inspect local startup scripts and scheduled tasks on the source host."
    ],
    "dns_tunneling": [
        "Priority 1: Terminate outbound queries to the affected parent DNS domain.",
        "Priority 2: Implement DNS inspection or query rate limiting on local resolvers.",
        "Priority 3: Perform an endpoint scan for remote access tools or covert tunnels."
    ],
    "large_upload": [
        "Priority 1: Identify and review the nature of the large outbound data volume.",
        "Priority 2: Correlate the transfer with authorized data backup or file-sharing processes.",
        "Priority 3: Analyze the destination IP ownership and reputation."
    ],
    "default": [
        "Priority 1: Inspect the host network telemetry for unusual port connections or protocols.",
        "Priority 2: Isolate the host if the activity does not match authorized business baselines.",
        "Priority 3: Review system security event logs on the target endpoint."
    ]
}

def get_playbook(finding_type: str) -> List[str]:
    """Retrieve prioritized response playbook actions for a given finding type."""
    return PLAYBOOKS.get(finding_type, PLAYBOOKS["default"])
