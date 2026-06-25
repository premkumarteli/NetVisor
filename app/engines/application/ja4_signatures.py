from typing import Dict, Any, Optional

# JA4/TLS Fingerprint mapping to application name, malicious/suspicious flag, and MITRE IDs.
# Key is the fingerprint or fingerprint prefix (lowercase, whitespace stripped).
# Value is a dictionary containing:
# - "application_name": str
# - "is_malicious": bool
# - "is_suspicious": bool
# - "mitre_id": Optional[str]
JA4_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "t13d1715h2": {
        "application_name": "Python Requests",
        "is_malicious": False,
        "is_suspicious": False,
        "mitre_id": None
    },
    "t13d1516h2": {
        "application_name": "Curl",
        "is_malicious": False,
        "is_suspicious": False,
        "mitre_id": None
    },
    "t12d1516": {
        "application_name": "Go HTTP Client",
        "is_malicious": False,
        "is_suspicious": False,
        "mitre_id": None
    },
    "t13d1516h2_8a21_a230": {
        "application_name": "Slack Client",
        "is_malicious": False,
        "is_suspicious": False,
        "mitre_id": None
    },
    "t13d1516h2_8008_d103": {
        "application_name": "Spotify Client",
        "is_malicious": False,
        "is_suspicious": False,
        "mitre_id": None
    },
    "t13d1516h2_9a12_108a": {
        "application_name": "Tor Browser",
        "is_malicious": False,
        "is_suspicious": True,
        "mitre_id": "T1090"
    },
    "t12d1415h2_5b23_70c2": {
        "application_name": "Cobalt Strike C2",
        "is_malicious": True,
        "is_suspicious": False,
        "mitre_id": "T1071"
    },
    "t12d1215h2_9b21_0b20": {
        "application_name": "Log4j Exploit Payload",
        "is_malicious": True,
        "is_suspicious": False,
        "mitre_id": "T1190"
    }
}

def lookup_ja4_signature(fingerprint: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Lookup a JA4/TLS client fingerprint in the signature database.
    Matches exact fingerprint or checks if the fingerprint starts with the signature key.
    """
    if not fingerprint:
        return None
    
    cleaned = str(fingerprint).strip().lower()
    
    # Try exact match first
    if cleaned in JA4_SIGNATURES:
        return JA4_SIGNATURES[cleaned]
    
    # Try prefix match (longest prefix match first)
    sorted_sig_keys = sorted(JA4_SIGNATURES.keys(), key=len, reverse=True)
    for sig in sorted_sig_keys:
        if cleaned.startswith(sig):
            return JA4_SIGNATURES[sig]
            
    return None
