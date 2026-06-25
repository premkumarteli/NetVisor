from typing import Optional, Tuple

VPN_PROVIDER_KEYWORDS = {
    "mullvad",
    "nordvpn",
    "proton",
    "surfshark",
    "expressvpn",
    "windscribe",
    "ivpn",
    "pia",
}

class TLSCertificateDetector:
    def __init__(self) -> None:
        pass

    def analyze(self, flow: dict) -> Tuple[bool, Optional[str]]:
        """
        Inspect SNI, Issuer CN, and Subject CN in that order of priority.
        Returns:
            (is_vpn, reason)
        """
        # Prioritize SNI
        sni = str(flow.get("sni") or "").lower()
        if sni:
            for kw in VPN_PROVIDER_KEYWORDS:
                if kw in sni:
                    return True, f"VPN provider '{kw}' detected in TLS SNI '{sni}'"

        # Next check Issuer CN
        issuer_cn = str(flow.get("issuer_cn") or "").lower()
        if issuer_cn:
            for kw in VPN_PROVIDER_KEYWORDS:
                if kw in issuer_cn:
                    return True, f"VPN provider '{kw}' detected in TLS Certificate Issuer CN '{issuer_cn}'"

        # Next check Subject CN
        subject_cn = str(flow.get("subject_cn") or "").lower()
        if subject_cn:
            for kw in VPN_PROVIDER_KEYWORDS:
                if kw in subject_cn:
                    return True, f"VPN provider '{kw}' detected in TLS Certificate Subject CN '{subject_cn}'"

        # Fallback to domain
        domain = str(flow.get("domain") or "").lower()
        if domain:
            for kw in VPN_PROVIDER_KEYWORDS:
                if kw in domain:
                    return True, f"VPN provider '{kw}' detected in flow domain '{domain}'"

        return False, None

    def clear(self) -> None:
        pass
