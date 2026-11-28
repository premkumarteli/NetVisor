import re
from typing import Optional, Tuple

# Token-bounded patterns: must match as isolated word/token or delimited by [.-_ / space]
# Pia specially matches privateinternetaccess or isolated 'pia' token to prevent false positives
# on words like 'olympian', 'utopia', 'ethiopia', 'sepia', 'piano'.
VPN_PATTERNS = {
    "pia": re.compile(r"(?:^|[\W_])(?:pia|private[\s\-_.]*internet[\s\-_.]*access)(?:$|[\W_])", re.IGNORECASE),
    "mullvad": re.compile(r"(?:^|[\W_])mullvad(?:$|[\W_])", re.IGNORECASE),
    "nordvpn": re.compile(r"(?:^|[\W_])(?:nordvpn|nord-vpn)(?:$|[\W_])", re.IGNORECASE),
    "proton": re.compile(r"(?:^|[\W_])(?:protonvpn|proton-vpn|proton)(?:$|[\W_])", re.IGNORECASE),
    "surfshark": re.compile(r"(?:^|[\W_])surfshark(?:$|[\W_])", re.IGNORECASE),
    "expressvpn": re.compile(r"(?:^|[\W_])(?:expressvpn|express-vpn)(?:$|[\W_])", re.IGNORECASE),
    "windscribe": re.compile(r"(?:^|[\W_])windscribe(?:$|[\W_])", re.IGNORECASE),
    "ivpn": re.compile(r"(?:^|[\W_])ivpn(?:$|[\W_])", re.IGNORECASE),
}


class TLSCertificateDetector:
    def __init__(self) -> None:
        pass

    def _match_provider(self, text: str) -> Optional[str]:
        if not text:
            return None
        for provider, pattern in VPN_PATTERNS.items():
            if pattern.search(text):
                return provider
        return None

    def analyze(self, flow: dict) -> Tuple[bool, Optional[str]]:
        """
        Inspect SNI, Issuer CN, and Subject CN in that order of priority.
        Uses token-bounded regex to prevent false positive matches on partial substrings.
        Returns:
            (is_vpn, reason)
        """
        # Prioritize SNI
        sni = str(flow.get("sni") or "").lower()
        if sni:
            kw = self._match_provider(sni)
            if kw:
                return True, f"VPN provider '{kw}' detected in TLS SNI '{sni}'"

        # Next check Issuer CN
        issuer_cn = str(flow.get("issuer_cn") or "").lower()
        if issuer_cn:
            kw = self._match_provider(issuer_cn)
            if kw:
                return True, f"VPN provider '{kw}' detected in TLS Certificate Issuer CN '{issuer_cn}'"

        # Next check Subject CN
        subject_cn = str(flow.get("subject_cn") or "").lower()
        if subject_cn:
            kw = self._match_provider(subject_cn)
            if kw:
                return True, f"VPN provider '{kw}' detected in TLS Certificate Subject CN '{subject_cn}'"

        # Fallback to domain
        domain = str(flow.get("domain") or "").lower()
        if domain:
            kw = self._match_provider(domain)
            if kw:
                return True, f"VPN provider '{kw}' detected in flow domain '{domain}'"

        return False, None

    def clear(self) -> None:
        pass
