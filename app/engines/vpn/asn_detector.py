import logging
from typing import Tuple, Optional
from app.utils.asn_lookup import asn_lookup_service
from .tor_intel import tor_intel

logger = logging.getLogger(__name__)

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

DATACENTER_PROVIDERS = {
    "m247",
    "leaseweb",
    "datacamp",
    "ovh",
    "digitalocean",
    "linode",
    "hetzner",
}

class ASNReputationDetector:
    def __init__(self) -> None:
        pass

    def analyze(self, ip: str) -> Tuple[bool, bool, Optional[str], Optional[str]]:
        """
        Analyze the IP for ASN reputation and Tor exit node.
        Returns:
            (is_tor_exit, is_vpn_or_hosting, matched_provider, reason)
        """
        if not ip:
            return False, False, None, None

        # 1. Tor Exit check
        is_tor = False
        try:
            is_tor = tor_intel.is_tor_exit(ip)
        except Exception as e:
            logger.debug("Failed to check Tor exit node status for %s: %s", ip, e)

        if is_tor:
            return True, False, "Tor Exit Node", "Tor exit node"

        # 2. ASN lookup
        asn_details = asn_lookup_service.lookup_asn_details(ip)
        if not asn_details:
            return False, False, None, None

        asn = str(asn_details.get("asn") or "")
        org = str(asn_details.get("organization") or "").lower()

        # Match VPN keywords
        for kw in VPN_PROVIDER_KEYWORDS:
            if kw in org:
                # Map to proper name if needed
                provider_name = kw.capitalize()
                return False, True, provider_name, f"Known VPN provider '{kw}' in ASN/ISP organization '{org}' (ASN {asn})"

        # Match Datacenter keywords
        for kw in DATACENTER_PROVIDERS:
            if kw in org:
                return False, True, kw.capitalize(), f"Hosting/datacenter provider '{kw}' in ASN/ISP organization '{org}' (ASN {asn})"

        return False, False, None, None
