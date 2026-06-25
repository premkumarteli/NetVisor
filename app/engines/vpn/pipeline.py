from typing import Optional, List, Dict, Any
from app.engines.common.config import EngineConfig
from app.engines.common.evidence import EvidenceTracker
from .asn_detector import ASNReputationDetector
from .wireguard import WireGuardHeuristicDetector
from .openvpn import OpenVPNSignatureDetector
from .tls_cert import TLSCertificateDetector

class VPNPipeline:
    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config if config is not None else EngineConfig()
        self.asn_detector = ASNReputationDetector()
        self.wireguard_detector = WireGuardHeuristicDetector()
        self.openvpn_detector = OpenVPNSignatureDetector()
        self.tls_detector = TLSCertificateDetector()

    def run(self, context: dict) -> Dict[str, Any]:
        """
        Runs the VPN pipeline against a flow context.
        Returns:
            dict containing:
              - is_vpn (bool)
              - confidence (float)
              - evidence (List[str])
              - provider (Optional[str])
              - vpn_type (Optional[str])
        """
        tracker = EvidenceTracker(self.config.vpn_weights)
        dst_ip = context.get("dst_ip") or context.get("ip") or "0.0.0.0"
        provider = None
        vpn_type = None

        # 1. ASN reputation & Tor exit nodes
        is_tor, is_asn, matched_provider, asn_reason = self.asn_detector.analyze(dst_ip)
        if is_tor:
            tracker.add_evidence("tor", asn_reason)
            provider = "Tor Exit Node"
            vpn_type = "Tor"
        elif is_asn:
            tracker.add_evidence("asn", asn_reason)
            provider = matched_provider

        # 2. WireGuard heuristics
        if self.wireguard_detector.analyze(context):
            tracker.add_evidence("wireguard", "WireGuard payload size patterns and consistent bidirectional exchange matched")
            vpn_type = "WireGuard"

        # 3. OpenVPN signatures
        is_ovpn, ovpn_reason = self.openvpn_detector.analyze(context)
        if is_ovpn:
            tracker.add_evidence("openvpn", ovpn_reason)
            vpn_type = "OpenVPN"

        # 4. TLS SNI / Certificate
        is_tls, tls_reason = self.tls_detector.analyze(context)
        if is_tls:
            tracker.add_evidence("tls", tls_reason)
            if not vpn_type:
                vpn_type = "TLS"
            # Try to extract provider from SNI/domain if we don't have one
            if not provider:
                for kw in ("nordvpn", "mullvad", "proton", "surfshark", "expressvpn", "windscribe", "ivpn", "pia"):
                    sni = str(context.get("sni") or "").lower()
                    domain = str(context.get("domain") or "").lower()
                    if kw in sni or kw in domain:
                        provider = kw.capitalize()
                        break

        total_conf = tracker.total_confidence
        is_vpn = total_conf >= self.config.vpn_threshold

        evidence_reasons = [str(ev.value) for ev in tracker.evidence_sources]

        return {
            "is_vpn": is_vpn,
            "confidence": total_conf,
            "evidence": evidence_reasons,
            "provider": provider,
            "vpn_type": vpn_type,
            "tracker": tracker
        }

    def clear(self) -> None:
        self.asn_detector = ASNReputationDetector()
        self.wireguard_detector.clear()
        self.openvpn_detector.clear()
        self.tls_detector.clear()
