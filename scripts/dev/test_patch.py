from unittest.mock import patch
from backend.engines.vpn.asn_detector import ASNReputationDetector
detector = ASNReputationDetector()
with patch("backend.services.vpn_detector.TorIntelligence.is_tor_exit", return_value=True):
    is_tor, is_asn, provider, reason = detector.analyze("185.220.101.1")
    print("Is tor:", is_tor)
