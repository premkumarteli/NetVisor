from app.services.threat_intelligence_service import threat_intel
from app.services.vpn_detector import vpn_detector


def test_threat_intel_uses_consistent_severity_levels():
    assert threat_intel.check_threat({"base_domain": "example-malware.com", "page_url": "https://example-malware.com"})["risk_level"] == "critical"
    assert threat_intel.check_threat({"base_domain": "files.example", "page_url": "https://files.example/bad.zip"})["risk_level"] == "medium"
    assert threat_intel.check_threat({"base_domain": "cdn.example", "page_url": "https://cdn.example/download", "event_count": 75})["risk_level"] == "high"


def test_vpn_detector_returns_reason_and_provider_hint():
    score, reason, provider = vpn_detector.analyze_vpn(
        "10.0.0.2",
        "45.2.3.15",
        51820,
        "connect.protonvpn.com",
    )

    assert score > 0
    assert "VPN" in reason
    assert provider == "ProtonVPN"
