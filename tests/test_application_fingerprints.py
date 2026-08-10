import json
import os
import pytest
from datetime import datetime, timezone
from engine import Severity
from app.engines.registry import EngineRegistry
from app.services.application_service import application_service
from app.utils.asn_lookup import asn_lookup_service

# Load fixtures helper
def load_fixture(name: str) -> dict:
    path = os.path.join("tests", "fixtures", "applications", name)
    with open(path, "r") as f:
        return json.load(f)

def test_tls_fingerprint_classification():
    # 1. Standard fingerprint (Curl)
    curl_data = load_fixture("curl_tls.json")
    result = application_service.classify_app(curl_data)
    assert result == "Curl"
    
    # 2. Suspicious fingerprint (Tor)
    tor_data = load_fixture("tor_browser_tls.json")
    result = application_service.classify_app(tor_data)
    assert result == "Tor Browser"
    
    # 3. Malicious fingerprint (Cobalt Strike)
    cs_data = load_fixture("cobalt_strike_tls.json")
    result = application_service.classify_app(cs_data)
    assert result == "Cobalt Strike C2"

def test_compatibility_wrapper_findings(monkeypatch):
    # Mock ASN lookup
    monkeypatch.setattr(
        asn_lookup_service,
        "lookup_asn_details",
        lambda ip: {"asn": 13335, "organization": "Cloudflare"} if ip else None
    )
    
    from app.services.application_service import application_compatibility_wrapper
    
    # 1. Curl finding
    curl_data = load_fixture("curl_tls.json")
    res = application_compatibility_wrapper(curl_data)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.finding_type == "application_detected"
    assert f.severity == Severity.INFO
    assert f.details["application_name"] == "Curl"
    assert f.details["asn"] == 13335
    assert f.details["asn_org"] == "Cloudflare"
    assert f.details["ja4_fingerprint"] == "t13d1516h2_3d1a_000a"
    
    # 2. Tor finding (Suspicious)
    tor_data = load_fixture("tor_browser_tls.json")
    res = application_compatibility_wrapper(tor_data)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.finding_type == "suspicious_application_detected"
    assert f.severity == Severity.HIGH
    assert f.mitre_attack_id == "T1090"
    
    # 3. Cobalt Strike finding (Malicious)
    cs_data = load_fixture("cobalt_strike_tls.json")
    res = application_compatibility_wrapper(cs_data)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.finding_type == "malicious_application_detected"
    assert f.severity == Severity.CRITICAL
    assert f.mitre_attack_id == "T1071"

def test_malicious_fingerprint_risk_correlation(monkeypatch):
    # Mock ASN lookup
    monkeypatch.setattr(
        asn_lookup_service,
        "lookup_asn_details",
        lambda ip: {"asn": 16509, "organization": "Amazon"} if ip else None
    )
    
    registry = EngineRegistry()
    target_ip = "10.0.0.100"
    
    # Analyze malicious flow using registry
    flow = load_fixture("cobalt_strike_tls.json")
    flow["src_ip"] = target_ip
    flow["last_seen"] = datetime.now(timezone.utc)
    
    # Reset state in risk engine to ensure clean run
    registry.get("risk").clear_state()
    
    res = registry.analyze_selective(flow, ["application", "risk", "ai"])
    
    # Ensure all run
    executed = res.metadata["executed_engines"]
    assert "application" in executed
    assert "risk" in executed
    assert "ai" in executed
    
    # Check that malicious_application_detected is generated
    finding_types = {f.finding_type for f in res.findings}
    assert "malicious_application_detected" in finding_types
    assert "risk_summary" in finding_types
    assert "ai_analysis" in finding_types
    
    # Check risk score propagated (should be at least 85)
    risk_finding = next(f for f in res.findings if f.finding_type == "risk_summary")
    assert risk_finding.details["risk_score"] >= 85
    
    # Check AI analysis details
    ai_finding = next(f for f in res.findings if f.finding_type == "ai_analysis")
    assert ai_finding.details["risk_score"] >= 85
    
    # Verify MITRE mapping for malicious_application_detected (T1071) is present
    mitres = {m["id"] for m in ai_finding.details["mitre"]}
    assert "T1071" in mitres
    
    # Verify AI summary references the application
    summary = ai_finding.details["summary"]
    assert "Cobalt Strike C2" in summary
