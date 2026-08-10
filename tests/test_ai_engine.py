import pytest
from datetime import datetime, timezone
from engine import Finding, Severity
from app.engines.common.config import EngineConfig
from app.engines.registry import EngineRegistry
from app.engines.ai.engine import AIEngine

def test_ai_engine_with_empty_findings():
    engine = AIEngine()
    context = {
        "src_ip": "10.0.0.5",
        "last_seen": datetime.now(timezone.utc),
        "_findings": []
    }
    
    result = engine.analyze(context)
    assert len(result.findings) == 1
    
    finding = result.findings[0]
    assert finding.finding_type == "ai_analysis"
    assert finding.severity == Severity.INFO
    assert finding.details["risk_score"] == 0
    assert "No significant threats detected" in finding.details["summary"]
    
    # Verify default playbook recommendations are returned
    recs = finding.details["recommendations"]
    assert len(recs) > 0
    assert any(r["priority"] == 1 for r in recs)


def test_ai_engine_with_unknown_finding_type():
    engine = AIEngine()
    
    custom_finding = Finding(
        engine="custom_plugin",
        finding_type="custom_threat",
        severity=Severity.HIGH,
        confidence=0.85,
        timestamp=datetime.now(timezone.utc),
        target_ip="10.0.0.5",
        evidence=["Custom threat triggered"]
    )
    
    context = {
        "src_ip": "10.0.0.5",
        "last_seen": datetime.now(timezone.utc),
        "_findings": [custom_finding]
    }
    
    # Should run successfully without throwing exceptions
    result = engine.analyze(context)
    assert len(result.findings) == 1
    
    finding = result.findings[0]
    assert finding.finding_type == "ai_analysis"
    # Fallback risk calculation should yield high risk (> 60) for a standalone HIGH finding
    assert finding.details["risk_score"] > 60
    assert "custom_threat" in finding.details["summary"]
    assert any(m["id"] == "UNKNOWN" for m in finding.details["mitre"])  # Fallback MITRE mapping


def test_ai_engine_with_multi_correlation():
    engine = AIEngine()
    
    # 1. credential_attack correlation finding
    cred_finding = Finding(
        engine="risk",
        finding_type="credential_attack",
        severity=Severity.HIGH,
        confidence=0.85,
        timestamp=datetime.now(timezone.utc),
        target_ip="10.0.0.5",
        evidence=["Credential attack correlated"]
    )
    
    # 2. active_c2 correlation finding
    c2_finding = Finding(
        engine="risk",
        finding_type="active_c2",
        severity=Severity.CRITICAL,
        confidence=0.90,
        timestamp=datetime.now(timezone.utc),
        target_ip="10.0.0.5",
        evidence=["Active C2 correlated"]
    )
    
    # 3. risk_summary finding
    risk_summary = Finding(
        engine="risk",
        finding_type="risk_summary",
        severity=Severity.CRITICAL,
        confidence=1.0,
        timestamp=datetime.now(timezone.utc),
        target_ip="10.0.0.5",
        details={
            "risk_score": 95,
            "active_findings_count": 2,
            "emitted_correlations_count": 2
        }
    )
    
    context = {
        "src_ip": "10.0.0.5",
        "last_seen": datetime.now(timezone.utc),
        "_findings": [cred_finding, c2_finding, risk_summary]
    }
    
    result = engine.analyze(context)
    assert len(result.findings) == 1
    
    finding = result.findings[0]
    assert finding.finding_type == "ai_analysis"
    assert finding.severity == Severity.CRITICAL
    assert finding.details["risk_score"] == 95
    assert finding.details["severity"] == "CRITICAL"
    
    # Summary should mention both active threat types
    summary = finding.details["summary"]
    assert "credential_attack" in summary
    assert "active_c2" in summary
    
    # Recommendations should contain prioritized playbooks from both
    recs = finding.details["recommendations"]
    assert len(recs) > 0
    
    # Verify strict Priority grouping (Priority 1 first, then 2, then 3)
    p1_indices = [i for i, r in enumerate(recs) if r["priority"] == 1]
    p2_indices = [i for i, r in enumerate(recs) if r["priority"] == 2]
    p3_indices = [i for i, r in enumerate(recs) if r["priority"] == 3]
    
    assert all(p1 < p2 for p1 in p1_indices for p2 in p2_indices)
    assert all(p2 < p3 for p2 in p2_indices for p3 in p3_indices)
    
    # MITRE mappings must contain T1110 and T1071
    mitres = {m["id"] for m in finding.details["mitre"]}
    assert "T1110" in mitres
    assert "T1071" in mitres


def test_ai_engine_registry_integration():
    registry = EngineRegistry()
    target_ip = "10.0.0.15"
    
    # Run selective analysis with threat, risk, and ai engines
    # Verify execution order and finding propagation
    
    # Feed 10 port scans to trigger port_scan
    res = None
    for port in range(1, 11):
        res = registry.analyze_selective({
            "src_ip": target_ip,
            "dst_ip": "192.168.1.1",
            "dst_port": port,
            "protocol": "TCP",
            "last_seen": "2026-06-16 12:00:00"
        }, ["threat", "risk", "ai"])
        
    assert res is not None
    # Execution order check: risk should execute last, then ai
    executed = res.metadata["executed_engines"]
    assert executed[-2] == "risk"
    assert executed[-1] == "ai"
    
    # Verify that ai_analysis finding is generated
    finding_types = {f.finding_type for f in res.findings}
    assert "ai_analysis" in finding_types
    
    ai_finding = next(f for f in res.findings if f.finding_type == "ai_analysis")
    assert ai_finding.details["risk_score"] == 70  # port scan risk score is 70
    assert "port_scan" in ai_finding.details["summary"]
    
    # Recommendations should include port scan remediation playbook actions
    recs = ai_finding.details["recommendations"]
    assert any("Block scanning traffic" in r["action"] for r in recs)
    
    # MITRE mapping should map port_scan to T1046
    mitres = {m["id"] for m in ai_finding.details["mitre"]}
    assert "T1046" in mitres
