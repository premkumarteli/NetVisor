import pytest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from engine.severity import Severity
from engine.findings import Finding
from engine.result import EngineResult
from engine.base import BaseEngine

# Define dummy engine implementations for validation
class DummyDeviceEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "DummyDevice"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, context: dict) -> EngineResult:
        mac = context.get("mac", "00:00:00:00:00:00")
        ip = context.get("ip", "0.0.0.0")
        findings = [
            Finding(
                engine=self.name,
                finding_type="device_discovery",
                severity=Severity.INFO,
                confidence=0.95,
                evidence=["Mac OUI matched", "mDNS query observed"],
                target_ip=ip,
                target_mac=mac,
                details={"host_hint": context.get("hostname", "Unknown")}
            )
        ]
        return EngineResult(findings=findings, metadata={"duration_ms": 1.5})


class DummyThreatEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "DummyThreat"

    @property
    def version(self) -> str:
        return "1.2.0"

    def analyze(self, context: dict) -> EngineResult:
        findings = []
        port_scan_detected = context.get("scanned_port_count", 0) >= 10
        if port_scan_detected:
            findings.append(
                Finding(
                    engine=self.name,
                    finding_type="port_scan",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    evidence=[f"Scanned {context['scanned_port_count']} unique ports"],
                    target_ip=context.get("ip", "0.0.0.0"),
                    mitre_attack_id="T1046"
                )
            )
        return EngineResult(findings=findings, metadata={"analyzer": "heuristic"})


def test_severity_values():
    assert Severity.INFO == "INFO"
    assert Severity.LOW == "LOW"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.HIGH == "HIGH"
    assert Severity.CRITICAL == "CRITICAL"


def test_finding_immutability():
    finding = Finding(
        engine="Test",
        finding_type="test_finding",
        severity=Severity.MEDIUM,
        confidence=0.8
    )
    assert finding.engine == "Test"
    assert finding.finding_type == "test_finding"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == 0.8
    assert finding.ttl == 300
    assert isinstance(finding.timestamp, datetime)
    
    # Assert frozen/immutability
    with pytest.raises(FrozenInstanceError):
        finding.confidence = 0.9  # type: ignore


def test_engine_result_encapsulation():
    finding = Finding(
        engine="Test",
        finding_type="test_finding",
        severity=Severity.LOW,
        confidence=0.5
    )
    result = EngineResult(findings=[finding], metadata={"key": "value"})
    assert len(result.findings) == 1
    assert result.findings[0].engine == "Test"
    assert result.metadata == {"key": "value"}


def test_dummy_device_engine_validation():
    engine = DummyDeviceEngine()
    assert engine.name == "DummyDevice"
    assert engine.version == "1.0.0"
    
    context = {"ip": "192.168.1.50", "mac": "00:11:22:33:44:55", "hostname": "DESKTOP-ABC"}
    result = engine.analyze(context)
    
    assert isinstance(result, EngineResult)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.engine == "DummyDevice"
    assert finding.finding_type == "device_discovery"
    assert finding.severity == Severity.INFO
    assert finding.confidence == 0.95
    assert finding.target_ip == "192.168.1.50"
    assert finding.target_mac == "00:11:22:33:44:55"
    assert finding.details == {"host_hint": "DESKTOP-ABC"}
    assert result.metadata == {"duration_ms": 1.5}


def test_dummy_threat_engine_validation():
    engine = DummyThreatEngine()
    assert engine.name == "DummyThreat"
    assert engine.version == "1.2.0"
    
    # Test case with no findings
    context_benign = {"ip": "10.0.0.5", "scanned_port_count": 3}
    result_benign = engine.analyze(context_benign)
    assert len(result_benign.findings) == 0
    
    # Test case with finding
    context_threat = {"ip": "10.0.0.5", "scanned_port_count": 12}
    result_threat = engine.analyze(context_threat)
    assert len(result_threat.findings) == 1
    finding = result_threat.findings[0]
    assert finding.engine == "DummyThreat"
    assert finding.finding_type == "port_scan"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9
    assert finding.mitre_attack_id == "T1046"
    assert "Scanned 12 unique ports" in finding.evidence
