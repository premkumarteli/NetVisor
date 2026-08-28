from __future__ import annotations

from datetime import datetime, timezone
import pytest

from backend.engines.threat import ThreatEngine
from backend.engines.threat.kerberoasting import KerberoastingDetector
from backend.engines.threat.pass_the_hash import PassTheHashDetector
from backend.engines.threat.smb_lateral_movement import SMBLateralMovementDetector
from backend.engines.threat.dns_tunneling import DNSTunnelingDetector


def test_kerberoasting_detection():
    detector = KerberoastingDetector()
    now = datetime.now(timezone.utc)

    # Simulate 4 Kerberos TGS-REQ requests with RC4-HMAC weak encryption targeting distinct SPNs
    finding = None
    spns = ["MSSQLSvc/sql01.corp.local:1433", "HTTP/web01.corp.local", "HOST/dc01.corp.local", "CIFS/file01.corp.local"]
    for spn in spns:
        flow = {
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.10",
            "dst_port": 88,
            "application_protocol": "KERBEROS",
            "domain": spn,
            "analysis_signals": ["rc4_hmac", "etype_23"],
        }
        f = detector.analyze(flow, now)
        if f:
            finding = f

    assert finding is not None
    assert finding.finding_type == "kerberoasting"
    assert finding.severity.name == "HIGH"
    assert finding.confidence >= 0.85
    assert "Kerberoasting" in finding.evidence[0]


def test_pass_the_hash_admin_share_access():
    detector = PassTheHashDetector()
    now = datetime.now(timezone.utc)

    flow = {
        "src_ip": "10.0.4.50",
        "dst_ip": "10.0.4.100",
        "dst_port": 445,
        "application_protocol": "SMB2",
        "analysis_signals": ["C$", "NTLMSSP_AUTH", "PSEXEC"],
    }

    finding = detector.analyze(flow, now)
    assert finding is not None
    assert finding.finding_type == "pass_the_hash"
    assert finding.severity.name == "CRITICAL"
    assert finding.confidence >= 0.90
    assert "Pass-the-Hash" in finding.evidence[0]


def test_smb_lateral_movement_fanout():
    detector = SMBLateralMovementDetector()
    now = datetime.now(timezone.utc)

    targets = ["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.13"]
    finding = None
    for target in targets:
        flow = {
            "src_ip": "10.0.1.5",
            "dst_ip": target,
            "dst_port": 445,
            "application_protocol": "SMB2",
            "bytes_sent": 4096,
        }
        f = detector.analyze(flow, now)
        if f:
            finding = f

    assert finding is not None
    assert finding.finding_type == "smb_lateral_movement"
    assert finding.severity.name == "HIGH"
    assert "Lateral Movement" in finding.evidence[0]


def test_dns_tunneling_high_entropy():
    detector = DNSTunnelingDetector()
    now = datetime.now(timezone.utc)

    flow = {
        "src_ip": "172.16.0.40",
        "dst_ip": "8.8.8.8",
        "domain": "v9x8z7a6b5c4d3e2f1g0h9i8j7k6l5m4n3o2p1q0.exfil-c2.example.com",
    }

    finding = detector.analyze(flow, now)
    assert finding is not None
    assert finding.finding_type == "dns_tunneling"
    assert finding.severity.name == "CRITICAL"


def test_threat_engine_composite_pipeline():
    engine = ThreatEngine()
    now = datetime.now(timezone.utc)

    context = {
        "src_ip": "192.168.1.105",
        "dst_ip": "192.168.1.10",
        "dst_port": 88,
        "application_protocol": "KERBEROS",
        "domain": "MSSQLSvc/sql01.corp.local:1433",
        "analysis_signals": ["rc4_hmac", "etype_23"],
        "last_seen": now.isoformat(),
    }

    # Run multiple iterations to trigger detection thresholds
    result = None
    for i in range(4):
        ctx = dict(context)
        ctx["domain"] = f"SPN_{i}/service.corp.local"
        result = engine.analyze(ctx)

    assert result is not None
    assert len(result.findings) >= 1
    types = [f.finding_type for f in result.findings]
    assert "kerberoasting" in types
