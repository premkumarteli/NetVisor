import os
import json
import pytest
from app.engines.threat.engine import ThreatEngine
from shared.engine import EngineResult

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "threats")

def get_fixture_files():
    """Helper to locate all threat JSON fixture files."""
    files = []
    if os.path.exists(FIXTURES_DIR):
        for f in os.listdir(FIXTURES_DIR):
            if f.endswith(".json"):
                files.append(os.path.join(FIXTURES_DIR, f))
    return files

@pytest.mark.parametrize("fixture_path", get_fixture_files())
def test_threat_engine_parity_with_fixture(fixture_path):
    # Load the fixture
    with open(fixture_path, "r", encoding="utf-8") as f:
        fixture_data = json.load(f)

    fixture_name = fixture_data["name"]
    flows = fixture_data.get("flows", [])
    expected_findings = fixture_data.get("expected_findings", [])

    # Instantiate threat engine
    engine = ThreatEngine()

    actual_findings = []
    # Feed flows sequentially to mimic real-time processing
    for flow in flows:
        res = engine.analyze(flow)
        assert isinstance(res, EngineResult), f"Result for {fixture_name} must be an EngineResult"
        actual_findings.extend(res.findings)

    # Assert metrics
    metrics = engine.metrics()
    assert metrics["executions"] == len(flows), f"Executions metric mismatch for {fixture_name}"
    assert metrics["findings_generated"] == len(actual_findings), f"Findings generated metric mismatch for {fixture_name}"

    # Verify the findings match the expected ones
    assert len(actual_findings) == len(expected_findings), (
        f"Findings count mismatch for {fixture_name}: expected {len(expected_findings)}, got {len(actual_findings)}. "
        f"Actual findings: {actual_findings}"
    )

    for expected in expected_findings:
        match_found = False
        for actual in actual_findings:
            severity_name = actual.severity.name if hasattr(actual.severity, "name") else str(actual.severity)
            if (
                actual.finding_type == expected["finding_type"]
                and severity_name == expected["severity"]
                and pytest.approx(actual.confidence) == expected["confidence"]
                and actual.evidence == expected["evidence"]
            ):
                match_found = True
                break
        assert match_found, f"Could not find matching actual finding for expected: {expected} in actual findings: {actual_findings} for {fixture_name}"


def test_port_scan_boundary():
    engine = ThreatEngine()
    
    # 9 ports -> no alert
    for port in range(1, 10):
        res = engine.analyze({
            "src_ip": "10.0.0.10",
            "dst_ip": "192.168.1.1",
            "dst_port": port,
            "protocol": "TCP",
            "last_seen": "2026-06-13 12:00:00"
        })
        assert len(res.findings) == 0

    # 10 ports -> alert
    res_10 = engine.analyze({
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.1",
        "dst_port": 10,
        "protocol": "TCP",
        "last_seen": "2026-06-13 12:00:01"
    })
    assert len(res_10.findings) == 1
    assert res_10.findings[0].finding_type == "port_scan"


def test_large_upload_boundary():
    engine = ThreatEngine()

    # 4.99MB (4990000 bytes) -> no alert
    res_small = engine.analyze({
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_out": 4990000,
        "last_seen": "2026-06-13 12:00:00"
    })
    assert len(res_small.findings) == 0

    # 5.00MB (5000000 bytes) -> no alert
    res_threshold = engine.analyze({
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_out": 5000000,
        "last_seen": "2026-06-13 12:00:01"
    })
    assert len(res_threshold.findings) == 0

    # 5.01MB (5010000 bytes) -> alert
    res_large = engine.analyze({
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_out": 5010000,
        "last_seen": "2026-06-13 12:00:02"
    })
    assert len(res_large.findings) == 1
    assert res_large.findings[0].finding_type == "large_upload"


def test_subdomain_bloom_boundary():
    engine = ThreatEngine()

    # 49 subdomains -> no alert
    for i in range(1, 50):
        res = engine.analyze({
            "src_ip": "10.0.0.10",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "domain": f"sub{i}.example.com",
            "last_seen": "2026-06-13 12:00:00"
        })
        assert len(res.findings) == 0

    # 50 subdomains -> no alert (threshold is 50, so <= 50 is safe)
    res_50 = engine.analyze({
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "UDP",
        "domain": "sub50.example.com",
        "last_seen": "2026-06-13 12:00:00"
    })
    assert len(res_50.findings) == 0

    # 51 subdomains -> alert (> 50)
    res_51 = engine.analyze({
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "UDP",
        "domain": "sub51.example.com",
        "last_seen": "2026-06-13 12:00:01"
    })
    assert len(res_51.findings) == 1
    assert res_51.findings[0].finding_type == "dns_tunneling"
