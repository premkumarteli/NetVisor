from shared.engine import EngineResult, Finding
from agent.device_detector import device_compatibility_wrapper
from app.services.application_service import application_compatibility_wrapper

def test_device_compatibility_wrapper_success():
    res = device_compatibility_wrapper(ip="192.168.1.10", mac="00:50:56:11:22:33", hostname="DESKTOP-ABC")
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.engine == "device"
    assert finding.finding_type == "device_profiled"
    assert finding.target_ip == "192.168.1.10"
    assert finding.target_mac == "00:50:56:11:22:33"
    assert finding.details["vendor"] == "VMware"
    assert "MAC Address presence" in finding.evidence


def test_device_compatibility_wrapper_edge_cases():
    # Test with mac=None and hostname=None
    res = device_compatibility_wrapper(ip="127.0.0.1", mac=None, hostname=None, active_probe=False)
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.engine == "device"
    assert finding.finding_type == "device_profiled"
    assert finding.target_mac is None
    # Vendor should be Unknown since MAC is missing
    assert finding.details["vendor"] == "Unknown"
    # No MAC Address presence in evidence
    assert "MAC Address presence" not in finding.evidence


def test_application_compatibility_wrapper_success():
    # YouTube matches via the rules in ApplicationService
    row = {
        "src_ip": "192.168.1.10",
        "dst_ip": "172.217.16.14",
        "sni": "youtube.com",
        "protocol": "TCP"
    }
    res = application_compatibility_wrapper(row)
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.engine == "application"
    assert finding.details["application_name"] == "YouTube"
    assert "Classified application: YouTube" in finding.evidence


def test_application_compatibility_wrapper_unknown():
    # A generic unknown flow should yield no findings (empty list)
    row = {
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "src_port": 12345,
        "dst_port": 54321,
    }
    res = application_compatibility_wrapper(row)
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 0
    assert res.metadata["application"] == "Unknown"
