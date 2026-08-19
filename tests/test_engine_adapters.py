import pytest
from engine import EngineResult, Finding
from backend.engines.device.engine import DeviceEngine
from backend.engines.application.engine import ApplicationEngine
from backend.engines.vpn.engine import VPNEngine

def test_device_engine_adapter():
    engine = DeviceEngine()
    assert engine.name == "device"
    assert engine.version == "1.0.0"
    
    # Assert initial metrics are zero
    m = engine.metrics()
    assert m["executions"] == 0
    assert m["findings_generated"] == 0
    assert m["avg_execution_ms"] == 0.0

    # Execute analyze
    context = {"ip": "192.168.1.10", "mac": "00:50:56:11:22:33", "hostname": "DESKTOP-ABC"}
    res = engine.analyze(context)
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 1
    
    # Assert metrics have updated
    m = engine.metrics()
    assert m["executions"] == 1
    assert m["findings_generated"] == 1
    assert m["avg_execution_ms"] >= 0.0


def test_application_engine_adapter():
    engine = ApplicationEngine()
    assert engine.name == "application"
    assert engine.version == "1.0.0"
    
    m = engine.metrics()
    assert m["executions"] == 0
    assert m["findings_generated"] == 0

    # Execute analyze
    row = {
        "src_ip": "192.168.1.10",
        "dst_ip": "172.217.16.14",
        "sni": "youtube.com",
        "protocol": "TCP"
    }
    res = engine.analyze(row)
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 1
    
    m = engine.metrics()
    assert m["executions"] == 1
    assert m["findings_generated"] == 1


def test_vpn_engine_adapter():
    engine = VPNEngine()
    assert engine.name == "vpn"
    assert engine.version == "1.0.0"
    
    m = engine.metrics()
    assert m["executions"] == 0

    # 185.220.101.1 matches Tor exit node in compatibility layer
    context = {"src_ip": "192.168.1.10", "dst_ip": "185.220.101.1", "port": 443}
    res = engine.analyze(context)
    assert isinstance(res, EngineResult)
    assert len(res.findings) == 1
    
    m = engine.metrics()
    assert m["executions"] == 1
    assert m["findings_generated"] == 1
