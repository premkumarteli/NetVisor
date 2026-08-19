import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest

from engine import Finding, Severity, EngineResult
from backend.engines.common.config import EngineConfig
from backend.engines.registry import EngineRegistry
from backend.engines.risk.engine import RiskEngine
from backend.engines.risk.decay import calculate_decay
from backend.engines.risk.suppression import SuppressionStore
from backend.engines.risk.correlation import Correlator
from backend.engines.risk.models import CorrelationRule, DEFAULT_RULES

def make_flow(**overrides):
    base = {
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "domain": None,
        "packet_count": 20,
        "byte_count": 5000,
        "duration": 3.0,
        "average_packet_size": 250.0,
        "agent_id": "agent-1",
        "organization_id": "org-1",
        "start_time": "2026-06-13 12:00:00",
        "last_seen": "2026-06-13 12:00:00",
    }
    base.update(overrides)
    return base


def test_decay_calculation_utility():
    # Base score = 100, age = 0 -> score should be 100
    assert calculate_decay(100.0, 0.0, 300.0, 300.0) == 100.0

    # Age = half-life (300s) -> score should be half (50)
    assert calculate_decay(100.0, 300.0, 600.0, 300.0) == 50.0

    # Age >= TTL (300s) -> score should be 0.0
    assert calculate_decay(100.0, 300.0, 300.0, 300.0) == 0.0

    # Negative age -> treat as 0
    assert calculate_decay(100.0, -10.0, 300.0, 300.0) == 100.0


def test_suppression_store():
    store = SuppressionStore()
    observed_at = datetime(2026, 6, 13, 12, 0, 0)

    # Initial check should not suppress
    assert not store.should_suppress("10.0.0.1", "rule1", observed_at, 60.0)

    # Record emission
    store.record_emission("10.0.0.1", "rule1", observed_at)

    # Subsequent check within window (30s later) should suppress
    assert store.should_suppress("10.0.0.1", "rule1", observed_at + timedelta(seconds=30), 60.0)

    # Check after window (61s later) should not suppress
    assert not store.should_suppress("10.0.0.1", "rule1", observed_at + timedelta(seconds=61), 60.0)

    # Check for different rule should not suppress
    assert not store.should_suppress("10.0.0.1", "rule2", observed_at + timedelta(seconds=30), 60.0)

    # Check for different IP should not suppress
    assert not store.should_suppress("10.0.0.2", "rule1", observed_at + timedelta(seconds=30), 60.0)


def test_correlation_rules_evaluation():
    correlator = Correlator()
    observed_at = datetime(2026, 6, 13, 12, 0, 0)
    target_ip = "10.0.0.5"

    # VPN finding
    vpn_finding = Finding(
        engine="vpn",
        finding_type="vpn_detected",
        severity=Severity.MEDIUM,
        confidence=0.8,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["VPN detected"]
    )

    # Port scan finding
    port_scan_finding = Finding(
        engine="threat",
        finding_type="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["Port scan detected"]
    )

    # Evaluate correlation when both are present
    active_findings = [(vpn_finding, 35.0), (port_scan_finding, 70.0)]
    correlations = correlator.evaluate_rules(target_ip, active_findings, observed_at)

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr.finding_type == "credential_attack"
    assert corr.severity == Severity.HIGH
    assert corr.mitre_attack_id == "T1110"
    assert corr.details["rule_name"] == "credential_attack"
    assert "vpn_detected" in corr.details["correlated_findings"]
    assert "port_scan" in corr.details["correlated_findings"]
    assert any("vpn_detected" in ev for ev in corr.evidence)
    assert any("port_scan" in ev for ev in corr.evidence)


def test_risk_score_aggregation_and_decay_in_engine():
    config = EngineConfig()
    config.risk_decay_half_life = 100.0  # short half life for testing
    config.risk_suppression_window = 10.0
    
    engine = RiskEngine(config=config)
    observed_at = datetime(2026, 6, 13, 12, 0, 0)
    target_ip = "10.0.0.8"

    # 1. First run with a single threat finding (port scan)
    port_scan = Finding(
        engine="threat",
        finding_type="port_scan",
        severity=Severity.HIGH,
        confidence=1.0,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["Scanning ports"]
    )

    context = {
        "src_ip": target_ip,
        "last_seen": observed_at,
        "_findings": [port_scan]
    }

    result = engine.analyze(context)
    assert len(result.findings) == 1
    summary = result.findings[0]
    assert summary.finding_type == "risk_summary"
    # Port scan base score is 70. Max aggregate is 70.
    assert summary.details["risk_score"] == 70
    assert summary.severity == Severity.HIGH

    # 2. Run again after 100 seconds (1 half life) with no new findings
    # Port scan decayed score = 70 * 0.5 = 35.
    context_later = {
        "src_ip": target_ip,
        "last_seen": observed_at + timedelta(seconds=100),
        "_findings": []
    }

    result_later = engine.analyze(context_later)
    assert len(result_later.findings) == 1
    summary_later = result_later.findings[0]
    assert summary_later.details["risk_score"] == 35
    assert summary_later.severity == Severity.MEDIUM

    # 3. Run again after 301 seconds (exceeding port scan TTL of 300s)
    # The finding should be pruned, and score should return to 0.
    context_expired = {
        "src_ip": target_ip,
        "last_seen": observed_at + timedelta(seconds=301),
        "_findings": []
    }
    result_expired = engine.analyze(context_expired)
    assert len(result_expired.findings) == 1
    summary_expired = result_expired.findings[0]
    assert summary_expired.details["risk_score"] == 0
    assert summary_expired.severity == Severity.INFO


def test_correlation_and_suppression_window():
    config = EngineConfig()
    config.risk_decay_half_life = 300.0
    config.risk_suppression_window = 60.0
    
    engine = RiskEngine(config=config)
    observed_at = datetime(2026, 6, 13, 12, 0, 0)
    target_ip = "10.0.0.12"

    vpn = Finding(
        engine="vpn",
        finding_type="vpn_detected",
        severity=Severity.MEDIUM,
        confidence=0.8,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["VPN active"]
    )
    port_scan = Finding(
        engine="threat",
        finding_type="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["Port scan active"]
    )

    # First execution should trigger credential_attack and risk_summary
    context = {
        "src_ip": target_ip,
        "last_seen": observed_at,
        "_findings": [vpn, port_scan]
    }
    res = engine.analyze(context)
    # Expected: risk_summary + credential_attack
    assert len(res.findings) == 2
    types = {f.finding_type for f in res.findings}
    assert "risk_summary" in types
    assert "credential_attack" in types

    # Second execution 30s later with the same context
    # Correlation is still valid but should be SUPPRESSED (within 60s)
    context_dup = {
        "src_ip": target_ip,
        "last_seen": observed_at + timedelta(seconds=30),
        "_findings": []
    }
    res_dup = engine.analyze(context_dup)
    # Expected: risk_summary only, credential_attack is suppressed
    assert len(res_dup.findings) == 1
    assert res_dup.findings[0].finding_type == "risk_summary"

    # Third execution 65s later
    # Correlation is still valid and suppression window has expired
    context_expiry = {
        "src_ip": target_ip,
        "last_seen": observed_at + timedelta(seconds=65),
        "_findings": []
    }
    res_expiry = engine.analyze(context_expiry)
    # Expected: risk_summary + credential_attack
    assert len(res_expiry.findings) == 2
    types_expiry = {f.finding_type for f in res_expiry.findings}
    assert "risk_summary" in types_expiry
    assert "credential_attack" in types_expiry


def test_registry_selective_reordering_and_integration():
    registry = EngineRegistry()
    
    # Verify risk engine is registered
    assert "risk" in registry.list_engines()

    # Verify order: risk should always execute last even if requested in different orders
    res1 = registry.analyze_selective({"src_ip": "10.0.0.1", "last_seen": "2026-06-13 12:00:00"}, ["risk", "threat"])
    assert res1.metadata["executed_engines"] == ["threat", "risk"]

    res2 = registry.analyze_selective({"src_ip": "10.0.0.1", "last_seen": "2026-06-13 12:00:00"})
    # Risk should execute second-to-last, and AI should execute last
    assert res2.metadata["executed_engines"][-2] == "risk"
    assert res2.metadata["executed_engines"][-1] == "ai"


def test_mixed_findings_fixture():
    fixture_path = os.path.join("tests", "fixtures", "risk", "mixed_findings.json")
    with open(fixture_path, "r") as f:
        fixture = json.load(f)

    registry = EngineRegistry()
    
    # We will simulate the series of flows in the fixture
    # mixed_findings has:
    # 1. VPN flow
    # 2. 10 Port scan flows
    # 3. 5 Beaconing flows
    # Target IP = 10.0.0.100

    results = []
    for flow in fixture["flows"]:
        # Run selective analysis with vpn and threat engines (so we generate vpn/threat findings)
        # And run risk at the end
        res = registry.analyze_selective(flow, ["vpn", "threat", "risk"])
        results.append(res)

    # We expect 'credential_attack' correlation to be triggered at least once across all flows
    all_triggered_types = {f.finding_type for res in results for f in res.findings}
    assert "credential_attack" in all_triggered_types
    # We do NOT expect 'active_c2', 'suspicious_exfiltration', or 'credential_stuffing' to be triggered anywhere
    assert "active_c2" not in all_triggered_types
    assert "suspicious_exfiltration" not in all_triggered_types
    assert "credential_stuffing" not in all_triggered_types

    # Verify that raw findings entered the risk engine history before correlation
    risk_history = registry.get("risk")._history["10.0.0.100"]
    history_types = {f.finding_type for f in risk_history}
    assert "vpn_detected" in history_types
    assert "port_scan" in history_types
    assert "beaconing" in history_types

    # Verify that finding history deduplication works (not accumulating duplicates)
    assert len(risk_history) == 3

    # Find the risk_summary finding from the final result to verify it has accumulated scores
    final_res = results[-1]
    summary = next(f for f in final_res.findings if f.finding_type == "risk_summary")
    # Base score of credential_attack is 80. Port scan is 70, beaconing is 70, vpn is 35.
    # Scores: 80, 70, 70, 35.
    # Aggregate: 80 + 70*0.1 + 70*0.1 + 35*0.1 = 80 + 7 + 7 + 3.5 = 97.5 -> 98.
    assert summary.details["risk_score"] > 80
    assert summary.severity == Severity.CRITICAL




def test_decay_expiry_fixture():
    fixture_path = os.path.join("tests", "fixtures", "risk", "decay_expiry.json")
    with open(fixture_path, "r") as f:
        fixture = json.load(f)

    registry = EngineRegistry()
    
    # 1. Run initial flows (Port scanning)
    res_high = None
    for flow in fixture["initial_flows"]:
        res_high = registry.analyze_selective(flow, ["threat", "risk"])

    # Verify that the risk score is high
    assert res_high is not None
    summary_high = next(f for f in res_high.findings if f.finding_type == "risk_summary")
    assert summary_high.details["risk_score"] == 70
    assert summary_high.severity == Severity.HIGH

    # 2. Run expiry flow at 12:06:00 (more than 5 mins/300s TTL after scan completed)
    res_expired = registry.analyze_selective(fixture["expiry_flow"], ["threat", "risk"])
    summary_expired = next(f for f in res_expired.findings if f.finding_type == "risk_summary")
    
    # Risk score should return to 0 since findings have expired
    assert summary_expired.details["risk_score"] == 0
    assert summary_expired.severity == Severity.INFO


def test_vpn_port_scan_correlation():
    registry = EngineRegistry()
    target_ip = "10.0.0.10"
    
    # 1. Feed a VPN flow (triggers vpn_detected)
    registry.analyze_selective({
        "src_ip": target_ip,
        "dst_ip": "185.220.101.1",
        "dst_port": 1194,
        "protocol": "UDP",
        "last_seen": "2026-06-13 12:00:00"
    }, ["vpn", "threat", "risk"])
    
    # 2. Feed 10 port scans to trigger port_scan
    # Collect all generated findings to handle potential early triggers and suppression
    all_finding_types = set()
    for port in range(1, 11):
        res = registry.analyze_selective({
            "src_ip": target_ip,
            "dst_ip": "192.168.1.1",
            "dst_port": port,
            "protocol": "TCP",
            "last_seen": "2026-06-13 12:00:05"
        }, ["vpn", "threat", "risk"])
        for f in res.findings:
            all_finding_types.add(f.finding_type)
        
    # Check that credential_attack was triggered in the findings
    assert "credential_attack" in all_finding_types


def test_beaconing_dns_correlation():
    registry = EngineRegistry()
    target_ip = "10.0.0.10"
    base_time = datetime(2026, 6, 13, 12, 0, 0)
    
    # 1. Feed 5 beaconing flows (spaced 30s apart)
    for i in range(5):
        registry.analyze_selective({
            "src_ip": target_ip,
            "dst_ip": "8.8.8.8",
            "dst_port": 80,
            "protocol": "TCP",
            "last_seen": base_time + timedelta(seconds=i*30)
        }, ["vpn", "threat", "risk"])
        
    # 2. Feed 51 unique subdomain queries to trigger dns_tunneling
    all_finding_types = set()
    for i in range(1, 52):
        res = registry.analyze_selective({
            "src_ip": target_ip,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "domain": f"sub{i}.example.com",
            "last_seen": base_time + timedelta(seconds=180) # 12:03:00
        }, ["vpn", "threat", "risk"])
        for f in res.findings:
            all_finding_types.add(f.finding_type)
        
    # Check that active_c2 was triggered
    assert "active_c2" in all_finding_types


def test_large_upload_beaconing_correlation():
    registry = EngineRegistry()
    target_ip = "10.0.0.10"
    base_time = datetime(2026, 6, 13, 12, 0, 0)
    
    # 1. Feed 5 beaconing flows
    for i in range(5):
        registry.analyze_selective({
            "src_ip": target_ip,
            "dst_ip": "8.8.8.8",
            "dst_port": 80,
            "protocol": "TCP",
            "last_seen": base_time + timedelta(seconds=i*30)
        }, ["vpn", "threat", "risk"])
        
    # 2. Feed 1 large upload flow (6MB)
    res = registry.analyze_selective({
        "src_ip": target_ip,
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_out": 6000000,
        "last_seen": base_time + timedelta(seconds=180) # 12:03:00
    }, ["vpn", "threat", "risk"])
    
    # Check that suspicious_exfiltration was triggered
    assert res is not None
    finding_types = {f.finding_type for f in res.findings}
    assert "suspicious_exfiltration" in finding_types


def test_configuration_overrides_propagation():
    # Instantiate custom EngineConfig
    config = EngineConfig()
    config.port_scan_threshold = 4
    
    # Instantiate registry with our custom config
    registry = EngineRegistry(config=config)
    
    # Verify that the threat engine within registry has config.port_scan_threshold = 4
    threat_engine = registry.get("threat")
    assert threat_engine.config.port_scan_threshold == 4
    
    # Feed 3 unique port scans -> should NOT alert
    for port in range(1, 4):
        res = registry.analyze_selective({
            "src_ip": "10.0.0.10",
            "dst_ip": "192.168.1.1",
            "dst_port": port,
            "protocol": "TCP",
            "last_seen": "2026-06-13 12:00:00"
        }, ["threat"])
        assert len(res.findings) == 0
        
    # 4th port scan -> should alert now because threshold was overridden to 4!
    res_4 = registry.analyze_selective({
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.1",
        "dst_port": 4,
        "protocol": "TCP",
        "last_seen": "2026-06-13 12:00:00"
    }, ["threat"])
    assert len(res_4.findings) == 1
    assert res_4.findings[0].finding_type == "port_scan"


def test_suppression_flood():
    config = EngineConfig()
    config.risk_suppression_window = 60.0
    engine = RiskEngine(config=config)
    observed_at = datetime(2026, 6, 13, 12, 0, 0)
    target_ip = "10.0.0.12"

    vpn = Finding(
        engine="vpn",
        finding_type="vpn_detected",
        severity=Severity.MEDIUM,
        confidence=0.8,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["VPN active"]
    )
    port_scan = Finding(
        engine="threat",
        finding_type="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        timestamp=observed_at,
        target_ip=target_ip,
        evidence=["Port scan active"]
    )

    emitted_correlations = []
    # Feed the findings 100 times, within the suppression window
    for i in range(100):
        # We simulate time passing slightly (e.g. 0.1s increments) but all within the 60s window
        curr_time = observed_at + timedelta(seconds=i * 0.1)
        curr_context = {
            "src_ip": target_ip,
            "last_seen": curr_time,
            "_findings": [vpn, port_scan]
        }
        res = engine.analyze(curr_context)
        for f in res.findings:
            if f.finding_type == "credential_attack":
                emitted_correlations.append(f)

    # Exactly 1 correlation should be emitted, and 99 suppressed!
    assert len(emitted_correlations) == 1


def test_risk_engine_stress_limit():
    import time
    engine = RiskEngine()
    target_ip = "10.0.0.1"
    observed_at = datetime(2026, 6, 13, 12, 0, 0)
    
    # We will generate 10,000 findings of various standard types in rotation
    standard_types = [
        ("vpn", "vpn_detected"),
        ("threat", "port_scan"),
        ("threat", "brute_force"),
        ("threat", "beaconing"),
        ("threat", "dns_tunneling"),
        ("threat", "large_upload")
    ]
    
    start_time = time.perf_counter()
    
    for i in range(10000):
        engine_name, finding_type = standard_types[i % len(standard_types)]
        finding = Finding(
            engine=engine_name,
            finding_type=finding_type,
            severity=Severity.HIGH,
            confidence=0.9,
            timestamp=observed_at + timedelta(seconds=i),
            target_ip=target_ip,
            evidence=["Telemetry stream"]
        )
        
        context = {
            "src_ip": target_ip,
            "last_seen": observed_at + timedelta(seconds=i),
            "_findings": [finding]
        }
        engine.analyze(context)
        
    duration = time.perf_counter() - start_time
    
    # History size should be bounded to the number of unique finding types (<= 6)
    history_size = len(engine._history[target_ip])
    assert history_size <= 6
    
    # Suppression store should contain at most the 4 unique rules
    suppression_size = len(engine.suppression_store._last_emitted)
    assert suppression_size <= 4
    
    # A single final execution should be extremely fast (< 50ms)
    final_start = time.perf_counter()
    engine.analyze({
        "src_ip": target_ip,
        "last_seen": observed_at + timedelta(seconds=10001),
        "_findings": []
    })
    final_duration_ms = (time.perf_counter() - final_start) * 1000.0
    assert final_duration_ms < 50.0, f"Final execution took too long: {final_duration_ms}ms"


