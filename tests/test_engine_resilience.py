import pytest
from datetime import datetime, timezone
from shared.engine import Severity
from app.engines.registry import EngineRegistry

@pytest.fixture
def registry():
    return EngineRegistry()

FUZZ_CONTEXTS = [
    # 1. Empty context
    {},
    # 2. Missing or None IPs
    {"src_ip": None, "dst_ip": None, "internal_device_ip": None, "target_ip": None},
    # 3. Invalid/Malformed timestamps
    {"last_seen": "invalid-timestamp-format-abc", "first_seen": 123456789},
    # 4. Incorrect types for fields
    {"ja4": 123, "domain": {}, "sni": []},
    # 5. Negative values and overflow bounds
    {"bytes_out": -1, "total_bytes": -999999999, "byte_count": "invalid-bytes", "packets": -50},
    # 6. Completely unexpected and massive garbage keys
    {"garbage_key": "x" * 10000, "another_junk": {"nested": "value"}},
    # 7. Missing/None internal fields
    {"_findings": None, "_engine_results": None},
    # 8. Mix of malformed fields
    {
        "src_ip": 127001,
        "dst_port": "not-a-port",
        "protocol": None,
        "ja4_fingerprint": 9.99,
        "last_seen": datetime.now(timezone.utc)
    }
]

def test_all_engines_resilience(registry):
    """
    Ensure every registered engine handles a series of highly malformed, 
    incorrectly typed, and boundary-overflow contexts without raising exceptions.
    """
    engines = registry.list_engines()
    
    for context in FUZZ_CONTEXTS:
        for engine_name in engines:
            engine = registry.get(engine_name)
            try:
                # Run engine analysis and verify it returns a valid EngineResult
                result = engine.analyze(context)
                assert result is not None
                assert hasattr(result, "findings")
                assert hasattr(result, "metadata")
            except Exception as e:
                pytest.fail(f"Engine '{engine_name}' raised an exception during fuzz context analysis: {e}\nContext: {context}")

def test_registry_selective_resilience(registry):
    """
    Ensure EngineRegistry.analyze_selective executes cleanly on malformed context data.
    """
    for context in FUZZ_CONTEXTS:
        try:
            result = registry.analyze_selective(context)
            assert result is not None
            assert hasattr(result, "findings")
            assert hasattr(result, "metadata")
        except Exception as e:
            pytest.fail(f"Registry selective analysis raised an exception during fuzz context: {e}\nContext: {context}")


def test_concurrent_engine_execution(registry):
    """
    Simulate highly concurrent execution (1000 tasks across 16 threads)
    and verify that engine metrics remain consistent (threat >= risk >= ai).
    """
    import concurrent.futures
    import random

    # Reset state to ensure clean start
    for name in registry.list_engines():
        engine = registry.get(name)
        if hasattr(engine, "clear_state"):
            engine.clear_state()

    contexts = []
    for i in range(1000):
        ip_idx = i % 10
        contexts.append({
            "src_ip": f"192.168.1.{ip_idx}",
            "dst_ip": f"10.0.0.{ip_idx}",
            "dst_port": random.choice([80, 443, 22, 53, 8080]),
            "protocol": "TCP",
            "byte_count": random.randint(100, 5000),
            "packets": random.randint(1, 10),
            "last_seen": datetime.utcnow().isoformat()
        })

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        futures = [
            executor.submit(registry.analyze_selective, ctx, ["threat", "risk", "ai"])
            for ctx in contexts
        ]
        # Wait and raise exceptions if any occurred in the threads
        for f in futures:
            f.result()

    metrics = registry.metrics()
    assert metrics["threat"]["executions"] > 0
    assert metrics["risk"]["executions"] > 0
    assert metrics["ai"]["executions"] > 0
    assert metrics["threat"]["executions"] >= metrics["risk"]["executions"]
    assert metrics["risk"]["executions"] >= metrics["ai"]["executions"]


def test_parallel_risk_correlation(registry):
    """
    Verify that 50 threads running concurrently against the same target IP
    triggering risk correlation (vpn_detected + port_scan -> credential_attack)
    results in exactly one correlation alert due to suppression store thread safety.
    """
    import concurrent.futures
    from shared.engine import Finding, Severity

    # Reset state to ensure clean start
    risk_engine = registry.get("risk")
    risk_engine.clear_state()

    observed_at = datetime.utcnow()
    target_ip = "192.168.1.100"

    # Context containing the two required findings
    vpn_finding = Finding(
        engine="vpn",
        finding_type="vpn_detected",
        severity=Severity.LOW,
        confidence=0.8,
        evidence=["VPN connection detected"],
        timestamp=observed_at,
        target_ip=target_ip
    )
    port_scan_finding = Finding(
        engine="threat",
        finding_type="port_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        evidence=["Port scan detected"],
        timestamp=observed_at,
        target_ip=target_ip
    )

    context = {
        "src_ip": target_ip,
        "last_seen": observed_at,
        "_findings": [vpn_finding, port_scan_finding]
    }

    # Execute 50 concurrent calls directly to risk engine to preserve _findings
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [
            executor.submit(risk_engine.analyze, context)
            for _ in range(50)
        ]
        results = [f.result() for f in futures]

    # Count how many times credential_attack finding was emitted
    emitted_count = 0
    for res in results:
        for finding in res.findings:
            if finding.finding_type == "credential_attack":
                emitted_count += 1

    # Exactly one thread should emit, all others suppressed
    assert emitted_count == 1
