import time
import pytest
import ipaddress
import threading
import asyncio
from unittest.mock import MagicMock, AsyncMock
from backend.services.correlation_worker import CorrelationWorker
from backend.services.evidence_cache import evidence_cache, EvidenceSnapshot
from backend.core.config import settings

@pytest.fixture(autouse=True)
def clean_cache_and_settings():
    # Store old settings
    old_cidrs = settings.NETVISOR_ORGANIZATION_CIDRS
    old_assets = settings.NETVISOR_INFRASTRUCTURE_ASSETS
    old_max_edges = settings.NETVISOR_MAX_EDGES_PER_ORG
    old_max_preds = settings.NETVISOR_MAX_PREDECESSORS_PER_NODE
    old_max_supps = settings.NETVISOR_MAX_SUPPRESSION_ENTRIES_PER_ORG

    # Clear state in cache
    evidence_cache.clear()

    yield

    # Restore old settings
    settings.NETVISOR_ORGANIZATION_CIDRS = old_cidrs
    settings.NETVISOR_INFRASTRUCTURE_ASSETS = old_assets
    settings.NETVISOR_MAX_EDGES_PER_ORG = old_max_edges
    settings.NETVISOR_MAX_PREDECESSORS_PER_NODE = old_max_preds
    settings.NETVISOR_MAX_SUPPRESSION_ENTRIES_PER_ORG = old_max_supps
    evidence_cache.clear()

def test_scope_and_topology_validation():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"]}'
    settings.NETVISOR_INFRASTRUCTURE_ASSETS = '[]'
    
    # Define flows with invalid scopes (multicast, broadcast, loopback, unspecified, link-local, external)
    flows = [
        # Loopback
        {"src_ip": "127.0.0.1", "dst_ip": "10.0.0.5"},
        # Multicast
        {"src_ip": "10.0.0.5", "dst_ip": "224.0.0.252"},
        # Broadcast
        {"src_ip": "10.0.0.5", "dst_ip": "255.255.255.255"},
        # Link-local
        {"src_ip": "fe80::1", "dst_ip": "10.0.0.5"},
        # Unspecified
        {"src_ip": "0.0.0.0", "dst_ip": "10.0.0.5"},
        # External
        {"src_ip": "8.8.8.8", "dst_ip": "10.0.0.5"}
    ]
    
    incidents = worker.analyze_flows("org_1", flows)
    assert len(incidents) == 0
    # The invalid flows should not be entered in history
    assert len(worker.tenant_states["org_1"].connection_history) == 0

def test_subnet_aware_broadcast():
    worker = CorrelationWorker()
    # Configure organization CIDRs
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24", "172.16.0.0/12"]}'
    settings.NETVISOR_INFRASTRUCTURE_ASSETS = '[]'
    
    # 10.0.0.255 is the broadcast address for 10.0.0.0/24 subnet.
    # 172.16.255.255 is NOT a broadcast address for 172.16.0.0/12 (which is 172.31.255.255).
    flows = [
        # Subnet broadcast
        {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.255"},
        # Normal host in 172.16.0.0/12
        {"src_ip": "10.0.0.5", "dst_ip": "172.16.255.255"}
    ]
    
    worker.analyze_flows("org_1", flows)
    history = worker.tenant_states["org_1"].connection_history
    
    # Subnet broadcast (10.0.0.255) must be classified as BROADCAST and dropped
    assert ("10.0.0.5", "10.0.0.255") not in history
    # Normal host (172.16.255.255) must be kept
    assert ("10.0.0.5", "172.16.255.255") in history

def test_infrastructure_cidr_membership():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"]}'
    # 10.0.0.0/28 is infrastructure subnet
    settings.NETVISOR_INFRASTRUCTURE_ASSETS = '[{"org_id": "org_1", "cidr_or_ip": "10.0.0.0/28", "role": "server", "criticality": "high"}]'
    
    flows = [
        # Inside infrastructure range
        {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6"},
        # Outside infrastructure range but internal
        {"src_ip": "10.0.0.20", "dst_ip": "10.0.0.21"}
    ]
    
    worker.analyze_flows("org_1", flows)
    
    # Verify scope classification matches
    org_cidrs = worker._get_org_cidrs("org_1")
    infra_ips, infra_nets = worker._get_infra_assets("org_1")
    
    from backend.utils.network import classify_ip_scope_v2
    # 10.0.0.5 is inside 10.0.0.0/28
    assert classify_ip_scope_v2("10.0.0.5", org_cidrs, infra_ips, infra_nets) == "INFRASTRUCTURE"
    # 10.0.0.20 is outside 10.0.0.0/28
    assert classify_ip_scope_v2("10.0.0.20", org_cidrs, infra_ips, infra_nets) == "INTERNAL"

def test_temporal_causality():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"]}'
    
    # 1. Reverse causality check (B -> C before A -> B)
    # B -> C
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    # A -> B
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    assert len(incidents) == 0

    # 2. Correct causality (A -> B before B -> C)
    worker = CorrelationWorker()
    # A -> B at t1
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    # Add active threat evidence so it promotes to finding
    evidence_cache.record("org_1", "10.0.0.2", "MALWARE", "critical", time.time())
    # B -> C at t2
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    
    assert len(incidents) == 1
    assert incidents[0]["type"] == "lateral_movement"
    assert incidents[0]["chain"] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
    assert incidents[0]["severity"] == "CRITICAL"
    assert incidents[0]["confidence_score"] == 95

def test_cycle_rejection():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"]}'
    evidence_cache.record("org_1", "10.0.0.2", "ANOMALY", "critical", time.time())
    
    # A -> B -> A cycle
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.2"}])
    assert len(incidents) == 0

    # A -> A -> B self-loop cycle
    worker = CorrelationWorker()
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.2"}])
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    assert len(incidents) == 0

def test_tenant_isolation():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"], "org_2": ["10.0.0.0/24"]}'
    
    # org_1: A -> B
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    
    # Evidence exists in org_1, not in org_2
    evidence_cache.record("org_1", "10.0.0.2", "SCAN", "critical", time.time())
    
    # org_2: B -> C (Should NOT trigger since A -> B only exists in org_1)
    incidents = worker.analyze_flows("org_2", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    assert len(incidents) == 0
    
    # org_1: B -> C (Should trigger)
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    assert len(incidents) == 1

def test_evidence_promotion_policy():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"]}'
    
    # A -> B
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    
    # Case 1: Low evidence only -> Remains Candidate (does not promote)
    evidence_cache.record("org_1", "10.0.0.2", "ANOMALY", "low", time.time())
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    assert len(incidents) == 0
    
    # Case 2: Medium evidence on A, no pivot B evidence, 1 signal only -> Candidate only
    evidence_cache.clear()
    evidence_cache.record("org_1", "10.0.0.2", "ANOMALY", "medium", time.time())
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    assert len(incidents) == 0
    
    # Case 3: Medium evidence on A + Pivot B evidence (with lateral-relevant signal e.g. BRUTE_FORCE) -> Promoted
    evidence_cache.record("org_1", "10.0.0.3", "BRUTE_FORCE", "medium", time.time())
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "HIGH"
    
    # Case 4: High evidence with lateral-relevant signal (e.g. PORT_SCAN) -> Promoted
    evidence_cache.clear()
    worker = CorrelationWorker()
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    evidence_cache.record("org_1", "10.0.0.2", "PORT_SCAN", "high", time.time())
    incidents = worker.analyze_flows("org_1", [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}])
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "HIGH"
    assert incidents[0]["confidence_score"] == 80

def test_evidence_signal_decay():
    cache = evidence_cache
    cache.clear()
    
    now = time.time()
    # Record CRITICAL malware signal expiring in 2s
    cache.record("org_1", "10.0.0.5", "MALWARE", "critical", now, ttl_seconds=2.0)
    # Record LOW anomaly signal expiring in 10s
    cache.record("org_1", "10.0.0.5", "ANOMALY", "low", now, ttl_seconds=10.0)
    
    # Check max severity is CRITICAL initially
    snap = cache.get_active("org_1", "10.0.0.5", now)
    assert snap is not None
    assert snap.max_severity == "critical"
    
    # Check max severity decays to LOW after 3s (malware expired, anomaly active)
    snap_decayed = cache.get_active("org_1", "10.0.0.5", now + 3.0)
    assert snap_decayed is not None
    assert snap_decayed.max_severity == "low"
    assert "MALWARE" not in snap_decayed.signals

def test_eviction_limits_performance():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/8"]}'
    settings.NETVISOR_MAX_EDGES_PER_ORG = 10000
    
    # Load test: write 11,000 edges rapidly
    start_time = time.perf_counter()
    flows = [{"src_ip": f"10.1.{i // 256}.{i % 256}", "dst_ip": f"10.2.{i // 256}.{i % 256}"} for i in range(11000)]
    worker.analyze_flows("org_1", flows)
    duration = time.perf_counter() - start_time
    
    # Verify limit is respected
    history = worker.tenant_states["org_1"].connection_history
    assert len(history) == 10000

def test_evidence_cache_concurrency():
    cache = evidence_cache
    cache.clear()
    
    def worker_thread(tid):
        for i in range(100):
            cache.record("org_test", f"10.0.0.{tid}", f"SIGNAL_{i}", "medium", time.time())
            
    threads = []
    for t in range(5):
        thread = threading.Thread(target=worker_thread, args=(t,))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        thread.join()
        
    # Verify all records exist without race crashes
    for t in range(5):
        snap = cache.get_active("org_test", f"10.0.0.{t}", time.time())
        assert snap is not None
        assert len(snap.signals) == 100

def test_worker_shutdown_does_not_clear_shared_cache():
    worker = CorrelationWorker()
    settings.NETVISOR_ORGANIZATION_CIDRS = '{"org_1": ["10.0.0.0/24"]}'
    
    worker.analyze_flows("org_1", [{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"}])
    evidence_cache.record("org_1", "10.0.0.2", "SCAN", "medium", time.time())
    
    # Shutdown / cleanup
    worker.cleanup_state()
    
    # Local maps are cleared
    assert len(worker.tenant_states) == 0
    # Shared evidence cache is NOT cleared (retained for other engines)
    assert len(evidence_cache._cache) > 0

@pytest.mark.anyio
async def test_redis_retry_and_dlq(monkeypatch):
    """
    Integration test asserting the Redis PEL reclamation, delivery count, and DLQ routing logic.
    """
    # 1. Setup mock Redis client
    mock_redis = MagicMock()
    
    # Simulate a poison message payload
    poison_payload = {"flows": "invalid-json-structure", "org_id": "org_1"}
    
    # Mock xpending_range to return a message with delivery_count = 6 (exceeding retry limit)
    mock_redis.xpending_range.return_value = [
        {
            "message_id": "1620000000000-0",
            "elapsed_milliseconds": 20000,  # > 15s idle
            "times_delivered": 6,           # > 5 limit
        }
    ]
    
    # Mock xrange to return the payload for the poison message ID
    mock_redis.xrange.return_value = [("1620000000000-0", poison_payload)]
    
    # Mock xreadgroup to return empty to terminate the consumer loop quickly
    mock_redis.xreadgroup.return_value = []
    
    monkeypatch.setattr("backend.services.correlation_worker.get_redis_connection", lambda: mock_redis)
    
    worker = CorrelationWorker()
    
    # 2. Run the loop logic once manually by mocking start's while loop condition
    # We will trigger the periodic Pending Message Reclamation block
    # We will use monkeypatch to check random.random() < 0.1 to be always True
    monkeypatch.setattr("random.random", lambda: 0.05)
    
    # Run start loop and wait dynamically for completion of the reclamation block
    task = asyncio.create_task(worker.start())
    for _ in range(50):
        if mock_redis.xack.called:
            break
        await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    
    # 3. Assertions
    # Verify xrange was called to fetch the message payload
    mock_redis.xrange.assert_called_with("netvisor:flow_stream", min="1620000000000-0", max="1620000000000-0")
    # Verify message was routed to DLQ stream
    mock_redis.xadd.assert_called_with("netvisor:flow_stream:deadletter", poison_payload)
    # Verify xack was called to acknowledge and remove the failed message from PEL
    mock_redis.xack.assert_called_with("netvisor:flow_stream", "correlation_workers", "1620000000000-0")
