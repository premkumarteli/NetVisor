"""
Adversarial Concurrency & WebSocket Payload Stress Suite for M2.
Written by Challenger M2-2.

Tests:
1. High-concurrency GET /api/v1/dashboard/overview (100 parallel requests)
2. WebSocket dashboard_update payload consistency under rapid multi-threaded state updates
3. Data integrity & invariant checking under extreme dynamic telemetry mutations
"""

import asyncio
import threading
import time
import random
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.dependencies import require_org_admin, get_current_user
from backend.services.live_telemetry_store import LiveTelemetryStore, live_telemetry_store
from backend.services.broadcast_scheduler import BroadcastScheduler


@pytest.fixture
def mock_admin_client():
    mock_user = {
        "user_id": "test-admin-stress",
        "organization_id": "org-stress-test",
        "role": "org_admin",
        "username": "admin_stress",
        "email": "admin_stress@example.com",
    }
    app.dependency_overrides[require_org_admin] = lambda: mock_user
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def test_concurrent_get_dashboard_overview(mock_admin_client):
    """
    Stress-test concurrent HTTP GET /api/v1/dashboard/overview calls.
    Executes 100 requests across 10 threads concurrently.
    Verifies zero 500 errors, connection leaks, or schema corruptions.
    """
    num_threads = 10
    requests_per_thread = 10
    errors = []
    responses = []
    lock = threading.Lock()

    def worker():
        for _ in range(requests_per_thread):
            try:
                resp = mock_admin_client.get("/api/v1/dashboard/overview")
                if resp.status_code != 200:
                    with lock:
                        errors.append(f"HTTP {resp.status_code}: {resp.text}")
                else:
                    data = resp.json()
                    # Validate schema invariants
                    assert "agents_summary" in data
                    assert "gateways_summary" in data
                    assert "fleet_summary" in data
                    assert data["fleet_summary"]["total_queue_depth"] == (
                        data["agents_summary"]["queue_depth"] + data["gateways_summary"]["queue_depth"]
                    )
                    assert data["fleet_summary"]["total_degraded"] == (
                        data["agents_summary"]["degraded"] + data["gateways_summary"]["degraded"]
                    )
                    with lock:
                        responses.append(data)
            except Exception as e:
                with lock:
                    errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    start_time = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start_time

    assert len(errors) == 0, f"Encountered {len(errors)} errors during concurrent requests: {errors[:5]}"
    assert len(responses) == num_threads * requests_per_thread, (
        f"Expected {num_threads * requests_per_thread} successful responses, got {len(responses)}"
    )
    print(f"\n[STRESS TEST PASS] 100 concurrent GET /api/v1/dashboard/overview completed in {elapsed:.3f}s")


@pytest.mark.anyio
async def test_websocket_payload_consistency_under_dynamic_updates():
    """
    Stress-test WebSocket dashboard_update payload consistency while 15 threads
    actively mutate LiveTelemetryStore state (recording flows, agents, gateways, alerts, pruning).
    """
    store = LiveTelemetryStore()
    scheduler = BroadcastScheduler()
    
    stop_event = threading.Event()
    mutation_errors = []
    emitted_payloads = []
    payload_lock = asyncio.Lock()

    async def mock_emit_event(event_name, payload):
        if event_name == "dashboard_update":
            async with payload_lock:
                emitted_payloads.append(payload)

    # Worker function mutating store continuously
    def mutator_worker(worker_id):
        org_ids = ["org-alpha", "org-beta", "org-gamma", "default"]
        statuses = ["online", "offline", "degraded"]
        try:
            while not stop_event.is_set():
                org = random.choice(org_ids)
                op = random.randint(1, 6)
                if op == 1:
                    store.record_agent_status(
                        organization_id=org,
                        agent_id=f"agent-{worker_id}-{random.randint(1, 20)}",
                        status=random.choice(statuses),
                        queue_depth=random.randint(0, 1000),
                        errors=random.randint(0, 10),
                    )
                elif op == 2:
                    store.record_gateway_status(
                        organization_id=org,
                        gateway_id=f"gw-{worker_id}-{random.randint(1, 20)}",
                        status=random.choice(statuses),
                        queue_depth=random.randint(0, 500),
                        errors=random.randint(0, 5),
                    )
                elif op == 3:
                    store.record_alert(
                        org,
                        {
                            "id": f"alt-{random.randint(1, 1000)}",
                            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                            "score": random.uniform(1.0, 10.0),
                            "src_ip": f"192.168.1.{random.randint(1, 254)}",
                            "time": "2026-08-11T12:00:00Z",
                        },
                    )
                elif op == 4:
                    flow_key = (f"10.0.0.{worker_id}", "8.8.8.8", 1234, 443, "TCP")
                    store.record_flow(
                        org, flow_key, bytes_count=1000, packets_count=10, app="HTTPS", proto="TCP", is_new=True, is_end=False
                    )
                elif op == 5:
                    store.register_known_ip(org, f"10.0.0.{random.randint(1, 254)}")
                elif op == 6:
                    store.prune_old_samples(org, time.time())
                time.sleep(0.001)
        except Exception as exc:
            mutation_errors.append(f"Worker {worker_id} crashed: {exc}")

    # Launch 15 mutator threads
    threads = [threading.Thread(target=mutator_worker, args=(i,), daemon=True) for i in range(15)]
    for t in threads:
        t.start()

    with patch("backend.services.broadcast_scheduler.emit_event", side_effect=mock_emit_event), \
         patch("backend.services.broadcast_scheduler.live_telemetry_store", store):
        
        # Broadcast 20 rounds of updates while state is rapidly changing
        for _ in range(20):
            await scheduler.broadcast_all()
            await asyncio.sleep(0.01)

    stop_event.set()
    for t in threads:
        t.join(timeout=2.0)

    assert len(mutation_errors) == 0, f"Mutator thread errors: {mutation_errors}"
    assert len(emitted_payloads) >= 20, f"Expected at least 20 broadcasts, got {len(emitted_payloads)}"

    # Invariant checks on all emitted payloads
    required_stats_keys = {
        "active_devices", "total_devices", "high_risk", "flows_24h", "bandwidth",
        "risk_distribution", "threat_summary", "agents_summary", "gateways_summary", "fleet_summary"
    }
    required_summary_keys = {"online", "offline", "total", "degraded", "queue_depth"}

    for idx, payload in enumerate(emitted_payloads):
        assert "stats" in payload, f"Payload {idx} missing 'stats'"
        stats = payload["stats"]
        missing_keys = required_stats_keys - set(stats.keys())
        assert not missing_keys, f"Payload {idx} stats missing keys: {missing_keys}"

        agents = stats["agents_summary"]
        gateways = stats["gateways_summary"]
        fleet = stats["fleet_summary"]

        assert required_summary_keys.issubset(set(agents.keys())), f"Payload {idx} agents_summary keys incomplete"
        assert required_summary_keys.issubset(set(gateways.keys())), f"Payload {idx} gateways_summary keys incomplete"

        for k in required_summary_keys:
            assert type(agents[k]) is int and agents[k] >= 0, f"Payload {idx} agents[{k}] invalid: {agents[k]}"
            assert type(gateways[k]) is int and gateways[k] >= 0, f"Payload {idx} gateways[{k}] invalid: {gateways[k]}"

        assert fleet["total_queue_depth"] == agents["queue_depth"] + gateways["queue_depth"], (
            f"Payload {idx} fleet queue depth mismatch"
        )
        assert fleet["total_degraded"] == agents["degraded"] + gateways["degraded"], (
            f"Payload {idx} fleet degraded mismatch"
        )

    print(f"\n[WS STRESS PASS] Tested {len(emitted_payloads)} WebSocket broadcasts during 15-thread rapid store mutation.")
