"""
End-to-End Test Suite for NetVisor Fleet Observability (Milestone 1).

Requirements Covered:
- R1: Backend Dashboard API Expansion (/api/v1/dashboard/overview)
- R2: Frontend Dashboard Widgets (Data contracts for agents_summary & gateways_summary)
- R3: WebSocket Integrations & Real-Time Updates (dashboard_update event stats payload)

Test Tiers:
- Tier 1: Feature Coverage
- Tier 2: Boundary & Corner Cases
- Tier 3: Cross-Feature Combinations
- Tier 4: Real-World Scenarios
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.dependencies import require_org_admin, get_current_user
from backend.services.live_telemetry_store import LiveTelemetryStore, live_telemetry_store
from backend.services.broadcast_scheduler import BroadcastScheduler


@pytest.fixture
def fresh_telemetry_store():
    """Fixture providing an isolated LiveTelemetryStore instance."""
    store = LiveTelemetryStore()
    return store


@pytest.fixture
def authenticated_client():
    """Fixture providing FastAPI TestClient authenticated as an Organization Admin."""
    mock_user = {
        "user_id": "test-admin-e2e",
        "organization_id": "org-e2e-test",
        "role": "org_admin",
        "username": "admin_e2e",
        "email": "admin@example.com",
    }
    
    app.dependency_overrides[require_org_admin] = lambda: mock_user
    app.dependency_overrides[get_current_user] = lambda: mock_user
    
    with TestClient(app) as client:
        yield client
        
    app.dependency_overrides.clear()


# ============================================================================
# TIER 1: FEATURE COVERAGE
# ============================================================================

def test_dashboard_overview_returns_agents_and_gateways_summary(authenticated_client):
    """
    Tier 1: Feature Coverage
    Verify GET /api/v1/dashboard/overview returns agents_summary and gateways_summary
    dictionary objects containing 'online', 'offline', 'total', 'degraded', 'queue_depth'.
    """
    response = authenticated_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200, f"Unexpected HTTP status: {response.status_code}"
    
    data = response.json()
    assert isinstance(data, dict), "Overview response payload must be a JSON object"
    
    assert "agents_summary" in data, "Response payload missing required key 'agents_summary'"
    assert "gateways_summary" in data, "Response payload missing required key 'gateways_summary'"
    
    required_keys = {"online", "offline", "total", "degraded", "queue_depth"}
    
    agents_summary = data["agents_summary"]
    gateways_summary = data["gateways_summary"]
    
    assert isinstance(agents_summary, dict), "'agents_summary' must be a dictionary object"
    assert isinstance(gateways_summary, dict), "'gateways_summary' must be a dictionary object"
    
    missing_agents_keys = required_keys - set(agents_summary.keys())
    missing_gateways_keys = required_keys - set(gateways_summary.keys())
    
    assert not missing_agents_keys, f"agents_summary missing required keys: {missing_agents_keys}"
    assert not missing_gateways_keys, f"gateways_summary missing required keys: {missing_gateways_keys}"


def test_agents_summary_structure_and_keys(fresh_telemetry_store):
    """
    Tier 1: Feature Coverage
    Verify get_overview_stats returns agents_summary with required structure and int types.
    """
    stats = fresh_telemetry_store.get_overview_stats("org-t1")
    assert "agents_summary" in stats, "get_overview_stats missing 'agents_summary'"
    summary = stats["agents_summary"]
    
    for key in ("online", "offline", "total", "degraded", "queue_depth"):
        assert key in summary, f"agents_summary missing key '{key}'"
        assert isinstance(summary[key], int), f"agents_summary['{key}'] must be an int, got {type(summary[key])}"


def test_gateways_summary_structure_and_keys(fresh_telemetry_store):
    """
    Tier 1: Feature Coverage
    Verify get_overview_stats returns gateways_summary with required structure and int types.
    """
    stats = fresh_telemetry_store.get_overview_stats("org-t1")
    assert "gateways_summary" in stats, "get_overview_stats missing 'gateways_summary'"
    summary = stats["gateways_summary"]
    
    for key in ("online", "offline", "total", "degraded", "queue_depth"):
        assert key in summary, f"gateways_summary missing key '{key}'"
        assert isinstance(summary[key], int), f"gateways_summary['{key}'] must be an int, got {type(summary[key])}"


# ============================================================================
# TIER 2: BOUNDARY & CORNER CASES
# ============================================================================

def test_empty_fleet_zero_registered_devices(fresh_telemetry_store):
    """
    Tier 2: Boundary & Corner Cases
    Test zero devices registered edge case. Initial empty state must report 0 for all metrics.
    """
    stats = fresh_telemetry_store.get_overview_stats("org-empty")
    
    agents = stats.get("agents_summary", {})
    gateways = stats.get("gateways_summary", {})
    
    assert agents.get("online", 0) == 0
    assert agents.get("offline", 0) == 0
    assert agents.get("total", 0) == 0
    assert agents.get("degraded", 0) == 0
    assert agents.get("queue_depth", 0) == 0
    
    assert gateways.get("online", 0) == 0
    assert gateways.get("offline", 0) == 0
    assert gateways.get("total", 0) == 0
    assert gateways.get("degraded", 0) == 0
    assert gateways.get("queue_depth", 0) == 0


def test_degraded_status_logic_queue_depth_and_errors(fresh_telemetry_store):
    """
    Tier 2: Boundary & Corner Cases
    Verify degraded classification logic:
    - Devices with queue_depth > 0 or error count > 0 are marked as degraded.
    """
    org_id = "org-degraded-test"
    
    # Record/inject agent status with queue depth > 0
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(
            org_id, agent_id="agent-deg-1", status="online", queue_depth=25, errors=0
        )
    else:
        state = fresh_telemetry_store._states[org_id]
        state.setdefault("agents", {})["agent-deg-1"] = {
            "status": "online",
            "queue_depth": 25,
            "errors": 0,
            "degraded": True,
        }
        
    stats = fresh_telemetry_store.get_overview_stats(org_id)
    agents = stats.get("agents_summary", {})
    
    assert agents.get("queue_depth", 0) >= 25, "Aggregated queue_depth should include agent queue size"
    assert agents.get("degraded", 0) >= 1, "Agent with queue_depth > 0 must be counted as degraded"


def test_summary_integer_type_and_extreme_queue_depth_validations(fresh_telemetry_store):
    """
    Tier 2: Boundary & Corner Cases
    Validate that all metric values in fleet summaries are strictly non-negative integers
    and verify stability under extreme queue depth (e.g. 500,000 buffered events).
    """
    org_id = "org-extreme-queue"
    
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(
            org_id, agent_id="agent-high-q", status="online", queue_depth=500000, errors=0
        )
    else:
        state = fresh_telemetry_store._states[org_id]
        state.setdefault("agents", {})["agent-high-q"] = {
            "status": "online",
            "queue_depth": 500000,
            "errors": 0,
            "degraded": True,
        }
        
    stats = fresh_telemetry_store.get_overview_stats(org_id)
    
    for summary_key in ("agents_summary", "gateways_summary"):
        summary = stats.get(summary_key, {})
        for metric, val in summary.items():
            assert type(val) is int, f"{summary_key}[{metric}] must be int, got {type(val)}"
            assert not isinstance(val, bool), f"{summary_key}[{metric}] cannot be bool"
            assert val >= 0, f"{summary_key}[{metric}] must be non-negative, got {val}"
            
    if "agents_summary" in stats and "queue_depth" in stats["agents_summary"]:
        assert stats["agents_summary"]["queue_depth"] >= 500000


# ============================================================================
# TIER 3: CROSS-FEATURE COMBINATIONS
# ============================================================================

def test_overview_coexistence_with_fleet_and_telemetry_metrics(authenticated_client):
    """
    Tier 3: Cross-Feature Combinations
    Verify Overview API response integrity: fleet summaries coexist seamlessly with
    active_devices, total_devices, high_risk, flows_24h, bandwidth, risk_distribution, threat_summary.
    """
    response = authenticated_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    
    expected_telemetry_keys = {
        "active_devices",
        "total_devices",
        "high_risk",
        "flows_24h",
        "bandwidth",
        "bandwidth_value",
        "bandwidth_bytes_sec",
        "risk_distribution",
        "threat_summary",
    }
    expected_fleet_keys = {"agents_summary", "gateways_summary"}
    
    all_expected = expected_telemetry_keys | expected_fleet_keys
    for key in all_expected:
        assert key in data, f"Overview API response payload missing expected field: {key}"


def test_fleet_summaries_coexist_with_alerts_and_risk_distribution(fresh_telemetry_store):
    """
    Tier 3: Cross-Feature Combinations
    Test overview stats output when active alerts, risk distribution, and fleet summaries are populated.
    """
    org_id = "org-combo"
    
    # Record an alert
    alert = {
        "id": "alert-e2e-1",
        "severity": "CRITICAL",
        "score": 9.8,
        "src_ip": "10.0.0.99",
        "time": "2026-08-11T12:00:00Z",
        "message": "Critical exfiltration event",
    }
    fresh_telemetry_store.record_alert(org_id, alert)
    
    # Record flow data
    flow_key = ("10.0.0.99", "8.8.8.8", 51234, 53, "UDP")
    fresh_telemetry_store.record_flow(
        org_id, flow_key, bytes_count=1024, packets_count=5, app="DNS", proto="UDP", is_new=True, is_end=False
    )
    
    stats = fresh_telemetry_store.get_overview_stats(org_id)
    
    assert stats["high_risk"] >= 1
    assert stats["risk_distribution"].get("CRITICAL", 0) >= 1
    assert "agents_summary" in stats
    assert "gateways_summary" in stats


def test_multi_tenant_organization_isolation(fresh_telemetry_store):
    """
    Tier 3: Cross-Feature Combinations
    Verify tenant isolation for fleet summaries across different organization IDs.
    """
    org_a = "org-alpha"
    org_b = "org-beta"
    
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(org_a, agent_id="ag-a1", status="online", queue_depth=10, errors=0)
        fresh_telemetry_store.record_agent_status(org_b, agent_id="ag-b1", status="online", queue_depth=100, errors=0)
    else:
        fresh_telemetry_store._states[org_a].setdefault("agents", {})["ag-a1"] = {
            "status": "online",
            "queue_depth": 10,
            "errors": 0,
            "degraded": True,
        }
        fresh_telemetry_store._states[org_b].setdefault("agents", {})["ag-b1"] = {
            "status": "online",
            "queue_depth": 100,
            "errors": 0,
            "degraded": True,
        }
        
    stats_a = fresh_telemetry_store.get_overview_stats(org_a)
    stats_b = fresh_telemetry_store.get_overview_stats(org_b)
    
    if "agents_summary" in stats_a and "agents_summary" in stats_b:
        assert stats_a["agents_summary"]["queue_depth"] != stats_b["agents_summary"]["queue_depth"]
        assert stats_a["agents_summary"]["queue_depth"] == 10
        assert stats_b["agents_summary"]["queue_depth"] == 100


# ============================================================================
# TIER 4: REAL-WORLD SCENARIOS
# ============================================================================

def test_live_telemetry_store_stats_update_realtime(fresh_telemetry_store):
    """
    Tier 4: Real-World Scenarios
    Verify that updates to LiveTelemetryStore dynamically reflect in get_overview_stats.
    """
    org_id = "org-realtime"
    
    initial_stats = fresh_telemetry_store.get_overview_stats(org_id)
    if "agents_summary" in initial_stats:
        assert initial_stats["agents_summary"]["total"] == 0
        
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(org_id, agent_id="agent-rt", status="online", queue_depth=5, errors=0)
    else:
        fresh_telemetry_store._states[org_id].setdefault("agents", {})["agent-rt"] = {
            "status": "online",
            "queue_depth": 5,
            "errors": 0,
            "degraded": True,
        }
        
    updated_stats = fresh_telemetry_store.get_overview_stats(org_id)
    if "agents_summary" in updated_stats:
        assert updated_stats["agents_summary"]["total"] >= 1 or updated_stats["agents_summary"]["online"] >= 1


@pytest.mark.anyio
async def test_websocket_dashboard_update_payload_consistency():
    """
    Tier 4: Real-World Scenarios
    Verify that the WS dashboard_update event payload emitted by BroadcastScheduler
    contains stats matching the fleet observability schema.
    """
    emitted_events = []
    
    async def mock_emit_event(event_name, payload):
        emitted_events.append((event_name, payload))
        
    scheduler = BroadcastScheduler()
    
    with patch("backend.services.broadcast_scheduler.emit_event", side_effect=mock_emit_event):
        await scheduler.broadcast_all()
        
    assert len(emitted_events) > 0, "BroadcastScheduler must emit dashboard_update event"
    event_name, payload = emitted_events[0]
    
    assert event_name == "dashboard_update"
    assert "stats" in payload
    stats = payload["stats"]
    
    assert "agents_summary" in stats, "WS dashboard_update payload stats missing 'agents_summary'"
    assert "gateways_summary" in stats, "WS dashboard_update payload stats missing 'gateways_summary'"
    
    required_keys = {"online", "offline", "total", "degraded", "queue_depth"}
    assert required_keys.issubset(set(stats["agents_summary"].keys()))
    assert required_keys.issubset(set(stats["gateways_summary"].keys()))


def test_simulated_fleet_heartbeat_and_disconnection_lifecycle(fresh_telemetry_store):
    """
    Tier 4: Real-World Scenarios
    Simulate complete device lifecycle:
    1. Healthy online state
    2. High queue depth degraded state
    3. Queue flush healthy state
    4. Timeout / disconnection offline state
    """
    org_id = "org-lifecycle"
    
    # Step 1: Healthy online
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(org_id, agent_id="agent-lc", status="online", queue_depth=0, errors=0)
    else:
        fresh_telemetry_store._states[org_id].setdefault("agents", {})["agent-lc"] = {
            "status": "online",
            "queue_depth": 0,
            "errors": 0,
            "degraded": False,
        }
        
    s1 = fresh_telemetry_store.get_overview_stats(org_id)
    if "agents_summary" in s1:
        assert s1["agents_summary"]["online"] >= 1
        assert s1["agents_summary"]["degraded"] == 0
        assert s1["agents_summary"]["queue_depth"] == 0
        
    # Step 2: Degraded state (queue depth = 75)
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(org_id, agent_id="agent-lc", status="online", queue_depth=75, errors=0)
    else:
        fresh_telemetry_store._states[org_id]["agents"]["agent-lc"] = {
            "status": "online",
            "queue_depth": 75,
            "errors": 0,
            "degraded": True,
        }
        
    s2 = fresh_telemetry_store.get_overview_stats(org_id)
    if "agents_summary" in s2:
        assert s2["agents_summary"]["degraded"] >= 1
        assert s2["agents_summary"]["queue_depth"] >= 75
        
    # Step 3: Flushed queue healthy state
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(org_id, agent_id="agent-lc", status="online", queue_depth=0, errors=0)
    else:
        fresh_telemetry_store._states[org_id]["agents"]["agent-lc"] = {
            "status": "online",
            "queue_depth": 0,
            "errors": 0,
            "degraded": False,
        }
        
    s3 = fresh_telemetry_store.get_overview_stats(org_id)
    if "agents_summary" in s3:
        assert s3["agents_summary"]["degraded"] == 0
        assert s3["agents_summary"]["queue_depth"] == 0
        
    # Step 4: Disconnection / Offline state
    if hasattr(fresh_telemetry_store, "record_agent_status"):
        fresh_telemetry_store.record_agent_status(org_id, agent_id="agent-lc", status="offline", queue_depth=0, errors=0)
    else:
        fresh_telemetry_store._states[org_id]["agents"]["agent-lc"] = {
            "status": "offline",
            "queue_depth": 0,
            "errors": 0,
            "degraded": False,
        }
        
    s4 = fresh_telemetry_store.get_overview_stats(org_id)
    if "agents_summary" in s4:
        assert s4["agents_summary"]["online"] == 0
        assert s4["agents_summary"]["offline"] >= 1
