"""
Adversarial Stress and Boundary Test Suite for Milestone 2 Fleet Observability Backend.

Tested Components:
- backend.services.agent_service.AgentService.get_agents_summary
- backend.services.gateway_service.GatewayService.get_gateways_summary
- backend.services.live_telemetry_store.LiveTelemetryStore.get_overview_stats
- /api/v1/dashboard/overview REST API
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.dependencies import require_org_admin, get_current_user
from backend.services.agent_service import agent_service
from backend.services.gateway_service import gateway_service
from backend.services.live_telemetry_store import live_telemetry_store, LiveTelemetryStore


@pytest.fixture
def mock_db_conn():
    """Returns a mocked database connection and cursor."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    return conn, cursor


@pytest.fixture
def authenticated_client():
    mock_user = {
        "user_id": "challenger-admin",
        "organization_id": "org-challenger",
        "role": "org_admin",
        "username": "challenger",
        "email": "challenger@example.com",
    }
    app.dependency_overrides[require_org_admin] = lambda: mock_user
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


# ============================================================================
# 1. BOUNDARY: ZERO DEVICES & EMPTY DB TABLES
# ============================================================================

def test_zero_devices_empty_tables(mock_db_conn):
    conn, cursor = mock_db_conn
    cursor.fetchall.return_value = []

    # Agent Summary
    agent_summary = agent_service.get_agents_summary(conn, organization_id="org-empty")
    assert agent_summary == {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}

    # Gateway Summary
    gateway_summary = gateway_service.get_gateways_summary(conn, organization_id="org-empty")
    assert gateway_summary == {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}

    # Overview Stats with empty DB
    stats = live_telemetry_store.get_overview_stats("org-empty", db_conn=conn)
    assert stats["agents_summary"] == {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}
    assert stats["gateways_summary"] == {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}
    assert stats["fleet_summary"] == {"total_queue_depth": 0, "total_degraded": 0}


# ============================================================================
# 2. BOUNDARY: NULL, MISSING, AND MALFORMED FIELDS IN DB
# ============================================================================

def test_agent_summary_null_and_malformed_fields(mock_db_conn):
    conn, cursor = mock_db_conn
    now_dt = datetime.now(timezone.utc)

    rows = [
        # Row 1: Completely null/empty values
        {
            "agent_id": "ag-null-1",
            "name": None,
            "hostname": None,
            "ip_address": None,
            "os_family": None,
            "version": None,
            "inspection_enabled": None,
            "inspection_status": None,
            "inspection_proxy_running": None,
            "inspection_ca_installed": None,
            "inspection_browsers_json": None,
            "inspection_last_error": None,
            "inspection_metrics_json": None,
            "organization_id": None,
            "last_seen": None,
            "cpu_usage": None,
            "ram_usage": None,
            "integrity_status": None,
            "manifest_hash": None,
        },
        # Row 2: Corrupted/invalid JSON in inspection_metrics_json, online
        {
            "agent_id": "ag-badjson-2",
            "hostname": "host-2",
            "last_seen": now_dt,
            "inspection_metrics_json": "{invalid json syntax",
            "integrity_status": "verified",
        },
        # Row 3: Online, valid metrics, verified integrity, zero errors/queues (Healthy)
        {
            "agent_id": "ag-healthy-3",
            "hostname": "host-3",
            "last_seen": now_dt,
            "inspection_metrics_json": '{"queue_size": 0, "upload_failures": 0}',
            "integrity_status": "verified",
        },
        # Row 4: Online, but unverified integrity status (should be degraded)
        {
            "agent_id": "ag-unverified-4",
            "hostname": "host-4",
            "last_seen": now_dt,
            "inspection_metrics_json": '{"queue_size": 0}',
            "integrity_status": "tampered",
        },
    ]

    # Execute fetch_agents call mock
    def mock_execute(query, params=()):
        pass

    cursor.execute.side_effect = mock_execute
    cursor.fetchall.side_effect = [rows, []]  # 1st for fetch_agents, 2nd for fetch_device_counts

    summary = agent_service.get_agents_summary(conn, organization_id="org-test")
    assert summary["total"] == 4
    assert summary["offline"] == 1  # ag-null-1 has last_seen=None -> Offline
    assert summary["online"] == 3   # ag-badjson-2, ag-healthy-3, ag-unverified-4 -> Online
    # Degraded check for online agents:
    # ag-badjson-2 has integrity_status="verified", metrics parsing returns {}, queue=0, errors=None -> healthy
    # ag-healthy-3 has verified, queue 0 -> healthy
    # ag-unverified-4 has integrity_status="tampered" (!= verified) -> degraded
    assert summary["degraded"] == 1


def test_gateway_summary_null_and_malformed_fields(mock_db_conn):
    conn, cursor = mock_db_conn
    now_dt = datetime.now(timezone.utc)

    rows = [
        # Row 1: Nulls everywhere
        {
            "gateway_id": "gw-null-1",
            "organization_id": None,
            "hostname": None,
            "capture_mode": None,
            "cert_status": None,
            "last_seen": None,
            "queue_depth": None,
            "flow_ingest_errors": None,
        },
        # Row 2: Online, string timestamp, inactive cert
        {
            "gateway_id": "gw-inactive-cert",
            "hostname": "gw-2",
            "cert_status": "expired",
            "last_seen": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "queue_depth": 0,
            "flow_ingest_errors": 0,
        },
        # Row 3: Online, future last_seen timestamp (clock skew scenario)
        {
            "gateway_id": "gw-future-ts",
            "hostname": "gw-3",
            "cert_status": "active",
            "last_seen": now_dt + timedelta(minutes=5),
            "queue_depth": 10,
            "flow_ingest_errors": 0,
        },
        # Row 4: Online, invalid format timestamp string -> should evaluate to None (offline)
        {
            "gateway_id": "gw-invalid-ts",
            "hostname": "gw-4",
            "cert_status": "active",
            "last_seen": "INVALID-TIMESTAMP-STRING",
            "queue_depth": 5,
            "flow_ingest_errors": 2,
        },
    ]

    cursor.fetchall.return_value = rows

    summary = gateway_service.get_gateways_summary(conn, organization_id="org-test")
    assert summary["total"] == 4
    # gw-null-1 (last_seen None) -> offline
    # gw-invalid-ts (last_seen bad str) -> offline
    # gw-inactive-cert (last_seen now) -> online
    # gw-future-ts (last_seen future) -> online (age=0)
    assert summary["online"] == 2
    assert summary["offline"] == 2
    # Degraded check for online gateways:
    # gw-inactive-cert: cert_status "expired" != "active" -> degraded
    # gw-future-ts: queue_depth 10 > 0 -> degraded
    assert summary["degraded"] == 2
    assert summary["queue_depth"] == 15  # 0 + 10 + 5 + 0 = 15 total queue depth across all gateways


# ============================================================================
# 3. BOUNDARY: EXTREME QUEUE DEPTHS & HIGH SCALABILITY
# ============================================================================

def test_extreme_queue_depth_aggregation(mock_db_conn):
    conn, cursor = mock_db_conn
    now_dt = datetime.now(timezone.utc)

    # 1,000,000,000 queue depth for agent
    agent_rows = [
        {
            "agent_id": "ag-huge-q",
            "hostname": "ag-huge",
            "last_seen": now_dt,
            "inspection_metrics_json": '{"upload_health": {"queue_depth": 1000000000}}',
            "integrity_status": "verified",
        }
    ]

    # 2,500,000,000 queue depth for gateway
    gateway_rows = [
        {
            "gateway_id": "gw-huge-q",
            "hostname": "gw-huge",
            "cert_status": "active",
            "last_seen": now_dt,
            "queue_depth": 2500000000,
            "flow_ingest_errors": 0,
        }
    ]

    def mock_agent_execute(query, params=()):
        pass

    cursor.execute.side_effect = mock_agent_execute
    cursor.fetchall.side_effect = [agent_rows, []]

    ag_summary = agent_service.get_agents_summary(conn, organization_id="org-extreme")
    assert ag_summary["queue_depth"] == 1000000000

    cursor.fetchall.side_effect = None
    cursor.fetchall.return_value = gateway_rows
    gw_summary = gateway_service.get_gateways_summary(conn, organization_id="org-extreme")
    assert gw_summary["queue_depth"] == 2500000000

    # Test LiveTelemetryStore combines them
    cursor.fetchall.side_effect = [agent_rows, [], gateway_rows]
    stats = live_telemetry_store.get_overview_stats("org-extreme", db_conn=conn)
    assert stats["fleet_summary"]["total_queue_depth"] == 3500000000


# ============================================================================
# 4. BOUNDARY: PLACEHOLDER AGENT EXCLUSION
# ============================================================================

def test_placeholder_agents_exclusion_in_summary(mock_db_conn):
    conn, cursor = mock_db_conn
    now_dt = datetime.now(timezone.utc)

    rows = [
        # Placeholders
        {"agent_id": "AGENT-TEST-001", "hostname": "host-1", "last_seen": now_dt},
        {"agent_id": "TEST-AGENT-X", "hostname": "host-2", "last_seen": now_dt},
        {"agent_id": "DEMO-123", "hostname": "host-3", "last_seen": now_dt},
        {"agent_id": "ag-real-1", "name": "SAMPLE-AGENT", "hostname": "host-4", "last_seen": now_dt},
        {"agent_id": "ag-real-2", "name": "Real", "hostname": "demo", "last_seen": now_dt},
        # Real Agent
        {"agent_id": "ag-prod-001", "name": "Prod Agent 1", "hostname": "prod-server-01", "last_seen": now_dt, "integrity_status": "verified"},
    ]

    cursor.fetchall.side_effect = [rows, []]

    summary = agent_service.get_agents_summary(conn, organization_id="org-prod")
    # All 5 placeholder rows should be filtered out, leaving only ag-prod-001
    assert summary["total"] == 1
    assert summary["online"] == 1


# ============================================================================
# 5. BOUNDARY: ORGANIZATION ID & MULTI-TENANCY PARAMETERS
# ============================================================================

@pytest.mark.parametrize("org_id", [
    None,
    "",
    "default",
    "org-123-abc",
    "' OR '1'='1",
    "org_with_special_chars_!@#$%^&*()",
])
def test_organization_id_safety_and_handling(mock_db_conn, org_id):
    conn, cursor = mock_db_conn
    cursor.fetchall.return_value = []

    # Should execute safely without raising exceptions or breaking SQL
    ag_sum = agent_service.get_agents_summary(conn, organization_id=org_id)
    gw_sum = gateway_service.get_gateways_summary(conn, organization_id=org_id)
    stats = live_telemetry_store.get_overview_stats(org_id, db_conn=conn)

    assert isinstance(ag_sum, dict)
    assert isinstance(gw_sum, dict)
    assert isinstance(stats, dict)


# ============================================================================
# 6. BOUNDARY: ONLINE WINDOW SECONDS EDGE CASES
# ============================================================================

def test_online_window_seconds_boundary(mock_db_conn):
    conn, cursor = mock_db_conn
    now_dt = datetime.now(timezone.utc)
    seen_15s_ago = now_dt - timedelta(seconds=15)

    rows = [
        {"agent_id": "ag-15s", "hostname": "host-15s", "last_seen": seen_15s_ago, "integrity_status": "verified"}
    ]

    cursor.fetchall.side_effect = [rows, []]

    # With window=20 (default): 15s <= 20s -> Online
    sum_20 = agent_service.get_agents_summary(conn, organization_id="org-win", online_window_seconds=20)
    assert sum_20["online"] == 1

    cursor.fetchall.side_effect = [rows, []]

    # With window=10: 15s > 10s -> Offline
    sum_10 = agent_service.get_agents_summary(conn, organization_id="org-win", online_window_seconds=10)
    assert sum_10["online"] == 0
    assert sum_10["offline"] == 1


# ============================================================================
# 7. INTEGRATION: REST ENDPOINT UNDER DEGRADED STATUS
# ============================================================================

def test_rest_overview_response_degraded_structure(authenticated_client):
    response = authenticated_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()

    assert "agents_summary" in data
    assert "gateways_summary" in data
    assert "fleet_summary" in data

    # Verify return types for all metrics in summary blocks
    for block_name in ("agents_summary", "gateways_summary"):
        block = data[block_name]
        for field in ("online", "offline", "total", "degraded", "queue_depth"):
            assert field in block
            assert type(block[field]) is int
            assert block[field] >= 0

    fleet = data["fleet_summary"]
    assert type(fleet["total_queue_depth"]) is int
    assert type(fleet["total_degraded"]) is int
    assert fleet["total_queue_depth"] == data["agents_summary"]["queue_depth"] + data["gateways_summary"]["queue_depth"]
    assert fleet["total_degraded"] == data["agents_summary"]["degraded"] + data["gateways_summary"]["degraded"]
