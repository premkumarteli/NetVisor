"""
Unit and API integration tests for /api/v1/dashboard/overview endpoint
and fleet observability summaries (Requirement R1).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.dependencies import require_org_admin, get_current_user
from backend.services.agent_service import agent_service
from backend.services.gateway_service import gateway_service
from backend.services.live_telemetry_store import live_telemetry_store


@pytest.fixture
def authenticated_client():
    """Fixture providing FastAPI TestClient authenticated as an Organization Admin."""
    mock_user = {
        "user_id": "test-admin-overview-api",
        "organization_id": "org-overview-test",
        "role": "org_admin",
        "username": "admin_overview",
        "email": "admin_overview@example.com",
    }

    app.dependency_overrides[require_org_admin] = lambda: mock_user
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def test_dashboard_overview_endpoint_returns_200_and_required_keys(authenticated_client):
    """
    Verify GET /api/v1/dashboard/overview returns 200 OK and includes
    'agents_summary', 'gateways_summary', and 'fleet_summary'.
    """
    response = authenticated_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert isinstance(data, dict), "Response must be a JSON object"

    assert "agents_summary" in data, "Missing 'agents_summary' key"
    assert "gateways_summary" in data, "Missing 'gateways_summary' key"
    assert "fleet_summary" in data, "Missing 'fleet_summary' key"

    expected_summary_keys = {"online", "offline", "total", "degraded", "queue_depth"}

    agents_summary = data["agents_summary"]
    gateways_summary = data["gateways_summary"]

    assert expected_summary_keys.issubset(set(agents_summary.keys())), (
        f"agents_summary missing keys: {expected_summary_keys - set(agents_summary.keys())}"
    )
    assert expected_summary_keys.issubset(set(gateways_summary.keys())), (
        f"gateways_summary missing keys: {expected_summary_keys - set(gateways_summary.keys())}"
    )

    for k in expected_summary_keys:
        assert isinstance(agents_summary[k], int), f"agents_summary[{k}] must be int"
        assert isinstance(gateways_summary[k], int), f"gateways_summary[{k}] must be int"
        assert agents_summary[k] >= 0
        assert gateways_summary[k] >= 0

    fleet_summary = data["fleet_summary"]
    assert "total_queue_depth" in fleet_summary
    assert "total_degraded" in fleet_summary
    assert fleet_summary["total_queue_depth"] == agents_summary["queue_depth"] + gateways_summary["queue_depth"]
    assert fleet_summary["total_degraded"] == agents_summary["degraded"] + gateways_summary["degraded"]


def test_agent_service_get_agents_summary_empty(authenticated_client):
    """
    Verify agent_service.get_agents_summary returns valid structure even with mock connection.
    """
    from unittest.mock import MagicMock
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []
    mock_conn.cursor.return_value = mock_cursor

    summary = agent_service.get_agents_summary(mock_conn, organization_id="test-org")
    assert isinstance(summary, dict)
    assert summary == {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}


def test_gateway_service_get_gateways_summary_empty(authenticated_client):
    """
    Verify gateway_service.get_gateways_summary returns valid structure when DB query is empty.
    """
    from unittest.mock import MagicMock
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []
    mock_conn.cursor.return_value = mock_cursor

    summary = gateway_service.get_gateways_summary(mock_conn, organization_id="test-org")
    assert isinstance(summary, dict)
    assert summary == {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}


def test_live_telemetry_store_incorporates_summaries():
    """
    Verify live_telemetry_store.get_overview_stats includes agents_summary and gateways_summary.
    """
    stats = live_telemetry_store.get_overview_stats("test-org-telemetry")
    assert "agents_summary" in stats
    assert "gateways_summary" in stats
    assert "fleet_summary" in stats
    assert stats["agents_summary"]["online"] >= 0
    assert stats["gateways_summary"]["online"] >= 0
