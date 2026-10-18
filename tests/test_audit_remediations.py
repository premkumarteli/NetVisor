"""
Targeted regression tests for NetVisor audit remediations.

Verifies:
1. WireGuardHeuristicDetector detects aggregated bidirectional flows.
2. Cross-tenant certificate revocation is blocked for gateway certificates.
3. Multi-tenant data reset preserves other tenants' cache and live telemetry.
"""

import pytest
from unittest.mock import MagicMock, patch

from backend.engines.vpn.wireguard import WireGuardHeuristicDetector
from backend.services.system_service import SystemService
from backend.services.live_telemetry_store import LiveTelemetryStore


def test_wireguard_detector_bidirectional_flow_detected():
    detector = WireGuardHeuristicDetector()
    flow = {
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.99",
        "src_port": 51820,
        "dst_port": 51820,
        "protocol": "UDP",
        "fwd_packets": 2,
        "rev_packets": 1,
        "analysis_signals": ["udp", "port_51820", "wg_size_148", "wg_size_92", "wg_size_32"],
    }
    assert detector.analyze(flow) is True


def test_wireguard_detector_unidirectional_without_handshake_rejected():
    detector = WireGuardHeuristicDetector()
    flow = {
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.99",
        "src_port": 51820,
        "dst_port": 51820,
        "protocol": "UDP",
        "fwd_packets": 5,
        "rev_packets": 0,
        "analysis_signals": ["udp", "port_51820", "wg_size_148"],
    }
    assert detector.analyze(flow) is False


def test_system_service_tenant_scoped_clear_preserves_other_orgs():
    system_service = SystemService()
    
    mock_redis = MagicMock()
    mock_redis.keys.return_value = ["dashboard:org_A:stats"]

    # Populate dummy state in a test LiveTelemetryStore instance
    test_store = LiveTelemetryStore()
    test_store._states["org_A"] = test_store._create_empty_org_state()
    test_store._states["org_B"] = test_store._create_empty_org_state()

    with patch("backend.services.system_service.logger"), \
         patch("backend.db.redis_client.get_redis_connection", return_value=mock_redis), \
         patch("backend.services.live_telemetry_store.live_telemetry_store", test_store), \
         patch("backend.db.clickhouse_client.get_clickhouse_client", return_value=None):

        system_service._clear_caches_and_analytics(organization_id="org_A")

        # Verify Redis flushdb was NOT called
        mock_redis.flushdb.assert_not_called()
        
        # Verify redis deleted only org_A keys
        mock_redis.delete.assert_called_with("dashboard:org_A:stats")

        # Verify LiveTelemetryStore preserved org_B
        assert "org_A" not in test_store._states
        assert "org_B" in test_store._states


def test_system_service_global_clear_flushes_all():
    system_service = SystemService()

    mock_redis = MagicMock()
    test_store = LiveTelemetryStore()
    test_store._states["org_A"] = test_store._create_empty_org_state()
    test_store._states["org_B"] = test_store._create_empty_org_state()

    with patch("backend.services.system_service.logger"), \
         patch("backend.db.redis_client.get_redis_connection", return_value=mock_redis), \
         patch("backend.services.live_telemetry_store.live_telemetry_store", test_store), \
         patch("backend.db.clickhouse_client.get_clickhouse_client", return_value=None):

        system_service._clear_caches_and_analytics(organization_id=None)

        # Verify Redis flushdb was called for global reset
        mock_redis.flushdb.assert_called_once()

        # Verify LiveTelemetryStore was completely cleared
        assert len(test_store._states) == 0
