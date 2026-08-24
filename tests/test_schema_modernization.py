import pytest
from unittest.mock import MagicMock
from backend.db.session import REQUIRED_SECURITY_TABLES, REQUIRED_SECURITY_COLUMNS, REQUIRED_RUNTIME_TABLES
from backend.services.alert_service import alert_service
from backend.utils.partition_manager import partition_manager

def test_schema_definitions_include_modernized_tables():
    assert "organizations" in REQUIRED_SECURITY_TABLES
    assert "risk_events" in REQUIRED_SECURITY_TABLES
    assert "device_ip_history" in REQUIRED_SECURITY_TABLES
    assert "organizations" in REQUIRED_RUNTIME_TABLES
    assert "risk_events" in REQUIRED_RUNTIME_TABLES
    assert "alerts" in REQUIRED_SECURITY_COLUMNS
    assert "alert_type" in REQUIRED_SECURITY_COLUMNS["alerts"]

def test_partition_manager_ddl_generation():
    ddl = partition_manager.generate_monthly_partition_ddl(
        table_name="flow_logs",
        column_name="start_time",
        months_ahead=3
    )
    assert "ALTER TABLE flow_logs" in ddl
    assert "PARTITION BY RANGE (TO_DAYS(start_time))" in ddl
    assert "p_future VALUES LESS THAN MAXVALUE" in ddl

def test_alert_service_risk_events_mocked():
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.lastrowid = 101
    mock_cursor.fetchall.return_value = [
        {
            "id": 101,
            "organization_id": "test-org",
            "device_id": "dev-001",
            "risk_type": "VPN_DETECTED",
            "confidence": 0.95,
            "score": 40,
            "evidence_json": '{"asn": "AS1234"}',
            "timestamp": "2026-08-23 12:00:00"
        }
    ]
    mock_conn.cursor.return_value = mock_cursor

    # Test record_risk_event
    event_id = alert_service.record_risk_event(
        mock_conn,
        organization_id="test-org",
        device_id="dev-001",
        risk_type="VPN_DETECTED",
        score=40,
        confidence=0.95,
        evidence_json={"asn": "AS1234"}
    )
    assert event_id == 101
    assert mock_conn.commit.called

    # Test get_risk_events
    events = alert_service.get_risk_events(
        mock_conn,
        organization_id="test-org",
        device_id="dev-001"
    )
    assert len(events) == 1
    assert events[0]["risk_type"] == "VPN_DETECTED"
    assert events[0]["evidence_json"] == {"asn": "AS1234"}
