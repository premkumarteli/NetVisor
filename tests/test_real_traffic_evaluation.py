import dataclasses
import json
import time
from types import SimpleNamespace
import pytest
from scapy.all import rdpcap

from app.schemas.flow_schema import FlowBase
from app.services.flow_service import flow_service
from app.services.flow_sanitization_service import flow_sanitization_service
from app.engines.registry import EngineRegistry
from collector.flow_manager import FlowManager
from collector.observations import PacketObservation

# Mock cursor and connection to inspect DB inserts without needing live MySQL
class MockCursor:
    def __init__(self):
        self.execute_calls = []

    def execute(self, query, params=None):
        self.execute_calls.append((query, params))

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def close(self):
        pass

class MockConnection:
    def __init__(self):
        self.cursor_obj = MockCursor()

    def cursor(self, dictionary=False):
        return self.cursor_obj

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

@pytest.fixture(autouse=True)
def mock_db_schema_checks(monkeypatch):
    import app.db.session
    import app.services.managed_device_service
    import app.services.session_service
    import app.services.external_endpoint_service
    
    ready_status = {"ready": True, "missing_tables": [], "missing_columns": [], "missing_indexes": []}
    monkeypatch.setattr(app.db.session, "runtime_schema_status", lambda *args, **kwargs: ready_status)
    monkeypatch.setattr(app.db.session, "require_runtime_schema", lambda *args, **kwargs: ready_status)
    
    # Patch direct imports in services
    if hasattr(app.services.managed_device_service, "require_runtime_schema"):
        monkeypatch.setattr(app.services.managed_device_service, "require_runtime_schema", lambda *args, **kwargs: ready_status)
    if hasattr(app.services.session_service, "require_runtime_schema"):
        monkeypatch.setattr(app.services.session_service, "require_runtime_schema", lambda *args, **kwargs: ready_status)
    if hasattr(app.services.external_endpoint_service, "require_runtime_schema"):
        monkeypatch.setattr(app.services.external_endpoint_service, "require_runtime_schema", lambda *args, **kwargs: ready_status)


def run_pcap_through_flow_manager(pcap_path: str) -> list:
    flows = []
    
    def on_flow_expired(summary):
        flows.append(summary)
        
    flow_manager = FlowManager(
        agent_id="AGENT-TEST-PCAP",
        organization_id="org-pcap-test",
        on_flow_expired=on_flow_expired,
        start_worker=False
    )
    
    packets = rdpcap(pcap_path)
    for pkt in packets:
        pkt_time = float(getattr(pkt, "time", time.time()))
        obs = PacketObservation.from_packet(
            pkt,
            source_type="agent",
            observed_at=pkt_time
        )
        if obs:
            flow_manager.update_from_observation(obs)
            
    with flow_manager._lock:
        for key, state in flow_manager._flows.items():
            if state.packet_count > 0:
                summary = flow_manager._build_summary(key, state)
                flows.append(summary)
        flow_manager._flows.clear()
        
    return flows


def test_real_wireguard_traffic_ingestion(monkeypatch):
    """
    Validate that real WireGuard UDP handshake traffic is successfully ingested,
    triggers a vpn_detected finding via the EngineRegistry, and inserts an alert
    in the database detailing the 'WireGuard' vpn_type.
    """
    # Force Mock ASN reputation check to return M247 organization
    from app.engines.vpn.asn_detector import asn_lookup_service
    monkeypatch.setattr(
        asn_lookup_service,
        "lookup_asn_details",
        lambda ip: {"asn": 9009, "organization": "M247 Ltd"}
    )
    
    # 1. Parse raw WireGuard PCAP
    raw_flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/wireguard.pcap")
    assert len(raw_flows) > 0
    
    # 2. Persist batch with Mock Connection
    conn = MockConnection()
    cursor = conn.cursor_obj
    
    flow_service._persist_batch_on_connection(conn, cursor, raw_flows)
    
    # 4. Assert alerts database insertion
    alert_inserts = [
        call for call in cursor.execute_calls
        if "INSERT INTO alerts" in call[0]
    ]
    assert len(alert_inserts) > 0
    
    # Verify breakdown_json parameters
    alert_query, alert_params = alert_inserts[0]
    breakdown_json = alert_params[4]
    breakdown = json.loads(breakdown_json)
    
    assert breakdown["application"] in ("Unknown", "Other")
    assert breakdown["primary_detection"] == "vpn_detected"
    assert "reasons" in breakdown
    assert any("WireGuard" in r for r in breakdown["reasons"])


def test_real_openvpn_traffic_ingestion():
    """
    Validate that real OpenVPN UDP control packets trigger openvpn signature evidence
    and generate a vpn_detected alert inside the database.
    """
    raw_flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/openvpn.pcap")
    assert len(raw_flows) > 0
    
    conn = MockConnection()
    cursor = conn.cursor_obj
    
    flow_service._persist_batch_on_connection(conn, cursor, raw_flows)
    
    alert_inserts = [
        call for call in cursor.execute_calls
        if "INSERT INTO alerts" in call[0]
    ]
    assert len(alert_inserts) > 0
    
    alert_query, alert_params = alert_inserts[0]
    breakdown = json.loads(alert_params[4])
    
    assert breakdown["primary_detection"] == "vpn_detected"
    assert any("OpenVPN" in r for r in breakdown["reasons"])


def test_real_tor_traffic_ingestion(monkeypatch):
    """
    Validate that real Tor outbound packets to a known Tor exit node trigger Tor exit reputation evidence
    and result in a critical/high severity VPN alert.
    """
    # Force live TorExit check to return True for the destination IP
    from app.services.vpn_detector import vpn_detector
    monkeypatch.setattr(
        vpn_detector._tor,
        "is_tor_exit",
        lambda ip: True
    )
    
    raw_flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/tor.pcap")
    assert len(raw_flows) > 0
    
    conn = MockConnection()
    cursor = conn.cursor_obj
    
    flow_service._persist_batch_on_connection(conn, cursor, raw_flows)
    
    alert_inserts = [
        call for call in cursor.execute_calls
        if "INSERT INTO alerts" in call[0]
    ]
    assert len(alert_inserts) > 0
    
    alert_query, alert_params = alert_inserts[0]
    severity = alert_params[2]
    breakdown = json.loads(alert_params[4])
    
    # Standalone VPN detections have a base score of 35, mapping to MEDIUM severity
    assert severity == "MEDIUM"
    assert breakdown["primary_detection"] == "vpn_detected"
    assert any("Tor exit node" in r for r in breakdown["reasons"])


def test_real_benign_traffic_ingestion():
    """
    Validate that standard benign TCP/DNS traffic (standard.pcap) does not trigger any
    threat engine alerts or vpn alerts, writing zero alerts to the database.
    """
    raw_flows = run_pcap_through_flow_manager("tests/fixtures/pcaps/standard.pcap")
    assert len(raw_flows) > 0
    
    sanitized_batch = []
    for flow in raw_flows:
        sanitized = flow_sanitization_service.sanitize_flow(flow, organization_id="org-pcap-test")
        if sanitized:
            sanitized_batch.append(("org-pcap-test", sanitized))
            
    conn = MockConnection()
    cursor = conn.cursor_obj
    
    flow_service._persist_batch_on_connection(conn, cursor, sanitized_batch)
    
    alert_inserts = [
        call for call in cursor.execute_calls
        if "INSERT INTO alerts" in call[0]
    ]
    # Standard benign browsing should never emit alerts
    assert len(alert_inserts) == 0
