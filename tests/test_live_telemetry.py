import asyncio
import time
import pytest
from unittest.mock import MagicMock, AsyncMock

from app.services.live_telemetry_store import LiveTelemetryStore
from app.services.event_dispatcher import EventDispatcher, flow_ingestion_queue
from app.services.broadcast_scheduler import BroadcastScheduler

def test_live_telemetry_store_flow_recording():
    store = LiveTelemetryStore()
    
    # Check initial stats
    stats = store.get_overview_stats("org-test")
    assert stats["active_devices"] == 0
    assert stats["total_devices"] == 0
    assert stats["flows_24h"] == 0
    
    # Record some benign flows
    flow_key1 = ("10.0.0.5", "8.8.8.8", 1234, 443, "TCP")
    store.record_flow("org-test", flow_key1, bytes_count=1000, packets_count=10, app="HTTPS", proto="TCP", is_new=True, is_end=False)
    store.record_device_seen("org-test", "10.0.0.5")
    store.increment_device_count("org-test")
    
    stats = store.get_overview_stats("org-test")
    assert stats["active_devices"] == 1
    assert stats["total_devices"] == 1
    assert stats["flows_24h"] == 1
    
    # Record updates to same flow
    store.record_flow("org-test", flow_key1, bytes_count=2000, packets_count=20, app="HTTPS", proto="TCP", is_new=False, is_end=False)
    stats = store.get_overview_stats("org-test")
    assert stats["active_devices"] == 1
    assert stats["flows_24h"] == 1 # remains 1
    
    # Close flow
    store.record_flow("org-test", flow_key1, bytes_count=0, packets_count=0, app="HTTPS", proto="TCP", is_new=False, is_end=True)
    stats = store.get_overview_stats("org-test")
    assert len(store._states["org-test"]["active_flows"]) == 0

def test_live_telemetry_store_alerts_tracking():
    store = LiveTelemetryStore()
    
    alert = {
        "id": "alert-1",
        "severity": "CRITICAL",
        "score": 9.5,
        "src_ip": "10.0.0.5",
        "time": "2026-06-25T12:00:00Z",
        "message": "Exfiltration pattern detected"
    }
    
    store.record_alert("org-test", alert)
    stats = store.get_overview_stats("org-test")
    assert stats["high_risk"] == 1
    assert stats["risk_distribution"]["CRITICAL"] == 1
    
    recent = store.get_recent_alerts("org-test", limit=5)
    assert len(recent) == 1
    assert recent[0]["id"] == "alert-1"

@pytest.mark.anyio
async def test_event_dispatcher_queuing(monkeypatch):
    # Clear any leftover items in the global queue
    while not flow_ingestion_queue.empty():
        try:
            flow_ingestion_queue.get_nowait()
        except asyncio.QueueEmpty:
            break

    dispatcher = EventDispatcher()
    
    # Mock downstream workers to verify they are called
    metrics_mock = AsyncMock()
    audit_mock = AsyncMock()
    
    monkeypatch.setattr(dispatcher, "_metrics_worker", metrics_mock)
    monkeypatch.setattr(dispatcher, "_audit_worker", audit_mock)
    
    # Start dispatcher loop
    dispatcher.start()
    
    # Enqueue a dummy batch
    batch = {
        "flows": [
            {
                "src_ip": "10.0.0.2",
                "dst_ip": "1.1.1.1",
                "src_port": 5000,
                "dst_port": 53,
                "protocol": "UDP",
                "packet_count": 2,
                "byte_count": 150,
                "duration": 0.1,
                "agent_id": "agent-xyz",
                "organization_id": "org-xyz",
                "start_time": "2026-06-25T12:00:00Z",
                "last_seen": "2026-06-25T12:00:00Z",
                "average_packet_size": 75.0,
            }
        ],
        "org_id": "org-xyz",
        "agent_id": "agent-xyz",
        "source_type": "agent",
    }
    
    await flow_ingestion_queue.put(batch)
    
    # Allow some time for event dispatcher loop to consume the item
    await asyncio.sleep(0.1)
    
    # Verify workers were called with the batch
    metrics_mock.assert_called_once_with(batch)
    audit_mock.assert_called_once_with(batch)
    
    dispatcher.stop()


def test_flow_manager_event_types(monkeypatch):
    from collector.flow_manager import FlowManager
    from collector import PacketObservation
    
    events = []
    def callback(summary):
        events.append(summary)
        
    manager = FlowManager(
        agent_id="GW-1",
        organization_id="ORG-1",
        on_flow_expired=callback,
        source_type="gateway",
        metadata_only=True,
        start_worker=False,
    )
    # Set timeouts and flush interval explicitly
    manager.flush_interval = 10.0
    manager.udp_timeout = 60.0
    manager.tcp_timeout = 60.0
    
    # Track current mocked time
    current_time = 1000.0
    monkeypatch.setattr(time, "time", lambda: current_time)
    
    # 1. Start a new flow observation at time = 1000.0
    obs1 = PacketObservation(
        observed_at=1000.0,
        source_type="gateway",
        metadata_only=True,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=52100,
        dst_port=53,
        protocol="UDP",
        packet_size=128,
        domain="example.com",
        sni=None,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        application_protocol="DNS",
        service_name="dns",
        analysis_source="port_signature",
        analysis_confidence=1.0,
        analysis_signals=("port_signature", "dns_query"),
    )
    manager.update_from_observation(obs1)
    
    # Check timeouts at T=1005 (less than flush_interval) -> no flush yet
    current_time = 1005.0
    manager._expire_flows()
    assert len(events) == 0
    
    # Check timeouts at T=1011 (greater than flush_interval) -> FLOW_NEW
    current_time = 1011.0
    manager._expire_flows()
    assert len(events) == 1
    assert events[0].event_type == "FLOW_NEW"
    
    # 2. Update the same flow at T=1012.0
    obs2 = PacketObservation(
        observed_at=1012.0,
        source_type="gateway",
        metadata_only=True,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        src_port=52100,
        dst_port=53,
        protocol="UDP",
        packet_size=256,
        domain="example.com",
        sni=None,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        application_protocol="DNS",
        service_name="dns",
        analysis_source="port_signature",
        analysis_confidence=1.0,
        analysis_signals=("port_signature", "dns_query"),
    )
    manager.update_from_observation(obs2)
    
    # Check timeouts at T=1023.0 (greater than flush_interval since last flushed) -> FLOW_UPDATE
    current_time = 1023.0
    manager._expire_flows()
    assert len(events) == 2
    assert events[1].event_type == "FLOW_UPDATE"
    
    # 3. Idle period: Check timeouts at T=1090.0 (greater than udp_timeout since T=1012.0) -> FLOW_END
    current_time = 1090.0
    manager._expire_flows()
    assert len(events) == 3
    assert events[2].event_type == "FLOW_END"

