from __future__ import annotations

from scapy.all import Ether, IP, TCP  # type: ignore

from collector import (
    DpiObservation,
    FlowManager,
    FlowObservation,
    LinuxRawSocketCaptureBackend,
    PacketObservation,
    ScapyCaptureBackend,
    build_capture_backend,
)
import collector.capture as capture_module


def test_packet_observation_round_trip_to_flow_observation():
    packet = Ether() / IP(src="10.0.0.10", dst="8.8.8.8") / TCP(sport=12345, dport=443)
    packet.captured_domain = "example.com"
    packet.captured_sni = "example.com"

    observation = PacketObservation.from_packet(packet, source_type="gateway", metadata_only=True)

    assert observation is not None
    assert observation.flow_key == ("10.0.0.10", "8.8.8.8", 12345, 443, "TCP")
    assert observation.domain == "example.com"
    assert observation.metadata_only is True
    assert observation.application_protocol == "HTTPS"
    assert observation.analysis_source == "port_signature"

    flow = observation.to_flow_observation(agent_id="GW-1", organization_id="ORG-1")
    assert isinstance(flow, FlowObservation)
    assert flow.source_type == "gateway"
    assert flow.metadata_only is True
    assert flow.domain == "example.com"
    assert flow.application_protocol == "HTTPS"
    assert flow.analysis_source == "port_signature"
    assert flow.agent_id == "GW-1"
    assert flow.organization_id == "ORG-1"


def test_flow_manager_status_snapshot_reports_capture_mode():
    manager = FlowManager(
        agent_id="GW-1",
        organization_id="ORG-1",
        on_flow_expired=lambda summary: None,
        source_type="gateway",
        metadata_only=True,
        start_worker=False,
    )

    snapshot = manager.status_snapshot()

    assert snapshot["source_type"] == "gateway"
    assert snapshot["metadata_only"] is True


def test_flow_manager_preserves_analyzer_metadata_in_summaries():
    manager = FlowManager(
        agent_id="GW-1",
        organization_id="ORG-1",
        on_flow_expired=lambda summary: None,
        source_type="gateway",
        metadata_only=True,
        start_worker=False,
    )
    observation = PacketObservation(
        observed_at=1_710_000_000.0,
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

    manager.update_from_observation(observation)
    state = manager._flows[observation.canonical_conversation_key]
    summary = manager._build_summary(observation.canonical_conversation_key, state)

    assert state.application_protocol == "DNS"
    assert state.service_name == "dns"
    assert state.analysis_source == "port_signature"
    assert state.analysis_confidence == 1.0
    assert state.analysis_signals == ("port_signature", "dns_query")
    assert summary.application_protocol == "DNS"
    assert summary.service_name == "dns"
    assert summary.analysis_source == "port_signature"
    assert summary.analysis_confidence == 1.0
    assert summary.analysis_signals == ("port_signature", "dns_query")


def test_build_capture_backend_prefers_linux_raw_on_linux(monkeypatch):
    monkeypatch.setattr(capture_module.platform, "system", lambda: "Linux")

    backend = build_capture_backend(role="gateway", interface="eth0", requested_backend="auto")

    assert isinstance(backend, LinuxRawSocketCaptureBackend)
    assert backend.backend_name == "linux_raw"


def test_build_capture_backend_uses_scapy_on_windows(monkeypatch):
    monkeypatch.setattr(capture_module.platform, "system", lambda: "Windows")

    backend = build_capture_backend(role="agent", interface=None, requested_backend="auto")

    assert isinstance(backend, ScapyCaptureBackend)
    assert backend.backend_name == "scapy"


def test_capture_status_reports_drop_rate_and_error_category():
    backend = ScapyCaptureBackend(role="agent", interface="Ethernet", requested_backend="scapy")
    backend._mark_started()
    backend._record_seen()
    backend._record_drop("Permission denied opening capture adapter")

    snapshot = backend.status_snapshot()

    assert snapshot["health_status"] == "unhealthy"
    assert snapshot["error_category"] == "permission"
    assert snapshot["drop_rate"] == 1.0
    assert snapshot["packets_dropped"] == 1


def test_dpi_observation_payload_omits_raw_headers():
    observation = DpiObservation(
        browser_name="Chrome",
        process_name="chrome.exe",
        page_url="https://example.com",
        base_domain="example.com",
        page_title="Example",
        content_category="web",
        content_id=None,
        search_query=None,
        http_method="GET",
        status_code=200,
        content_type="text/html",
        request_bytes=123,
        response_bytes=456,
        snippet_redacted="hello",
        timestamp="2026-04-24T00:00:00Z",
        app="Chrome",
    )

    payload = observation.to_payload()

    assert payload["browser_name"] == "Chrome"
    assert payload["source_type"] == "agent"
    assert "headers" not in payload


def test_10tuple_and_canonical_conversation_keys():
    obs1 = PacketObservation(
        observed_at=1_710_000_000.0,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.50",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=512,
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:dd:ee:02",
        vlan_id=10,
        tcp_flags="S",
    )
    obs2 = PacketObservation(
        observed_at=1_710_000_001.0,
        source_type="agent",
        metadata_only=False,
        src_ip="142.250.190.46",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=54321,
        protocol="TCP",
        packet_size=1024,
        src_mac="aa:bb:cc:dd:ee:02",
        dst_mac="aa:bb:cc:dd:ee:01",
        vlan_id=10,
        tcp_flags="SA",
    )

    # 10-tuple keys
    assert obs1.flow_key_10tuple == (
        "192.168.1.50", "142.250.190.46", 54321, 443, "TCP", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "-", "agent", 10
    )
    # Full canonical key equality for opposite directions of the same conversation
    assert obs1.canonical_conversation_key == obs2.canonical_conversation_key
    assert obs1.canonical_conversation_key == (
        ("142.250.190.46", "192.168.1.50"),
        (443, 54321),
        "TCP",
        ("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"),
        "agent",
        10,
    )


def test_tcp_fin_rst_fast_eviction():
    expired_summaries = []
    manager = FlowManager(
        agent_id="agent-1",
        organization_id="org-1",
        on_flow_expired=lambda s: expired_summaries.append(s),
        tcp_timeout=60,
        start_worker=False,
    )

    # 1. Start TCP flow with SYN
    syn_obs = PacketObservation(
        observed_at=100.0,
        source_type="agent",
        metadata_only=False,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1000,
        dst_port=80,
        protocol="TCP",
        packet_size=64,
        tcp_flags="S",
    )
    manager.update_from_observation(syn_obs)
    assert syn_obs.canonical_conversation_key in manager._flows
    assert manager._flows[syn_obs.canonical_conversation_key].is_closing is False

    # 2. Receive FIN
    fin_obs = PacketObservation(
        observed_at=105.0,
        source_type="agent",
        metadata_only=False,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1000,
        dst_port=80,
        protocol="TCP",
        packet_size=64,
        tcp_flags="FA",
    )
    manager.update_from_observation(fin_obs)
    assert manager._flows[syn_obs.canonical_conversation_key].is_closing is True

    # 3. Expire check at t=106 (1 sec after FIN) -> should still be alive
    import time
    orig_time = time.time
    try:
        import unittest.mock as mock
        with mock.patch("time.time", return_value=106.0):
            manager._expire_flows()
            assert syn_obs.canonical_conversation_key in manager._flows

        # 4. Expire check at t=108 (3 sec after FIN) -> should fast expire!
        with mock.patch("time.time", return_value=108.0):
            manager._expire_flows()
            assert syn_obs.canonical_conversation_key not in manager._flows
            assert len(expired_summaries) == 2
            assert expired_summaries[0].event_type == "FLOW_NEW"
            assert expired_summaries[1].event_type == "FLOW_END"
    finally:
        pass


def test_flow_manager_bidirectional_accounting():
    manager = FlowManager(
        agent_id="agent-1",
        organization_id="org-1",
        on_flow_expired=lambda s: None,
        tcp_timeout=60,
        start_worker=False,
    )

    fwd_obs = PacketObservation(
        observed_at=100.0,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.50",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=500,
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:dd:ee:02",
        vlan_id=10,
        tcp_flags="PA",
    )
    rev_obs = PacketObservation(
        observed_at=100.1,
        source_type="agent",
        metadata_only=False,
        src_ip="142.250.190.46",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=54321,
        protocol="TCP",
        packet_size=1200,
        src_mac="aa:bb:cc:dd:ee:02",
        dst_mac="aa:bb:cc:dd:ee:01",
        vlan_id=10,
        tcp_flags="PA",
    )

    manager.update_from_observation(fwd_obs)
    assert len(manager._flows) == 1

    manager.update_from_observation(rev_obs)
    assert len(manager._flows) == 1

    state = list(manager._flows.values())[0]
    assert state.packet_count == 2
    assert state.byte_count == 1700
    assert state.fwd_bytes == 500
    assert state.fwd_packets == 1
    assert state.rev_bytes == 1200
    assert state.rev_packets == 1

    summary = manager._build_summary(fwd_obs.canonical_conversation_key, state)
    assert summary.fwd_bytes == 500
    assert summary.rev_bytes == 1200
    assert summary.fwd_packets == 1
    assert summary.rev_packets == 1
    assert summary.packet_count == 2
    assert summary.byte_count == 1700
    assert summary.src_ip == "192.168.1.50"
    assert summary.dst_ip == "142.250.190.46"


def test_flow_manager_mac_anchoring_stability():
    manager = FlowManager(
        agent_id="agent-1",
        organization_id="org-1",
        on_flow_expired=lambda s: None,
        tcp_timeout=60,
        start_worker=False,
    )

    fwd_obs1 = PacketObservation(
        observed_at=100.0,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.50",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:dd:ee:02",
        tcp_flags="S",
    )
    rev_obs = PacketObservation(
        observed_at=100.1,
        source_type="agent",
        metadata_only=False,
        src_ip="142.250.190.46",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=54321,
        protocol="TCP",
        packet_size=100,
        src_mac="aa:bb:cc:dd:ee:02",
        dst_mac="aa:bb:cc:dd:ee:01",
        tcp_flags="SA",
    )
    fwd_obs2 = PacketObservation(
        observed_at=100.2,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.50",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:dd:ee:02",
        tcp_flags="A",
    )

    # 1. First packet (Forward) establishes initial anchor
    manager.update_from_observation(fwd_obs1)
    state = list(manager._flows.values())[0]
    assert state.src_mac == "aa:bb:cc:dd:ee:01"
    assert state.dst_mac == "aa:bb:cc:dd:ee:02"

    # 2. Second packet (Reverse) must NOT flip state.src_mac / dst_mac
    manager.update_from_observation(rev_obs)
    state = list(manager._flows.values())[0]
    assert state.src_mac == "aa:bb:cc:dd:ee:01"
    assert state.dst_mac == "aa:bb:cc:dd:ee:02"

    # 3. Third packet (Forward) remains anchored and stable
    manager.update_from_observation(fwd_obs2)
    state = list(manager._flows.values())[0]
    assert state.src_mac == "aa:bb:cc:dd:ee:01"
    assert state.dst_mac == "aa:bb:cc:dd:ee:02"

    summary = manager._build_summary(fwd_obs1.canonical_conversation_key, state)
    assert summary.src_mac == "aa:bb:cc:dd:ee:01"
    assert summary.dst_mac == "aa:bb:cc:dd:ee:02"


