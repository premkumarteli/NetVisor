import pytest
from packet_engine.parser import PacketObservation
from packet_engine.flow_aggregator import FlowManager


def test_canonical_key_excludes_mac_addresses():
    obs = PacketObservation(
        observed_at=1000.0,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        src_mac="00:11:22:33:44:55",
        dst_mac="aa:bb:cc:dd:ee:ff",
        vlan_id=0,
    )
    key = obs.canonical_conversation_key

    # Key must be a 5-tuple: (ip_pair, port_pair, protocol, source_type, vlan_id)
    assert len(key) == 5, f"Expected 5-tuple canonical key without MACs, got length {len(key)}: {key}"
    assert key[0] == ("10.0.0.1", "192.168.1.100")
    assert key[1] == (443, 50000)
    assert key[2] == "TCP"
    assert key[3] == "agent"
    assert key[4] == 0

    # Ensure MACs are not present anywhere in the tuple
    for elem in key:
        if isinstance(elem, tuple):
            for sub in elem:
                assert sub not in ("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")


def test_flows_with_different_macs_merge_in_flow_manager():
    manager = FlowManager(
        agent_id="test-agent",
        organization_id="test-org",
        on_flow_expired=lambda s: None,
        start_worker=False,
    )

    # Packet 1: Host A -> Host B before router (local MACs)
    pkt1 = PacketObservation(
        observed_at=1000.0,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.50",
        dst_ip="172.16.0.10",
        src_port=45000,
        dst_port=80,
        protocol="TCP",
        packet_size=60,
        src_mac="00:11:22:33:44:55",
        dst_mac="00:aa:bb:cc:dd:01",  # Local gateway MAC
        vlan_id=0,
    )

    # Packet 2: Host A -> Host B after router (routed MACs)
    pkt2 = PacketObservation(
        observed_at=1000.1,
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.50",
        dst_ip="172.16.0.10",
        src_port=45000,
        dst_port=80,
        protocol="TCP",
        packet_size=60,
        src_mac="00:aa:bb:cc:dd:02",  # Router egress MAC
        dst_mac="11:22:33:44:55:66",  # Destination host MAC
        vlan_id=0,
    )

    # Packet 3: Host B -> Host A reverse reply
    pkt3 = PacketObservation(
        observed_at=1000.2,
        source_type="agent",
        metadata_only=False,
        src_ip="172.16.0.10",
        dst_ip="192.168.1.50",
        src_port=80,
        dst_port=45000,
        protocol="TCP",
        packet_size=120,
        src_mac="11:22:33:44:55:66",
        dst_mac="00:aa:bb:cc:dd:02",
        vlan_id=0,
    )

    # Both forward observations must have the same canonical key
    assert pkt1.canonical_conversation_key == pkt2.canonical_conversation_key
    # Reverse observation must also match
    assert pkt1.canonical_conversation_key == pkt3.canonical_conversation_key

    # Feed all 3 packets into FlowManager
    manager.update_from_observation(pkt1)
    manager.update_from_observation(pkt2)
    manager.update_from_observation(pkt3)

    active_flows = manager.get_active_flows()
    assert len(active_flows) == 1, f"Expected 1 merged flow, got {len(active_flows)}"

    flow = list(active_flows.values())[0]
    assert flow.packet_count == 3
    assert flow.byte_count == 240
    # First-seen MACs must be retained as attributes on the flow record
    assert flow.src_mac == "00:11:22:33:44:55"
    assert flow.dst_mac == "00:aa:bb:cc:dd:01"
