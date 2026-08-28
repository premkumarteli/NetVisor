import tempfile
import pytest
import dpkt
from scapy.all import Ether, IP, IPv6, TCP, UDP, raw
from scapy.layers.l2 import Dot1Q

from packet_engine.bpf_filter import BPFFilterEngine
from packet_engine.af_packet_backend import AFPacketMmapBackend
from packet_engine.cpu_affinity import CPUAffinityManager
from packet_engine.tcp_stream import BidirectionalTCPStream, TCPStreamTrackerManager
from packet_engine.tls_consumer import parse_tls_server_hello_record, TLSServerHelloMetadata
from packet_engine.object_pool import (
    PacketObservationPool,
    FlowObservationPool,
    HttpTransactionPool,
    TLSHandshakeMetadataPool,
)
from packet_engine.metrics import NetVisorMetricsExporter
from packet_engine.pcap_replay import PCAPReplayer


def test_vlan_qinq_bpf_filtering():
    engine = BPFFilterEngine()

    # 1. Standard Ethernet + IPv4 DNS (Port 53)
    dns_frame = raw(Ether() / IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=53000, dport=53))
    assert engine.should_pass_packet(dns_frame) is True

    # 2. 802.1Q Single VLAN Tag + IPv4 HTTPS (Port 443)
    vlan_frame = raw(Ether() / Dot1Q(vlan=100) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=443))
    assert engine.should_pass_packet(vlan_frame) is True

    # 3. 802.1ad QinQ Dual VLAN Tags + IPv4 mDNS Noise (Port 5353)
    qinq_frame = raw(Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP(src="10.0.0.1", dst="224.0.0.251") / UDP(sport=5353, dport=5353))
    assert engine.should_pass_packet(qinq_frame) is False


def test_ipv6_dynamic_offset_filtering():
    engine = BPFFilterEngine()
    ipv6_frame = raw(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=60000, dport=22))
    assert engine.should_pass_packet(ipv6_frame) is True


def test_bidirectional_tcp_streams():
    manager = TCPStreamTrackerManager()
    flow_key = (("192.168.1.10", "10.0.0.1"), (54321, 80), "TCP", (None, None), "eth", 0)

    # Client -> Server request
    c2s_bytes = manager.process_bidirectional_segment(
        flow_key=flow_key, seq=1000, ack=1, payload=b"GET /api HTTP/1.1\r\n", flags="PA", is_forward=True
    )
    assert c2s_bytes == b"GET /api HTTP/1.1\r\n"

    # Server -> Client response
    s2c_bytes = manager.process_bidirectional_segment(
        flow_key=flow_key, seq=5000, ack=1020, payload=b"HTTP/1.1 200 OK\r\n", flags="PA", is_forward=False
    )
    assert s2c_bytes == b"HTTP/1.1 200 OK\r\n"


def test_tls_server_hello_parsing():
    # Build synthetic ServerHello payload
    server_hello_payload = (
        b"\x16" +
        b"\x03\x03" +
        b"\x00\x30" +
        b"\x02" +
        b"\x00\x00\x2c" +
        b"\x03\x03" +
        (b"\x00" * 32) +
        b"\x00" +
        b"\x13\x01" +
        b"\x00" +
        b"\x00\x06" +
        b"\x00\x2b\x00\x02\x03\x04"
    )

    metadata = parse_tls_server_hello_record(server_hello_payload)
    assert metadata is not None
    assert metadata.selected_cipher == 0x1301
    assert metadata.tls_version == "TLS 1.3"
    assert metadata.ja3s is not None


def test_prometheus_metrics_exporter():
    exporter = NetVisorMetricsExporter()
    exporter.update_metrics(packets=1000, flows=50, queue_depth=5, memory_bytes=1048576, tcp_streams=10, alerts=2)
    expo_str = exporter.generate_prometheus_exposition()

    assert "netvisor_packets_total 1000" in expo_str
    assert "netvisor_flows_total 50" in expo_str
    assert "netvisor_memory_bytes 1048576" in expo_str


def test_object_pools_coverage():
    p_pool = PacketObservationPool.get_pool()
    f_pool = FlowObservationPool.get_pool()
    h_pool = HttpTransactionPool.get_pool()
    t_pool = TLSHandshakeMetadataPool.get_pool()

    assert p_pool is not None
    assert f_pool is not None
    assert h_pool is not None
    assert t_pool is not None


def test_pcap_replay_framework():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_filename = f.name

    try:
        # Create synthetic pcap with 5 frames
        with open(pcap_filename, "wb") as f_out:
            writer = dpkt.pcap.Writer(f_out)
            pkt = raw(Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=1234, dport=53))
            for i in range(5):
                writer.writepkt(pkt, ts=1000.0 + i)

        replayer = PCAPReplayer(pcap_filename, speed_multiplier=0.0)
        replayed_count = []

        def cb(raw_b, ts):
            replayed_count.append(raw_b)

        total = replayer.replay(cb)
        assert total == 5
        assert len(replayed_count) == 5
    finally:
        import os
        if os.path.exists(pcap_filename):
            os.remove(pcap_filename)
