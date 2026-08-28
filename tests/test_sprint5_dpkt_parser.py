import pytest
from scapy.all import Ether, IP, TCP, UDP, raw
from packet_engine.parser import PacketObservation


def test_dpkt_raw_bytes_tcp_parsing():
    # Build raw TCP packet
    scapy_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54321, dport=443, flags="SA")
    raw_bytes = raw(scapy_pkt)

    obs = PacketObservation.from_raw_bytes(raw_bytes)
    assert obs is not None
    assert obs.src_mac == "00:11:22:33:44:55"
    assert obs.dst_mac == "66:77:88:99:aa:bb"
    assert obs.src_ip == "192.168.1.10"
    assert obs.dst_ip == "10.0.0.5"
    assert obs.src_port == 54321
    assert obs.dst_port == 443
    assert obs.protocol == "TCP"
    assert obs.tcp_flags == "SYN,ACK"
    assert obs.application_protocol == "HTTPS"
    assert obs.analysis_source == "dpkt_fast_dissector"


def test_dpkt_raw_bytes_udp_dns_parsing():
    scapy_pkt = Ether(src="00:aa:bb:cc:dd:ee", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.100", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    raw_bytes = raw(scapy_pkt)

    obs = PacketObservation.from_raw_bytes(raw_bytes)
    assert obs is not None
    assert obs.src_ip == "10.0.0.100"
    assert obs.dst_ip == "8.8.8.8"
    assert obs.src_port == 53000
    assert obs.dst_port == 53
    assert obs.protocol == "UDP"
    assert obs.application_protocol == "DNS"


def test_dpkt_vlan_8021q_tag_extraction():
    from scapy.layers.l2 import Dot1Q
    scapy_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / Dot1Q(vlan=100) / IP(src="172.16.0.1", dst="172.16.0.2") / TCP(sport=1234, dport=80, flags="S")
    raw_bytes = raw(scapy_pkt)

    obs = PacketObservation.from_raw_bytes(raw_bytes)
    assert obs is not None
    assert obs.vlan_id == 100
    assert obs.src_ip == "172.16.0.1"
    assert obs.dst_ip == "172.16.0.2"
    assert obs.protocol == "TCP"


def test_dpkt_http_host_extraction():
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: internal.netvisor.io\r\n\r\n"
    scapy_pkt = Ether() / IP(src="192.168.1.5", dst="192.168.1.1") / TCP(sport=50000, dport=80, flags="PA") / http_payload
    raw_bytes = raw(scapy_pkt)

    obs = PacketObservation.from_raw_bytes(raw_bytes)
    assert obs is not None
    assert obs.domain == "internal.netvisor.io"
    assert obs.application_protocol == "HTTP"


def test_from_packet_dispatch_to_dpkt():
    scapy_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=1111, dport=22, flags="S")
    
    # Passing Scapy packet uses fast raw bytes cutover automatically
    obs = PacketObservation.from_packet(scapy_pkt)
    assert obs is not None
    assert obs.src_ip == "10.1.1.1"
    assert obs.dst_ip == "10.1.1.2"
    assert obs.application_protocol == "SSH"
