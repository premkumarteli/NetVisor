import pytest
from scapy.all import Ether, IP, IPv6, TCP

from packet_engine.dpkt_parser import DpktFastParser
from packet_engine.classifier_fast import classify_packet_tier_fast
from packet_engine.parser import PacketObservation
from packet_engine.backend import CaptureBackend, ScapyCaptureBackend

# LinkType enum or string representations
try:
    from packet_engine.types import LinkType
except ImportError:
    try:
        from packet_engine.dpkt_parser import LinkType
    except ImportError:
        from enum import Enum
        class LinkType(str, Enum):
            ETHERNET = "ETHERNET"
            RAW_IP = "RAW_IP"


def build_ethernet_packet(dst_mac: str, src_mac: str = "00:11:22:33:44:55") -> bytes:
    pkt = Ether(dst=dst_mac, src=src_mac) / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="S")
    return bytes(pkt)


def build_raw_ipv4_packet() -> bytes:
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
    return bytes(pkt)


def build_raw_ipv6_packet() -> bytes:
    pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=54321, dport=443, flags="S")
    return bytes(pkt)


def test_ethernet_dst_mac_starting_with_0x40():
    # 0x40 in the first byte caused (0x40 >> 4) == 4, falsely detected as direct IPv4
    frame = build_ethernet_packet("40:11:22:33:44:55", "00:aa:bb:cc:dd:ee")
    
    # 1. DpktFastParser must parse framing as Ethernet
    hdr = DpktFastParser.parse_packet_memoryview(frame, link_type=LinkType.ETHERNET)
    assert hdr is not None, "Failed to parse Ethernet frame with dst MAC 40:..."
    assert hdr.src_mac == "00:aa:bb:cc:dd:ee"
    assert hdr.dst_mac == "40:11:22:33:44:55"
    assert hdr.src_ip == "192.168.1.10"
    assert hdr.dst_ip == "192.168.1.20"
    assert hdr.src_port == 12345
    assert hdr.dst_port == 80
    assert hdr.flags == "SYN"

    # 2. PacketObservation.from_raw_bytes must correctly parse
    obs = PacketObservation.from_raw_bytes(frame, link_type=LinkType.ETHERNET)
    assert obs is not None
    assert obs.src_mac == "00:aa:bb:cc:dd:ee"
    assert obs.dst_mac == "40:11:22:33:44:55"
    assert obs.src_ip == "192.168.1.10"
    assert obs.dst_ip == "192.168.1.20"

    # 3. Fast classifier must recognize SYN as Priority 0
    tier = classify_packet_tier_fast(frame, link_type=LinkType.ETHERNET)
    assert tier == 0


def test_ethernet_dst_mac_starting_with_0x60():
    # 0x60 in the first byte caused (0x60 >> 4) == 6, falsely detected as direct IPv6
    frame = build_ethernet_packet("60:aa:bb:cc:dd:ee", "00:11:22:33:44:55")

    hdr = DpktFastParser.parse_packet_memoryview(frame, link_type=LinkType.ETHERNET)
    assert hdr is not None, "Failed to parse Ethernet frame with dst MAC 60:..."
    assert hdr.src_mac == "00:11:22:33:44:55"
    assert hdr.dst_mac == "60:aa:bb:cc:dd:ee"
    assert hdr.src_ip == "192.168.1.10"
    assert hdr.dst_ip == "192.168.1.20"

    obs = PacketObservation.from_raw_bytes(frame, link_type=LinkType.ETHERNET)
    assert obs is not None
    assert obs.src_mac == "00:11:22:33:44:55"
    assert obs.dst_mac == "60:aa:bb:cc:dd:ee"


def test_raw_ipv4_packet_parsing():
    raw_ip = build_raw_ipv4_packet()

    # 1. Fast classifier tier
    tier = classify_packet_tier_fast(raw_ip, link_type=LinkType.RAW_IP)
    assert tier == 0, f"Expected tier 0 for raw IPv4 SYN, got {tier}"

    # 2. DpktFastParser
    hdr = DpktFastParser.parse_packet_memoryview(raw_ip, link_type=LinkType.RAW_IP)
    assert hdr is not None, "DpktFastParser returned None for raw IPv4 packet"
    assert hdr.src_mac is None
    assert hdr.dst_mac is None
    assert hdr.src_ip == "10.0.0.1"
    assert hdr.dst_ip == "10.0.0.2"
    assert hdr.src_port == 12345
    assert hdr.dst_port == 80
    assert hdr.flags == "SYN"

    # 3. PacketObservation
    obs = PacketObservation.from_raw_bytes(raw_ip, link_type=LinkType.RAW_IP)
    assert obs is not None, "PacketObservation returned None for raw IPv4 packet"
    assert obs.src_mac is None
    assert obs.dst_mac is None
    assert obs.src_ip == "10.0.0.1"
    assert obs.dst_ip == "10.0.0.2"
    assert obs.protocol == "TCP"


def test_raw_ipv6_packet_parsing():
    raw_ip = build_raw_ipv6_packet()

    tier = classify_packet_tier_fast(raw_ip, link_type=LinkType.RAW_IP)
    assert tier == 0, f"Expected tier 0 for raw IPv6 SYN, got {tier}"

    hdr = DpktFastParser.parse_packet_memoryview(raw_ip, link_type=LinkType.RAW_IP)
    assert hdr is not None, "DpktFastParser returned None for raw IPv6 packet"
    assert hdr.src_mac is None
    assert hdr.dst_mac is None
    assert hdr.src_ip == "2001:db8::1"
    assert hdr.dst_ip == "2001:db8::2"
    assert hdr.src_port == 54321
    assert hdr.dst_port == 443

    obs = PacketObservation.from_raw_bytes(raw_ip, link_type=LinkType.RAW_IP)
    assert obs is not None, "PacketObservation returned None for raw IPv6 packet"
    assert obs.src_mac is None
    assert obs.dst_mac is None
    assert obs.src_ip == "2001:db8::1"
    assert obs.dst_ip == "2001:db8::2"
    assert obs.protocol == "TCP"


def test_backend_link_type_attribute():
    backend = ScapyCaptureBackend(role="capture")
    assert hasattr(backend, "link_type")
    assert backend.link_type == LinkType.ETHERNET
