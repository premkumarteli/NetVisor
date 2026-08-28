from __future__ import annotations

import socket
import struct
import dpkt
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(slots=True)
class FastParsedHeader:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: Optional[str]
    payload_offset: int
    payload_length: int
    vlan_id: int = 0
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None


class DpktFastParser:
    """
    Zero-copy memoryview packet header extractor using DPKT.
    Extracts only core routing & 5-tuple fields (src_ip, dst_ip, src_port, dst_port,
    protocol, flags, payload_offset, payload_length) without building heavy protocol trees.
    """

    __slots__ = ()

    @staticmethod
    def parse_packet_memoryview(
        raw_data: bytes | memoryview,
    ) -> FastParsedHeader | None:
        if not raw_data or len(raw_data) < 14:
            return None

        # Convert to memoryview for zero-copy slicing
        mv = memoryview(raw_data) if isinstance(raw_data, bytes) else raw_data
        packet_len = len(mv)

        src_mac: Optional[str] = None
        dst_mac: Optional[str] = None
        vlan_id: int = 0

        # Fast header inspection
        first_byte = mv[0]
        ip_offset = 0

        # Determine framing: Ethernet vs Direct IP
        if (first_byte >> 4) in (4, 6):
            # Direct IP packet
            ip_offset = 0
        else:
            # Ethernet header (14 bytes minimum)
            if packet_len < 14:
                return None
            eth_bytes = bytes(mv[:14])
            src_mac = ":".join(f"{b:02x}" for b in eth_bytes[6:12])
            dst_mac = ":".join(f"{b:02x}" for b in eth.dst) if False else ":".join(f"{b:02x}" for b in eth_bytes[0:6])
            ether_type = (eth_bytes[12] << 8) | eth_bytes[13]
            ip_offset = 14

            if ether_type == 0x8100:  # 802.1Q VLAN
                if packet_len < 18:
                    return None
                vlan_bytes = bytes(mv[14:18])
                vlan_id = ((vlan_bytes[0] & 0x0F) << 8) | vlan_bytes[1]
                ether_type = (vlan_bytes[2] << 8) | vlan_bytes[3]
                ip_offset = 18

            if ether_type not in (0x0800, 0x86DD):
                return None  # Non-IP Ethernet packet

        if packet_len <= ip_offset:
            return None

        ip_first_byte = mv[ip_offset]
        ip_version = ip_first_byte >> 4

        if ip_version == 4:
            # IPv4 parsing
            if packet_len < ip_offset + 20:
                return None
            ihl = (ip_first_byte & 0x0F) * 4
            total_len = (mv[ip_offset + 2] << 8) | mv[ip_offset + 3]
            proto_num = mv[ip_offset + 9]
            
            src_bytes = bytes(mv[ip_offset + 12 : ip_offset + 16])
            dst_bytes = bytes(mv[ip_offset + 16 : ip_offset + 20])
            src_ip = socket.inet_ntop(socket.AF_INET, src_bytes)
            dst_ip = socket.inet_ntop(socket.AF_INET, dst_bytes)

            trans_offset = ip_offset + ihl

        elif ip_version == 6:
            # IPv6 parsing
            if packet_len < ip_offset + 40:
                return None
            proto_num = mv[ip_offset + 6]
            payload_len = (mv[ip_offset + 4] << 8) | mv[ip_offset + 5]

            src_bytes = bytes(mv[ip_offset + 8 : ip_offset + 24])
            dst_bytes = bytes(mv[ip_offset + 24 : ip_offset + 40])
            src_ip = socket.inet_ntop(socket.AF_INET6, src_bytes)
            dst_ip = socket.inet_ntop(socket.AF_INET6, dst_bytes)

            trans_offset = ip_offset + 40
        else:
            return None

        src_port = 0
        dst_port = 0
        tcp_flags = None
        payload_offset = trans_offset
        payload_length = 0

        if proto_num == 6:  # TCP
            if packet_len < trans_offset + 20:
                return None
            proto = "TCP"
            src_port = (mv[trans_offset] << 8) | mv[trans_offset + 1]
            dst_port = (mv[trans_offset + 2] << 8) | mv[trans_offset + 3]
            data_offset = ((mv[trans_offset + 12] >> 4) & 0x0F) * 4
            flags_byte = mv[trans_offset + 13]

            flags_list = []
            if flags_byte & 0x02: flags_list.append("SYN")
            if flags_byte & 0x10: flags_list.append("ACK")
            if flags_byte & 0x01: flags_list.append("FIN")
            if flags_byte & 0x04: flags_list.append("RST")
            if flags_byte & 0x08: flags_list.append("PSH")
            if flags_byte & 0x20: flags_list.append("URG")
            tcp_flags = ",".join(flags_list) if flags_list else None

            payload_offset = trans_offset + data_offset
            payload_length = max(0, packet_len - payload_offset)

        elif proto_num == 17:  # UDP
            if packet_len < trans_offset + 8:
                return None
            proto = "UDP"
            src_port = (mv[trans_offset] << 8) | mv[trans_offset + 1]
            dst_port = (mv[trans_offset + 2] << 8) | mv[trans_offset + 3]
            udp_len = (mv[trans_offset + 4] << 8) | mv[trans_offset + 5]
            payload_offset = trans_offset + 8
            payload_length = max(0, min(udp_len - 8, packet_len - payload_offset))

        else:
            proto = str(proto_num)
            payload_offset = trans_offset
            payload_length = max(0, packet_len - trans_offset)

        return FastParsedHeader(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            flags=tcp_flags,
            payload_offset=payload_offset,
            payload_length=payload_length,
            vlan_id=vlan_id,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )
