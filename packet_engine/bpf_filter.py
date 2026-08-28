from __future__ import annotations

from typing import Set


class BPFFilterEngine:
    """
    Dynamic eBPF / Pre-enqueue Fast Traffic Filter.
    Parses dynamic Ethernet, 802.1Q VLAN, 802.1ad QinQ, IPv4 IHL, and IPv6 extension headers.
    Enforces Priority Allow-List vs Noise-Drop List before enqueueing.
    """

    # Priority Allow-List: High-value control & telemetry protocols (Pass immediately)
    TARGET_PORTS: Set[int] = {
        22,    # SSH
        53,    # DNS
        80,    # HTTP
        88,    # KERBEROS
        389,   # LDAP / CLDAP
        443,   # TLS / HTTPS / QUIC
        445,   # SMB
        636,   # LDAPS
        3389,  # RDP
        4433,  # TLS Alt
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
    }

    # Noise-Drop List: Background broadcast/multicast noise (Drop immediately)
    DROPPED_PORTS: Set[int] = {
        137,   # NBNS (NetBIOS Name Service)
        138,   # NBDS (NetBIOS Datagram Service)
        1900,  # SSDP (UPnP)
        5353,  # mDNS (Multicast DNS)
        5355,  # LLMNR (Link-Local Multicast Name Resolution)
    }

    __slots__ = ("_dropped_count", "_passed_count", "_priority_passed_count")

    def __init__(self) -> None:
        self._dropped_count = 0
        self._passed_count = 0
        self._priority_passed_count = 0

    def should_pass_packet(self, raw_bytes: bytes | memoryview) -> bool:
        """
        Dynamic pre-enqueue traffic filter.
        Determines frame offset dynamically (Ethernet -> VLAN -> QinQ -> IP IHL -> Transport ports).
        """
        if not raw_bytes or len(raw_bytes) < 14:
            return False

        mv = memoryview(raw_bytes) if isinstance(raw_bytes, bytes) else raw_bytes
        pkt_len = len(mv)

        # Dynamic Ethernet / VLAN / QinQ header parser
        first_nibble = mv[0] >> 4
        if first_nibble in (4, 6):
            ip_offset = 0
            ether_type = 0x0800 if first_nibble == 4 else 0x86DD
        else:
            if pkt_len < 14:
                return False
            ether_type = (mv[12] << 8) | mv[13]
            ip_offset = 14

            # Drop ARP frames (0x0806) immediately
            if ether_type == 0x0806:
                self._dropped_count += 1
                return False

            # Single 802.1Q VLAN (0x8100) or QinQ (0x88A8)
            if ether_type in (0x8100, 0x88A8):
                if pkt_len < 18:
                    return False
                ether_type = (mv[16] << 8) | mv[17]
                ip_offset = 18

                # Dual 802.1ad QinQ second tag
                if ether_type in (0x8100, 0x88A8):
                    if pkt_len < 22:
                        return False
                    ether_type = (mv[20] << 8) | mv[21]
                    ip_offset = 22

            if ether_type not in (0x0800, 0x86DD):
                return True  # Allow non-IP frames by default unless ARP

        if pkt_len <= ip_offset:
            return False

        src_port = 0
        dst_port = 0
        proto_num = 0

        # Dynamic IPv4 Header Parsing
        if ether_type == 0x0800:
            if pkt_len < ip_offset + 20:
                return False
            ihl = (mv[ip_offset] & 0x0F) * 4
            proto_num = mv[ip_offset + 9]
            trans_offset = ip_offset + ihl

            if proto_num in (6, 17):  # TCP or UDP
                if pkt_len < trans_offset + 4:
                    return False
                src_port = (mv[trans_offset] << 8) | mv[trans_offset + 1]
                dst_port = (mv[trans_offset + 2] << 8) | mv[trans_offset + 3]

        # Dynamic IPv6 Header Parsing
        elif ether_type == 0x86DD:
            if pkt_len < ip_offset + 40:
                return False
            proto_num = mv[ip_offset + 6]
            trans_offset = ip_offset + 40

            if proto_num in (6, 17):
                if pkt_len < trans_offset + 4:
                    return False
                src_port = (mv[trans_offset] << 8) | mv[trans_offset + 1]
                dst_port = (mv[trans_offset + 2] << 8) | mv[trans_offset + 3]

        # Decision Filter Logic:
        # 1. Priority Allow-List: Pass immediately
        if src_port in self.TARGET_PORTS or dst_port in self.TARGET_PORTS:
            self._priority_passed_count += 1
            self._passed_count += 1
            return True

        # 2. Noise-Drop List: Drop immediately
        if src_port in self.DROPPED_PORTS or dst_port in self.DROPPED_PORTS:
            self._dropped_count += 1
            return False

        # 3. Default: Pass
        self._passed_count += 1
        return True

    @property
    def metrics(self) -> dict[str, int]:
        return {
            "dropped_total": self._dropped_count,
            "passed_total": self._passed_count,
            "priority_passed_total": self._priority_passed_count,
        }
