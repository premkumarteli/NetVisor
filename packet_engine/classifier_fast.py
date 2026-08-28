from __future__ import annotations


def classify_packet_tier_fast(raw_bytes: bytes) -> int:
    """
    Zero-allocation L2-L4 byte offset classifier.
    Determines packet priority tier before queue insertion:
      Priority 0 = High / Control (SYN, FIN, RST, DNS, TLS ClientHello, QUIC Initial)
      Priority 1 = Medium / Application Metadata (HTTP, SMB, DHCP)
      Priority 2 = Low / Bulk Payload & ACKs
    """
    length = len(raw_bytes)
    if length < 34:
        return 2  # Truncated frame -> Bulk Queue

    # Parse Layer 2 (Ethernet Header = 14 bytes default)
    l3_offset = 14
    ethertype = (raw_bytes[12] << 8) | raw_bytes[13]

    # Dynamically skip 802.1Q / 802.1ad VLAN tags
    while ethertype in (0x8100, 0x88A8, 0x9100) and l3_offset + 4 <= length:
        ethertype = (raw_bytes[l3_offset + 2] << 8) | raw_bytes[l3_offset + 3]
        l3_offset += 4

    # Process IPv4 Header (Ethertype 0x0800)
    if ethertype == 0x0800:
        if l3_offset + 20 > length:
            return 2

        version_ihl = raw_bytes[l3_offset]
        ip_version = (version_ihl >> 4) & 0x0F
        if ip_version != 4:
            return 2

        # Dynamic Internet Header Length (IHL) calculation
        ihl_bytes = (version_ihl & 0x0F) * 4
        if ihl_bytes < 20 or l3_offset + ihl_bytes > length:
            return 2

        ip_proto = raw_bytes[l3_offset + 9]
        l4_offset = l3_offset + ihl_bytes

        # UDP Protocol (Proto 17)
        if ip_proto == 17 and l4_offset + 8 <= length:
            src_port = (raw_bytes[l4_offset] << 8) | raw_bytes[l4_offset + 1]
            dst_port = (raw_bytes[l4_offset + 2] << 8) | raw_bytes[l4_offset + 3]

            # DNS (Port 53 / 5353) -> High Priority
            if src_port in (53, 5353) or dst_port in (53, 5353):
                return 0

            # QUIC (UDP Port 443) -> Check if QUIC Long Header Initial Packet
            if src_port == 443 or dst_port == 443:
                udp_payload_offset = l4_offset + 8
                if udp_payload_offset < length:
                    first_byte = raw_bytes[udp_payload_offset]
                    # Long Header (0x80) & Initial Type (0x00 in bits 4-5)
                    if (first_byte & 0x80) and ((first_byte & 0x30) == 0x00):
                        return 0  # QUIC Initial ClientHello -> High Priority
                return 1  # Generic QUIC Metadata -> Medium Priority

            # DHCP (Ports 67/68) -> Medium Priority
            if src_port in (67, 68) or dst_port in (67, 68):
                return 1

        # TCP Protocol (Proto 6)
        elif ip_proto == 6 and l4_offset + 14 <= length:
            tcp_flags = raw_bytes[l4_offset + 13]

            # SYN (0x02), FIN (0x01), RST (0x04) -> High Priority
            if tcp_flags & 0x07:
                return 0

            src_port = (raw_bytes[l4_offset] << 8) | raw_bytes[l4_offset + 1]
            dst_port = (raw_bytes[l4_offset + 2] << 8) | raw_bytes[l4_offset + 3]

            # Strict 6-Byte TLS ClientHello Wire Validation
            if src_port == 443 or dst_port == 443:
                tcp_data_offset = ((raw_bytes[l4_offset + 12] >> 4) & 0x0F) * 4
                payload_offset = l4_offset + tcp_data_offset
                if payload_offset + 6 <= length:
                    content_type = raw_bytes[payload_offset]       # 0x16 (Handshake)
                    version_major = raw_bytes[payload_offset + 1]  # 0x03 (SSL 3.0 / TLS 1.x)
                    handshake_type = raw_bytes[payload_offset + 5] # 0x01 (ClientHello)
                    if content_type == 0x16 and version_major == 0x03 and handshake_type == 0x01:
                        return 0  # Verified TLS ClientHello Handshake -> High Priority
                return 1

            # HTTP (Ports 80 / 8080) -> Medium Priority
            if src_port in (80, 8080) or dst_port in (80, 8080):
                return 1

            # SMB / NetBIOS (Port 445 / 139) -> Medium Priority
            if src_port in (445, 139) or dst_port in (445, 139):
                return 1

    # Process IPv6 Header (Ethertype 0x86DD)
    elif ethertype == 0x86DD:
        if l3_offset + 40 > length:
            return 2
        next_header = raw_bytes[l3_offset + 6]
        l4_offset = l3_offset + 40
        if next_header == 17 and l4_offset + 8 <= length:  # UDP
            src_port = (raw_bytes[l4_offset] << 8) | raw_bytes[l4_offset + 1]
            dst_port = (raw_bytes[l4_offset + 2] << 8) | raw_bytes[l4_offset + 3]
            if src_port in (53, 5353) or dst_port in (53, 5353):
                return 0
        elif next_header == 6 and l4_offset + 14 <= length:  # TCP
            tcp_flags = raw_bytes[l4_offset + 13]
            if tcp_flags & 0x07:
                return 0

    return 2  # Default Bulk Data / Payload ACK -> Low Priority
