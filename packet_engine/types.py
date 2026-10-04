from __future__ import annotations

from enum import Enum


class LinkType(str, Enum):
    """
    Data Link Layer Framing Types for Packet Ingestion.
    ETHERNET: Standard IEEE 802.3 / DIX Ethernet framing (14-byte header + optional 802.1Q tags).
    RAW_IP: Direct Layer 3 IPv4/IPv6 packet without Layer 2 Ethernet framing (e.g., TUN, WinDivert, WireGuard).
    """

    ETHERNET = "ETHERNET"
    RAW_IP = "RAW_IP"
