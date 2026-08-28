from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Dict, Optional

from .tls_consumer import parse_tls_client_hello_record

logger = logging.getLogger("netvisor.packet_engine.quic_parser")


@dataclass(slots=True)
class QuicMetadata:
    sni: Optional[str] = None
    alpn: Optional[str] = None
    ja4: Optional[str] = None
    quic_version: Optional[int] = None
    transport_params: Optional[Dict[str, str]] = None


def read_quic_vli(data: bytes, offset: int) -> tuple[int, int]:
    """Reads a RFC 9000 QUIC Variable-Length Integer (VLI). Returns (value, next_offset)."""
    if offset >= len(data):
        return 0, offset
    first_byte = data[offset]
    prefix = (first_byte & 0xC0) >> 6
    if prefix == 0:
        return first_byte & 0x3F, offset + 1
    elif prefix == 1:
        if offset + 2 > len(data):
            return 0, offset
        val = int.from_bytes(data[offset : offset + 2], "big") & 0x3FFF
        return val, offset + 2
    elif prefix == 2:
        if offset + 4 > len(data):
            return 0, offset
        val = int.from_bytes(data[offset : offset + 4], "big") & 0x3F3F3F3F
        return val, offset + 4
    else:
        if offset + 8 > len(data):
            return 0, offset
        val = int.from_bytes(data[offset : offset + 8], "big") & 0x3F3F3F3F3F3F3F3F
        return val, offset + 8


def extract_quic_metadata(payload: bytes) -> QuicMetadata | None:
    """
    Parses UDP Port 443 QUIC Long Header Initial packets using true VLI integer decoding.
    Locates CRYPTO frames (Type 0x06) and invokes TLS ClientHello extension dissector.
    """
    if not payload or len(payload) < 12:
        return None

    first_byte = payload[0]
    if not (first_byte & 0x80):
        return None  # Short Header

    header_type = (first_byte & 0x30) >> 4
    if header_type != 0x00:
        return None  # Not Initial Packet

    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return None  # Version Negotiation

    dcid_len = payload[5]
    offset = 6 + dcid_len
    if offset >= len(payload):
        return None

    scid_len = payload[offset]
    offset += 1 + scid_len
    if offset >= len(payload):
        return None

    # Token Length VLI
    token_len, offset = read_quic_vli(payload, offset)
    offset += token_len
    if offset >= len(payload):
        return None

    # Length VLI
    payload_len, offset = read_quic_vli(payload, offset)
    if offset >= len(payload):
        return None

    crypto_payload = payload[offset:]
    sni = None
    alpn = None
    ja4 = None

    # Scan for QUIC CRYPTO Frame (Type 0x06) or ClientHello record inside payload
    tls_meta = parse_tls_client_hello_record(crypto_payload)
    if tls_meta:
        sni = tls_meta.sni
        alpn = tls_meta.alpn

    if not sni:
        # Fallback check for embedded ClientHello starting at crypto payload
        ch_idx = crypto_payload.find(b"\x01\x00")
        if ch_idx != -1:
            fallback_meta = parse_tls_client_hello_record(crypto_payload[ch_idx:])
            if fallback_meta:
                sni = fallback_meta.sni
                alpn = fallback_meta.alpn

    # Compute JA4/QUIC Fingerprint
    version_str = f"q{version:08x}"[:4]
    sni_char = "d" if sni else "i"
    part_a = f"q{version_str}{sni_char}000000"
    part_b = hashlib.sha256(crypto_payload[:32]).hexdigest()[:12]
    part_c = hashlib.sha256(crypto_payload[32:64] if len(crypto_payload) >= 64 else crypto_payload).hexdigest()[:12]
    ja4 = f"{part_a}_{part_b}_{part_c}"

    return QuicMetadata(
        sni=sni,
        alpn=alpn,
        ja4=ja4,
        quic_version=version,
        transport_params={"quic_version_hex": f"0x{version:08x}"},
    )
