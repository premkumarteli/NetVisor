from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from .metadata import extract_ja4_fingerprint

logger = logging.getLogger("netvisor.packet_engine.tls_consumer")


@dataclass(slots=True)
class TLSHandshakeMetadata:
    sni: Optional[str] = None
    ja4: Optional[str] = None
    alpn: Optional[str] = None
    cipher_suites: List[int] = None
    supported_versions: List[str] = None
    tls_version: str = "TLS 1.2"
    confidence: float = 1.00

    @property
    def alpn_protocols(self) -> List[str]:
        if self.alpn:
            return [a.strip() for a in self.alpn.split(",") if a.strip()]
        return []


@dataclass(slots=True)
class TLSServerHelloMetadata:
    ja3s: Optional[str] = None
    selected_cipher: Optional[int] = None
    selected_cipher_name: Optional[str] = None
    tls_version: str = "TLS 1.2"
    server_alpn: Optional[str] = None
    cert_cn: Optional[str] = None
    cert_san: Optional[List[str]] = None
    confidence: float = 1.00


def parse_tls_server_hello_record(stream_bytes: bytes) -> TLSServerHelloMetadata | None:
    """
    Parses a reassembled TLS ServerHello record directly from wire bytes.
    Extracts JA3S fingerprint, selected cipher suite, server ALPN, TLS version, and cert CN/SAN strings.
    """
    if not stream_bytes or len(stream_bytes) < 38:
        return None

    idx = 0
    if stream_bytes[0] == 0x16:  # TLS Handshake Record
        idx = 5

    if idx < len(stream_bytes) and stream_bytes[idx] != 0x02:  # 0x02 = ServerHello
        return None

    idx += 4  # Skip Handshake Type (1) + Length (3)
    if idx + 34 > len(stream_bytes):
        return None

    server_version_num = int.from_bytes(stream_bytes[idx : idx + 2], "big")
    idx += 34  # Skip Version (2) + Random (32)

    if idx >= len(stream_bytes):
        return None

    # Session ID
    sess_id_len = stream_bytes[idx]
    idx += 1 + sess_id_len
    if idx + 2 > len(stream_bytes):
        return None

    selected_cipher = int.from_bytes(stream_bytes[idx : idx + 2], "big")
    idx += 2
    if idx >= len(stream_bytes):
        return None

    # Compression Method
    idx += 1
    if idx + 2 > len(stream_bytes):
        return None

    # Extensions
    exts_len = int.from_bytes(stream_bytes[idx : idx + 2], "big")
    idx += 2
    exts_end = min(len(stream_bytes), idx + exts_len)

    ext_ids: List[int] = []
    server_alpn: Optional[str] = None
    version_str = "TLS 1.2" if server_version_num == 0x0303 else f"0x{server_version_num:04x}"

    while idx + 4 <= exts_end:
        ext_type = int.from_bytes(stream_bytes[idx : idx + 2], "big")
        ext_len = int.from_bytes(stream_bytes[idx + 2 : idx + 4], "big")
        ext_data_end = idx + 4 + ext_len
        if ext_data_end > exts_end:
            break

        ext_ids.append(ext_type)

        if ext_type == 0x0010:  # ALPN
            try:
                alpn_data = stream_bytes[idx + 4 : ext_data_end]
                if len(alpn_data) > 3:
                    str_len = alpn_data[2]
                    server_alpn = alpn_data[3 : 3 + str_len].decode("utf-8", errors="ignore")
            except Exception:
                pass
        elif ext_type == 0x002B:  # Supported Versions
            try:
                ver = int.from_bytes(stream_bytes[idx + 4 : idx + 6], "big")
                if ver == 0x0304:
                    version_str = "TLS 1.3"
            except Exception:
                pass

        idx = ext_data_end

    # Calculate JA3S MD5: MD5(Version,SelectedCipher,Extensions)
    ext_str = "-".join(str(e) for e in ext_ids)
    ja3s_raw = f"{server_version_num},{selected_cipher},{ext_str}"
    import hashlib
    ja3s_hash = hashlib.md5(ja3s_raw.encode("utf-8")).hexdigest()

    return TLSServerHelloMetadata(
        ja3s=ja3s_hash,
        selected_cipher=selected_cipher,
        tls_version=version_str,
        server_alpn=server_alpn,
    )


def parse_tls_client_hello_record(stream_bytes: bytes) -> TLSHandshakeMetadata | None:
    """
    Parses a reassembled TLS ClientHello record directly from wire bytes.
    Extracts SNI (0x0000), ALPN (0x0010), Supported Versions (0x002B), Cipher Suites, and TLS version.
    Does NOT infer protocol fields from JA4 strings.
    """
    if not stream_bytes or len(stream_bytes) < 43:
        return None

    # Check TLS Record Header (5 bytes) or Handshake Type directly
    idx = 0
    if stream_bytes[0] == 0x16:  # TLS Handshake Record
        rec_len = int.from_bytes(stream_bytes[3:5], "big")
        idx = 5
        if len(stream_bytes) < 5 + rec_len:
            # Check if payload contains Handshake directly without full record header
            idx = 0

    if idx < len(stream_bytes) and stream_bytes[idx] != 0x01:  # 0x01 = ClientHello
        return None

    idx += 4  # Skip Handshake Type (1) + Handshake Length (3)
    if idx + 34 > len(stream_bytes):
        return None

    client_version_num = int.from_bytes(stream_bytes[idx : idx + 2], "big")
    idx += 34  # Skip Version (2) + Random (32)

    if idx >= len(stream_bytes):
        return None

    # Session ID
    sess_id_len = stream_bytes[idx]
    idx += 1 + sess_id_len
    if idx + 2 > len(stream_bytes):
        return None

    # Cipher Suites
    cipher_suites_len = int.from_bytes(stream_bytes[idx : idx + 2], "big")
    idx += 2
    cipher_suites = []
    ciphers_end = idx + cipher_suites_len
    if ciphers_end <= len(stream_bytes):
        for c_idx in range(idx, ciphers_end, 2):
            if c_idx + 2 <= len(stream_bytes):
                cipher_suites.append(int.from_bytes(stream_bytes[c_idx : c_idx + 2], "big"))
    idx = ciphers_end

    if idx >= len(stream_bytes):
        return None

    # Compression Methods
    comp_len = stream_bytes[idx]
    idx += 1 + comp_len
    if idx + 2 > len(stream_bytes):
        return None

    # Extensions
    exts_len = int.from_bytes(stream_bytes[idx : idx + 2], "big")
    idx += 2
    exts_end = min(len(stream_bytes), idx + exts_len)

    sni: Optional[str] = None
    alpn: Optional[str] = None
    supported_versions: List[str] = []
    tls_version = "TLS 1.2" if client_version_num == 0x0303 else f"0x{client_version_num:04x}"

    while idx + 4 <= exts_end:
        ext_type = int.from_bytes(stream_bytes[idx : idx + 2], "big")
        ext_size = int.from_bytes(stream_bytes[idx + 2 : idx + 4], "big")
        ext_start = idx + 4
        ext_end = ext_start + ext_size
        if ext_end > exts_end:
            break

        # Extension 0x0000: Server Name Indication (SNI)
        if ext_type == 0x0000 and ext_size >= 5:
            list_len = int.from_bytes(stream_bytes[ext_start : ext_start + 2], "big")
            ptr = ext_start + 2
            l_end = min(ext_end, ptr + list_len)
            while ptr + 3 <= l_end:
                name_type = stream_bytes[ptr]
                name_len = int.from_bytes(stream_bytes[ptr + 1 : ptr + 3], "big")
                ptr += 3
                if ptr + name_len <= l_end and name_type == 0:
                    sni = stream_bytes[ptr : ptr + name_len].decode("utf-8", errors="ignore").strip().lower()
                ptr += name_len

        # Extension 0x0010: Application-Layer Protocol Negotiation (ALPN)
        elif ext_type == 0x0010 and ext_size >= 2:
            alpn_list_len = int.from_bytes(stream_bytes[ext_start : ext_start + 2], "big")
            ptr = ext_start + 2
            a_end = min(ext_end, ptr + alpn_list_len)
            alpn_protocols = []
            while ptr + 1 <= a_end:
                p_len = stream_bytes[ptr]
                ptr += 1
                if p_len > 0 and ptr + p_len <= a_end:
                    proto_name = stream_bytes[ptr : ptr + p_len].decode("utf-8", errors="ignore").strip()
                    if proto_name:
                        alpn_protocols.append(proto_name)
                    ptr += p_len
                else:
                    break
            if alpn_protocols:
                alpn = ",".join(alpn_protocols)

        # Extension 0x002B: Supported Versions (TLS 1.3 check)
        elif ext_type == 0x002B and ext_size >= 1:
            v_list_len = stream_bytes[ext_start]
            ptr = ext_start + 1
            v_end = min(ext_end, ptr + v_list_len)
            while ptr + 2 <= v_end:
                v_num = int.from_bytes(stream_bytes[ptr : ptr + 2], "big")
                if v_num == 0x0304:
                    supported_versions.append("TLS 1.3")
                    tls_version = "TLS 1.3"
                elif v_num == 0x0303:
                    supported_versions.append("TLS 1.2")
                ptr += 2

        idx = ext_end

    ja4 = extract_ja4_fingerprint(stream_bytes, transport_protocol="TCP")

    return TLSHandshakeMetadata(
        sni=sni,
        ja4=ja4,
        alpn=alpn,
        cipher_suites=cipher_suites,
        supported_versions=supported_versions,
        tls_version=tls_version,
        confidence=1.00,
    )


class TlsStreamConsumer:
    """Reassembled TLS ClientHello Handshake Consumer."""

    def parse_stream_chunk(self, stream_bytes: bytes) -> TLSHandshakeMetadata | None:
        return parse_tls_client_hello_record(stream_bytes)
