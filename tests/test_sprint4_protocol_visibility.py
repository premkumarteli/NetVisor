import pytest
from packet_engine.quic_parser import QuicMetadata, extract_quic_metadata
from packet_engine.http_consumer import HttpStreamConsumer, HttpTransaction
from packet_engine.tls_consumer import TlsStreamConsumer, TLSHandshakeMetadata
from packet_engine.stream_registry import StreamConsumerRegistry, CONFIDENCE_MATRIX


def test_quic_initial_dissector():
    # Valid 72-byte TLS ClientHello record payload embedded in QUIC CRYPTO frame
    rec_hdr = b"\x16\x03\x01\x00\x43"
    hs_hdr = b"\x01\x00\x00\x3f"
    ch_base = b"\x03\x03" + (b"\xAA" * 32) + b"\x00"
    ciphers = b"\x00\x02\x00\x2f"
    comp = b"\x01\x00"
    exts_hdr = b"\x00\x14"
    ext_sni = b"\x00\x00\x00\x10\x00\x0e\x00\x00\x0bexample.com"
    ch_payload = rec_hdr + hs_hdr + ch_base + ciphers + comp + exts_hdr + ext_sni

    # QUIC Long Header Initial: Type 0x80, Version 1, DCID len 8, SCID len 8, Token len 0 (0x00), Length 2-byte VLI (0x4043)
    header = b"\x80\x00\x00\x00\x01\x08" + (b"\x01" * 8) + b"\x08" + (b"\x02" * 8) + b"\x00\x40\x43"
    payload = header + ch_payload

    meta = extract_quic_metadata(payload)
    assert meta is not None
    assert meta.quic_version == 1
    assert meta.sni == "example.com"
    assert meta.ja4 is not None
    assert meta.ja4.startswith("qq000d000000")


def test_http_stream_consumer_bidirectional():
    consumer = HttpStreamConsumer()
    
    # 1. Request Line
    raw_req = (
        b"GET /api/v1/telemetry HTTP/1.1\r\n"
        b"Host: api.netvisor.io\r\n"
        b"User-Agent: NetVisor-Sensor/2.0\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 128\r\n\r\n"
        b'{"status": "ok"}'
    )

    tx_req = consumer.parse_stream_chunk(raw_req)
    assert tx_req is not None
    assert isinstance(tx_req, HttpTransaction)
    assert tx_req.method == "GET"
    assert tx_req.host == "api.netvisor.io"
    assert tx_req.uri == "/api/v1/telemetry"
    assert tx_req.user_agent == "NetVisor-Sensor/2.0"
    assert tx_req.content_type == "application/json"
    assert tx_req.content_length == 128

    # 2. Response Status Line
    raw_res = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 42\r\n\r\n"
    )

    tx_res = consumer.parse_stream_chunk(raw_res)
    assert tx_res is not None
    assert tx_res.method == "RESPONSE"
    assert tx_res.status_code == 200
    assert tx_res.server == "nginx/1.24.0"
    assert tx_res.content_type == "application/json"


def test_tls_stream_consumer_alpn_and_supported_versions():
    consumer = TlsStreamConsumer()
    
    # TLS ClientHello record: Record Hdr (5) + Handshake Hdr (4) + Version/Random/Session (35) + Ciphers (4) + Comp (2) + Exts (45) = 90 bytes payload
    rec_hdr = b"\x16\x03\x01\x00\x5a"
    hs_hdr = b"\x01\x00\x00\x56"
    ch_base = b"\x03\x03" + (b"\xAA" * 32) + b"\x00"
    ciphers = b"\x00\x02\x00\x2f"
    comp = b"\x01\x00"

    # Extension 1: SNI (Type 0x0000, Size 12) -> "test.io" (16 bytes)
    ext_sni = b"\x00\x00\x00\x0c\x00\x0a\x00\x00\x07test.io"
    # Extension 2: ALPN (Type 0x0010, Size 14) -> Protocols: "h2", "http/1.1" (18 bytes)
    # ExtSize = 14 (0x000E), ListLen = 12 (0x000C), Len 2 "h2", Len 8 "http/1.1"
    ext_alpn = b"\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1"
    # Extension 3: Supported Versions (Type 0x002B, Size 5) -> ListLen 4, 0x0304 (TLS 1.3), 0x0303 (TLS 1.2) (9 bytes)
    ext_versions = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    
    # Total Exts Len = 16 + 18 + 9 = 43 bytes (0x002B)
    exts_hdr = b"\x00\x2b"
    raw_tls = rec_hdr + hs_hdr + ch_base + ciphers + comp + exts_hdr + ext_sni + ext_alpn + ext_versions

    tls_meta = consumer.parse_stream_chunk(raw_tls)
    assert tls_meta is not None
    assert isinstance(tls_meta, TLSHandshakeMetadata)
    assert tls_meta.sni == "test.io"
    assert tls_meta.alpn == "h2,http/1.1"  # Directly parsed from ALPN wire extension!
    assert tls_meta.tls_version == "TLS 1.3"  # Directly parsed from Supported Versions extension!
    assert "TLS 1.3" in tls_meta.supported_versions


def test_stream_consumer_registry():
    registry = StreamConsumerRegistry()

    raw_http_stream = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: gateway.internal\r\n\r\n"
    )

    result = registry.process_stream("HTTP", raw_http_stream)
    assert result is not None
    assert result.method == "POST"
    assert result.host == "gateway.internal"

    assert CONFIDENCE_MATRIX["VERIFIED_L7_HEADER"] == 1.00
    assert CONFIDENCE_MATRIX["PORT_AND_SIGNATURE_MATCH"] == 0.90
    assert CONFIDENCE_MATRIX["PORT_MAPPING_ONLY"] == 0.60
    assert CONFIDENCE_MATRIX["STATISTICAL_HEURISTIC"] == 0.40
