import pytest
import dpkt
from scapy.all import IP, TCP

from packet_engine.tls_consumer import (
    TLSHandshakeMetadata,
    TlsStreamConsumer,
    parse_tls_client_hello_record,
)
from packet_engine.metadata import extract_ja4_fingerprint
from packet_engine.tcp_stream import TCPStreamBuffer

# Try importing TLSAccumulator (expected to fail before implementation)
try:
    from packet_engine.tls_consumer import TLSAccumulator
except ImportError:
    TLSAccumulator = None


def test_tls_accumulator_class_exists():
    assert TLSAccumulator is not None, "TLSAccumulator must be defined in packet_engine.tls_consumer"


def test_split_tls_pcap_accumulation():
    assert TLSAccumulator is not None
    # Read segments from audit_scratch/split_tls.pcap
    with open("audit_scratch/split_tls.pcap", "rb") as f:
        reader = dpkt.pcap.Reader(f)
        packets = [dpkt.ethernet.Ethernet(buf) for _, buf in reader]

    seg1 = packets[0].data.data.data  # 70 bytes
    seg2 = packets[1].data.data.data  # 61 bytes
    full_payload = seg1 + seg2

    # Expected baseline from unsplit payload
    unsplit_meta = parse_tls_client_hello_record(full_payload)
    assert unsplit_meta is not None
    assert unsplit_meta.sni == "netvisor.example.com"
    expected_ja4 = unsplit_meta.ja4

    # Test via TLSAccumulator
    acc = TLSAccumulator()
    res1 = acc.feed(seg1)
    assert res1 is None, "Incomplete first segment must buffer and return None"

    res2 = acc.feed(seg2)
    assert res2 is not None, "Accumulator must return assembled payload once 5-byte record length is met"
    assert res2 == full_payload

    meta = parse_tls_client_hello_record(res2)
    assert meta is not None
    assert meta.sni == unsplit_meta.sni
    assert meta.ja4 == expected_ja4


def test_client_hello_split_into_3_segments():
    assert TLSAccumulator is not None
    with open("audit_scratch/split_tls.pcap", "rb") as f:
        reader = dpkt.pcap.Reader(f)
        packets = [dpkt.ethernet.Ethernet(buf) for _, buf in reader]

    full_payload = packets[0].data.data.data + packets[1].data.data.data
    unsplit_meta = parse_tls_client_hello_record(full_payload)
    assert unsplit_meta is not None

    # Split into 3 chunks: 40 bytes, 50 bytes, remainder (41 bytes)
    c1 = full_payload[:40]
    c2 = full_payload[40:90]
    c3 = full_payload[90:]

    acc = TLSAccumulator()
    assert acc.feed(c1) is None
    assert acc.feed(c2) is None
    complete = acc.feed(c3)

    assert complete is not None
    assert complete == full_payload
    meta = parse_tls_client_hello_record(complete)
    assert meta is not None
    assert meta.sni == unsplit_meta.sni
    assert meta.ja4 == unsplit_meta.ja4


def test_out_of_order_segments_with_tcp_stream_and_accumulator():
    assert TLSAccumulator is not None
    with open("audit_scratch/split_tls.pcap", "rb") as f:
        reader = dpkt.pcap.Reader(f)
        packets = [dpkt.ethernet.Ethernet(buf) for _, buf in reader]

    full_payload = packets[0].data.data.data + packets[1].data.data.data
    unsplit_meta = parse_tls_client_hello_record(full_payload)
    assert unsplit_meta is not None

    # Split into 3 segments
    chunk1 = full_payload[:40]
    chunk2 = full_payload[40:90]
    chunk3 = full_payload[90:]

    # Simulate TCP stream with segments arriving out-of-order:
    # SYN, then chunk 2, then chunk 1, then chunk 3
    stream = TCPStreamBuffer(flow_key=("10.0.0.1", "10.0.0.2", 50000, 443, "TCP"))
    stream.process_segment(seq=1000, ack=0, payload=b"", flags="S")

    acc = TLSAccumulator()
    assembled_meta = None

    # Arrival 1: Chunk 2 (seq 1041..1091) - out of order!
    flushed = stream.process_segment(seq=1041, ack=0, payload=chunk2, flags="A")
    if flushed:
        rec = acc.feed(flushed)
        if rec:
            assembled_meta = parse_tls_client_hello_record(rec)

    # Arrival 2: Chunk 1 (seq 1001..1041) - fills gap, flushes chunk1 + chunk2
    flushed = stream.process_segment(seq=1001, ack=0, payload=chunk1, flags="A")
    if flushed:
        rec = acc.feed(flushed)
        if rec:
            assembled_meta = parse_tls_client_hello_record(rec)

    assert assembled_meta is None, "Should not be complete yet (missing chunk 3)"

    # Arrival 3: Chunk 3 (seq 1091..1132)
    flushed = stream.process_segment(seq=1091, ack=0, payload=chunk3, flags="A")
    if flushed:
        rec = acc.feed(flushed)
        if rec:
            assembled_meta = parse_tls_client_hello_record(rec)

    assert assembled_meta is not None
    assert assembled_meta.sni == unsplit_meta.sni
    assert assembled_meta.ja4 == unsplit_meta.ja4


def test_tls_accumulator_overflow_drop():
    assert TLSAccumulator is not None
    acc = TLSAccumulator()

    # 1. Header claiming record size > 16 KB + 5 (16389 bytes)
    # Header: 0x16, 0x03, 0x03, len = 20000 (0x4e20)
    oversized_hdr = b"\x16\x03\x03\x4e\x20"
    res = acc.feed(oversized_hdr)
    assert res is None
    assert acc.overflow_drops == 1

    # 2. Accumulating payload bytes exceeding max capacity (16389 bytes)
    acc.reset()
    assert acc.overflow_drops == 0
    # Valid header claiming 16380 bytes, but send 17000 bytes
    hdr = b"\x16\x03\x03\x3f\xfc"
    res1 = acc.feed(hdr + (b"\xaa" * 16390))
    assert res1 is None
    assert acc.overflow_drops == 1


def test_tls_accumulator_timeout_drop():
    assert TLSAccumulator is not None
    acc = TLSAccumulator(timeout=5.0)

    # Feed incomplete chunk at t=100.0
    hdr = b"\x16\x03\x03\x00\x50" + (b"\xaa" * 20)  # expects 85 bytes, provided 25
    res1 = acc.feed(hdr, timestamp=100.0)
    assert res1 is None
    assert acc.timeout_drops == 0

    # Next chunk arrives at t=106.0 (> 5.0 seconds later)
    remainder = b"\xaa" * 60
    res2 = acc.feed(remainder, timestamp=106.0)
    assert res2 is None
    assert acc.timeout_drops == 1


def test_tls_stream_consumer_accumulates():
    # Consumer should buffer chunks and return metadata on completion
    consumer = TlsStreamConsumer()
    with open("audit_scratch/split_tls.pcap", "rb") as f:
        reader = dpkt.pcap.Reader(f)
        packets = [dpkt.ethernet.Ethernet(buf) for _, buf in reader]

    seg1 = packets[0].data.data.data
    seg2 = packets[1].data.data.data

    meta1 = consumer.parse_stream_chunk(seg1)
    assert meta1 is None, "Consumer must return None when record is incomplete"

    meta2 = consumer.parse_stream_chunk(seg2)
    assert meta2 is not None
    assert meta2.sni == "netvisor.example.com"
