import pytest
import time
from packet_engine.tcp_stream import (
    TCPStreamBuffer,
    TCPStreamStateEnum,
    TCPStreamTrackerManager,
    seq_lt,
    seq_gt,
)


def test_metric_delta_no_double_counting():
    flow_key = ("192.168.1.10", "1.1.1.1", 12345, 80, "TCP")
    tracker = TCPStreamTrackerManager()

    # SYN
    tracker.process_packet_segment(flow_key, seq=1000, ack=0, payload=b"", flags="S")

    # Segment 1
    tracker.process_packet_segment(flow_key, seq=1001, ack=1, payload=b"HELLO_", flags="A")

    # Packet 2 (Retransmission) -> Should trigger 1 retransmission
    tracker.process_packet_segment(flow_key, seq=1001, ack=1, payload=b"HELLO_", flags="A")

    # Packet 3 (Normal next segment) -> Retransmission count must NOT accumulate again!
    tracker.process_packet_segment(flow_key, seq=1007, ack=1, payload=b"WORLD", flags="A")

    snapshot = tracker.status_snapshot()
    assert snapshot["retransmissions_detected_total"] == 1  # Exactly 1, NOT 2 or 3!


def test_seq_wraparound_32bit():
    flow_key = ("10.0.0.1", "10.0.0.2", 7777, 80, "TCP")
    buffer = TCPStreamBuffer(flow_key)

    # Initial SEQ near 2^32 - 1
    start_seq = 0xFFFFFFFE
    buffer.process_segment(seq=start_seq, ack=0, payload=b"", flags="S")

    # Next expected seq wraps to (0xFFFFFFFE + 1) = 0xFFFFFFFF
    out1 = buffer.process_segment(seq=0xFFFFFFFF, ack=1, payload=b"A", flags="A")
    assert out1 == b"A"

    # Next expected seq wraps to 0x00000000
    out2 = buffer.process_segment(seq=0, ack=1, payload=b"B", flags="A")
    assert out2 == b"B"

    # Next expected seq is 1
    out3 = buffer.process_segment(seq=1, ack=1, payload=b"C", flags="A")
    assert out3 == b"C"
    assert buffer.total_assembled_bytes == 3


def test_overlapping_segment_trimming():
    flow_key = ("10.0.0.1", "10.0.0.2", 8888, 80, "TCP")
    buffer = TCPStreamBuffer(flow_key)
    buffer.process_segment(seq=1000, ack=0, payload=b"", flags="S")

    # Expected is 1001. Send Seq 1001, len 10 -> Expected becomes 1011
    out1 = buffer.process_segment(seq=1001, ack=1, payload=b"0123456789", flags="A")
    assert out1 == b"0123456789"
    assert buffer.next_expected_seq == 1011

    # Overlapping segment arrives: Seq 1005 (overlaps 1005-1010), length 10 (ends at 1015)
    # Expected is 1011, so leading 6 bytes (1005..1010) must be trimmed!
    # Remaining payload should be "ABCD" (bytes 6..9 of payload "012345ABCD")
    out_overlap = buffer.process_segment(seq=1005, ack=1, payload=b"012345ABCD", flags="A")
    assert out_overlap == b"ABCD"
    assert buffer.next_expected_seq == 1015


def test_immediate_post_insertion_memory_budget_enforcement():
    tracker = TCPStreamTrackerManager(
        max_global_memory_bytes=500,  # Cap at 500 bytes
        max_stream_bytes=300,
        max_idle_seconds=60.0,
    )

    flow1 = ("1.1.1.1", "2.2.2.2", 100, 80, "TCP")
    flow2 = ("1.1.1.2", "2.2.2.2", 101, 80, "TCP")

    # Out-of-order payloads are buffered in memory
    tracker.process_packet_segment(flow1, seq=100, ack=0, payload=b"", flags="S")
    tracker.process_packet_segment(flow1, seq=105, ack=1, payload=b"X" * 250, flags="A")

    tracker.process_packet_segment(flow2, seq=100, ack=0, payload=b"", flags="S")
    # Insertion of flow2's segment pushes global memory over 500 bytes -> Immediate enforcement!
    tracker.process_packet_segment(flow2, seq=105, ack=1, payload=b"Y" * 300, flags="A")

    snapshot = tracker.status_snapshot()
    assert snapshot["global_memory_bytes"] <= 500


def test_fin_with_payload_processing():
    flow_key = ("10.0.0.1", "10.0.0.2", 9999, 80, "TCP")
    buffer = TCPStreamBuffer(flow_key)
    buffer.process_segment(seq=100, ack=0, payload=b"", flags="S")

    # Segment with FA (FIN + ACK) and final payload
    out_fin = buffer.process_segment(seq=101, ack=1, payload=b"FINAL_DATA", flags="FA")
    assert out_fin == b"FINAL_DATA"
    assert buffer.state == TCPStreamStateEnum.FIN_WAIT
