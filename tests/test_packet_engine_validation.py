from __future__ import annotations

import time
import threading
import pytest
from packet_engine import (
    DualRingBuffer,
    FlowManager,
    TCPStreamTrackerManager,
    PacketObservation,
    wfq_worker_drain_loop,
)
from packet_engine.bpf_filter import BPFFilterEngine
from packet_engine.tcp_stream import seq_lt, seq_lte, seq_gt, seq_gte, BidirectionalTCPStream, TCPStreamBuffer


def test_seq_32bit_wraparound_boundary_math():
    """Validates 32-bit sequence number wraparound comparisons near 2^32 boundary."""
    # Near wraparound: 4_294_967_290 vs 10
    seq_old = 4_294_967_290
    seq_new = 10

    assert seq_lt(seq_old, seq_new) is True
    assert seq_lte(seq_old, seq_new) is True
    assert seq_gt(seq_new, seq_old) is True
    assert seq_gte(seq_new, seq_old) is True

    # Same sequence number
    assert seq_lte(100, 100) is True
    assert seq_gte(100, 100) is True
    assert seq_lt(100, 100) is False
    assert seq_gt(100, 100) is False


def test_malformed_and_truncated_packet_resilience():
    """Ensures packet parser does not crash on truncated or corrupt byte streams."""
    # Empty bytes
    assert PacketObservation.from_raw_bytes(b"") is None

    # Truncated Ethernet header (<14 bytes)
    assert PacketObservation.from_raw_bytes(b"\x00\x11\x22\x33\x44") is None

    # Corrupt IP header length
    corrupt_ip = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + b"\x40\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x08\x08\x08\x08"
    obs = PacketObservation.from_raw_bytes(corrupt_ip)
    assert obs is None or isinstance(obs, PacketObservation)


def test_concurrent_multi_threaded_flow_manager_stress():
    """Stresses 16-shard FlowManager under high concurrent multi-worker updates."""
    manager = FlowManager(
        agent_id="stress-agent",
        organization_id="org-stress",
        on_flow_expired=lambda summary: None,
        max_flows=10000,
        start_worker=False,
    )

    num_threads = 8
    updates_per_thread = 500

    def worker_task(thread_id: int):
        for i in range(updates_per_thread):
            src_ip = f"10.0.{(thread_id + i) % 255}.{(i % 254) + 1}"
            obs = PacketObservation(
                observed_at=1000.0 + i,
                source_type="stress",
                metadata_only=False,
                src_ip=src_ip,
                dst_ip="8.8.8.8",
                src_port=10000 + (i % 100),
                dst_port=443,
                protocol="TCP",
                packet_size=512,
                tcp_flags="A",
            )
            manager.update_from_observation(obs)

    threads = [threading.Thread(target=worker_task, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snapshot = manager.status_snapshot()
    assert snapshot["active_flow_count"] > 0
    assert snapshot["packet_count"] == num_threads * updates_per_thread


def test_ring_buffer_tail_drop_and_wfq_drain():
    """Validates DualRingBuffer tail-drop and WFQ worker drain balance."""
    ring = DualRingBuffer(control_capacity=10, data_capacity=10)

    # Fill control queue
    for i in range(10):
        assert ring.push(b"control_payload", priority=0) is True

    # Fill data queue
    for i in range(15):
        ring.push(b"bulk_payload", priority=2)

    assert ring.data_drops_total >= 5

    drained = []
    stop_evt = threading.Event()

    def process_envelope(env):
        drained.append(env)

    worker = threading.Thread(target=wfq_worker_drain_loop, args=(ring, process_envelope, stop_evt), daemon=True)
    worker.start()

    time.sleep(0.2)
    stop_evt.set()
    worker.join(timeout=1.0)

    assert len(drained) > 0


def test_bidirectional_tcp_stream_out_of_order_assembly():
    """Validates BidirectionalTCPStream segment reassembly with out-of-order data."""
    bi_stream = BidirectionalTCPStream(flow_key=("10.0.0.1", "10.0.0.2", 1234, 80, "TCP"))

    # Establish stream with SYN (next_expected_seq = 1000)
    bi_stream.process_segment(seq=999, ack=0, payload=b"", flags="S", is_forward=True)

    # Forward segment 2 (out of order: seq 1006 when 1000 is expected)
    out2 = bi_stream.process_segment(seq=1006, ack=1, payload=b"WORLD", flags="A", is_forward=True)
    assert out2 == b""
    assert bi_stream.client_to_server.out_of_order_count == 1

    # Forward segment 1 (in order fill: seq 1000, len 6 -> reaches 1006, flushing buffered 1006..1011)
    out1 = bi_stream.process_segment(seq=1000, ack=1, payload=b"HELLO_", flags="A", is_forward=True)
    assert out1 == b"HELLO_WORLD"

    # Reverse segment (server to client)
    rev_out = bi_stream.process_segment(seq=5000, ack=1015, payload=b"HTTP/1.1 200 OK\r\n", flags="A", is_forward=False)
    assert rev_out == b"HTTP/1.1 200 OK\r\n"
