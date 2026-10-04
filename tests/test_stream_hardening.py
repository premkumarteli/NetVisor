import time
import pytest
from scapy.all import IP, TCP

from packet_engine.tcp_stream import TCPStreamTrackerManager
from packet_engine.ring_buffer import DualRingBuffer, RawPacketEnvelope


def test_tcp_stream_tracker_max_streams_eviction():
    # Configure manager with 16 shards, max_streams = 160 (i.e. 10 per shard)
    manager = TCPStreamTrackerManager(
        max_global_memory_bytes=100 * 1024 * 1024,
        max_streams=160,
    )
    assert hasattr(manager, "streams_evicted_total")
    assert manager.streams_evicted_total == 0
    assert manager.max_streams_per_shard == 10

    # Target a specific shard by picking keys that hash to shard 0
    shard_target = 0
    matching_keys = []
    port = 1000
    while len(matching_keys) < 25:
        key = ("10.0.0.1", "10.0.0.2", port, 80, "TCP")
        if manager._get_shard_index(key) == shard_target:
            matching_keys.append(key)
        port += 1

    # Send 25 zero-payload SYN segments into the same shard
    t0 = 1000.0
    for i, key in enumerate(matching_keys):
        manager.process_packet_segment(
            flow_key=key,
            seq=100,
            ack=0,
            payload=b"",
            flags="S",
            timestamp=t0 + i,
        )

    # Shard size must be capped at max_streams_per_shard (10)
    shard_len = len(manager._shards[shard_target])
    assert shard_len <= 10, f"Shard exceeded max_streams_per_shard: {shard_len} > 10"

    # Exactly 15 streams must have been evicted
    assert manager.streams_evicted_total == 15

    # Check status snapshot
    snap = manager.status_snapshot()
    assert "streams_evicted_total" in snap
    assert snap["streams_evicted_total"] == 15


def test_dual_ring_buffer_token_bucket_single_source_flood():
    # DualRingBuffer with token bucket: burst=10, rate=5/sec
    ring = DualRingBuffer(
        control_capacity=50,
        data_capacity=100,
        token_rate=5.0,
        token_burst=10.0,
    )
    assert hasattr(ring, "control_rate_limited_total")
    assert ring.control_rate_limited_total == 0

    flood_ip = "192.168.1.100"
    legit_ip = "10.0.0.1"

    # Push 30 high-priority (priority=0) packets from flood_ip at t=100.0
    t0 = 100.0
    for _ in range(30):
        # We pass src_ip explicitly or in packet bytes
        accepted = ring.push(b"SYN_FLOOD_PKT", priority=0, timestamp=t0, src_ip=flood_ip)
        assert accepted is True, "Packet should be accepted into data queue even if rate-limited"

    # First 10 packets should be admitted to control_queue, remaining 20 diverted to data_queue
    assert ring.control_queue.qsize() == 10
    assert ring.data_queue.qsize() == 20
    assert ring.control_rate_limited_total == 20

    # Now a legitimate packet arrives from a different source IP
    accepted_legit = ring.push(b"LEGIT_SYN", priority=0, timestamp=t0, src_ip=legit_ip)
    assert accepted_legit is True
    # Legitimate packet MUST enter control_queue because its source has full token bucket!
    assert ring.control_queue.qsize() == 11
    assert ring.control_rate_limited_total == 20


def test_dual_ring_buffer_multi_source_flood():
    # Test SYN flood across multiple distinct sources
    ring = DualRingBuffer(
        control_capacity=100,
        data_capacity=200,
        token_rate=2.0,
        token_burst=5.0,
    )

    # 15 distinct attacker IPs each send 10 Priority 0 packets (150 total)
    t0 = 500.0
    for i in range(15):
        atk_ip = f"198.51.100.{i}"
        for _ in range(10):
            ring.push(b"MULTI_SYN", priority=0, timestamp=t0, src_ip=atk_ip)

    # Each attacker gets at most 5 into control_queue (15 * 5 = 75 in control)
    # Remaining 5 per attacker (15 * 5 = 75) diverted to data_queue
    assert ring.control_queue.qsize() == 75
    assert ring.data_queue.qsize() == 75
    assert ring.control_rate_limited_total == 75

    # A legitimate client connects from 203.0.113.50
    legit_ip = "203.0.113.50"
    ring.push(b"LEGIT_CLIENT_SYN", priority=0, timestamp=t0, src_ip=legit_ip)

    # Legitimate handshake gets admitted to control_queue
    assert ring.control_queue.qsize() == 76
    assert ring.control_rate_limited_total == 75
