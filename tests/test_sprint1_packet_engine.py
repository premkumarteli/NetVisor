import pytest
import time
from packet_engine.ring_buffer import DualRingBuffer, RawPacketEnvelope, wfq_worker_drain_loop
from packet_engine.classifier_fast import classify_packet_tier_fast
from packet_engine.metadata import _extract_http_host, extract_ja4_fingerprint
from packet_engine.parser import PacketObservation, FlowObservation


def test_dual_ring_buffer_push_pop():
    rb = DualRingBuffer(control_capacity=10, data_capacity=10)

    # Push Control (Priority 0)
    assert rb.push(b"control_packet_1", priority=0) is True
    # Push Data (Priority 2)
    assert rb.push(b"data_packet_1", priority=2) is True

    health = rb.get_health_metrics()
    assert health["control_queue_size"] == 1
    assert health["data_queue_size"] == 1
    assert health["packets_received_total"] == 2

    # Pop control first
    ctrl_item = rb.pop_control_nowait()
    assert ctrl_item is not None
    assert ctrl_item.raw_bytes == b"control_packet_1"

    data_item = rb.pop_data_nowait()
    assert data_item is not None
    assert data_item.raw_bytes == b"data_packet_1"


def test_wfq_worker_drain():
    rb = DualRingBuffer(control_capacity=100, data_capacity=100)
    processed = []

    for i in range(10):
        rb.push(f"ctrl_{i}".encode(), priority=0)
    for i in range(10):
        rb.push(f"data_{i}".encode(), priority=2)

    class MockStop:
        def __init__(self):
            self.calls = 0

        def is_set(self):
            self.calls += 1
            return self.calls > 2

    stop_event = MockStop()
    wfq_worker_drain_loop(rb, lambda env: processed.append(env.raw_bytes), stop_event, max_control_burst=5, min_data_batch=2)

    assert len(processed) > 0
    # First items should be control items due to priority
    assert processed[0].startswith(b"ctrl_")


def test_fast_classifier():
    # IPv4 TCP SYN Packet sample header (SYN flag 0x02)
    # Eth (14) + IP (20) + TCP (20 with SYN flag at offset 47)
    dummy_syn = (
        b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"  # Eth (Type 0x0800)
        + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"  # IPv4 IHL=5 Proto=6 (TCP)
        + b"\x00\x50\x1f\x90\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"  # TCP SYN flag=0x02
    )
    tier = classify_packet_tier_fast(dummy_syn)
    assert tier == 0  # High priority SYN


def test_http_host_extractor():
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pytest\r\n\r\n"
    domain = _extract_http_host(http_payload)
    assert domain == "example.com"


def test_parser_protocol_confidence():
    obs = PacketObservation(
        observed_at=time.time(),
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.10",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=53,
        protocol="UDP",
        packet_size=64,
        protocol_confidence=1.0,
    )
    flow_obs = obs.to_flow_observation(agent_id="test-agent", organization_id="test-org")
    assert flow_obs.protocol_confidence == 1.0
    d = flow_obs.as_dict()
    assert d["protocol_confidence"] == 1.0
