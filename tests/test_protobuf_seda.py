"""Comprehensive test suite for Protobuf v3 serialization, SEDA worker pool, and Maglev consistent hashing."""

import time
from unittest.mock import MagicMock
import pytest

from backend.proto import flow_telemetry_pb2
from backend.utils.protobuf_serializer import (
    compare_wire_size,
    deserialize_flow_batch,
    flow_dict_to_pb,
    flow_pb_to_dict,
    serialize_flow_batch,
)
from backend.workers.seda_worker_pool import MaglevHasher, SEDAWorkerPool
from backend.services.grpc_ingestion_service import FlowIngestionServicer


def test_protobuf_serialization_fidelity():
    """Verify bidirectional conversion fidelity between dict and Protobuf FlowRecord."""
    flow = {
        "flow_id": "flw_test_99",
        "timestamp_epoch_ms": 1700000000123,
        "agent_id": "agent_alpha",
        "device_id": "dev_01",
        "src_ip": "10.0.0.5",
        "dst_ip": "172.16.0.8",
        "src_port": 49152,
        "dst_port": 8443,
        "protocol": "TCP",
        "packets": 42,
        "bytes": 65536,
        "direction": "outbound",
        "flags": "SYN,ACK",
        "threat_indicator": "PORT_SCAN",
        "dns_query": "c2.evil.com",
        "tls_sni": "safe.org",
        "vpn_detected": True,
        "vpn_provider": "wireguard",
        "risk_score": 87.5,
        "metadata": {"env": "prod", "zone": "dmz"},
    }

    pb = flow_dict_to_pb(flow)
    assert pb.flow_id == "flw_test_99"
    assert pb.src_port == 49152
    assert pb.dst_port == 8443
    assert pb.vpn_detected is True
    assert pb.risk_score == pytest.approx(87.5)
    assert pb.metadata["env"] == "prod"

    restored = flow_pb_to_dict(pb)
    assert restored["flow_id"] == flow["flow_id"]
    assert restored["src_ip"] == flow["src_ip"]
    assert restored["dst_ip"] == flow["dst_ip"]
    assert restored["packets"] == flow["packets"]
    assert restored["bytes"] == flow["bytes"]
    assert restored["vpn_provider"] == flow["vpn_provider"]
    assert restored["metadata"] == flow["metadata"]


def test_wire_size_reduction():
    """Verify that Protobuf binary serialization yields substantial size savings vs JSON."""
    flows = [
        {
            "flow_id": f"flw_{i:04d}",
            "src_ip": f"192.168.1.{i % 254 + 1}",
            "dst_ip": "104.26.14.23",
            "src_port": 30000 + (i % 30000),
            "dst_port": 443,
            "protocol": "TCP",
            "packets": 15,
            "bytes": 2048,
            "direction": "outbound",
            "dns_query": "telemetry.cloud.example",
            "tls_sni": "telemetry.cloud.example",
            "risk_score": 12.0,
        }
        for i in range(100)
    ]

    metrics = compare_wire_size(flows)
    assert metrics["flow_count"] == 100
    assert metrics["json_bytes"] > metrics["protobuf_bytes"]
    # Expect at least 35% reduction on raw wire format
    assert metrics["reduction_percent"] >= 35.0
    assert metrics["saved_bytes"] > 0


def test_maglev_consistent_hashing_uniformity():
    """Verify that Maglev hasher distributes flows evenly across backend workers."""
    workers = [f"worker-{i}" for i in range(4)]
    hasher = MaglevHasher(workers, table_size=10007)

    counts = {w: 0 for w in workers}
    total = 2000

    for i in range(total):
        five_tuple = (f"10.0.{i % 255}.1", f"192.168.{i % 10}.1", 1024 + i, 443, "TCP")
        w = hasher.get_worker(five_tuple)
        counts[w] += 1

    expected_per_worker = total / len(workers)  # 500
    for w, count in counts.items():
        # Every worker should receive within 25% of the average under 2000 random samples
        assert count > expected_per_worker * 0.75, f"Worker {w} underloaded: {count}"
        assert count < expected_per_worker * 1.25, f"Worker {w} overloaded: {count}"


def test_maglev_bidirectional_flow_affinity():
    """Verify forward and reverse flow 5-tuples always hash to the exact same worker."""
    workers = ["node-a", "node-b", "node-c", "node-d"]
    hasher = MaglevHasher(workers, table_size=10007)

    forward_tuple = ("192.168.1.50", "93.184.216.34", 51234, 443, "TCP")
    reverse_tuple = ("93.184.216.34", "192.168.1.50", 443, 51234, "TCP")

    w_fwd = hasher.get_worker(forward_tuple)
    w_rev = hasher.get_worker(reverse_tuple)

    assert w_fwd == w_rev, f"Flow affinity broken: forward={w_fwd}, reverse={w_rev}"


def test_maglev_minimal_disruption_on_rebalance():
    """Verify that adding a worker causes minimal remapping churn."""
    initial_workers = ["w-0", "w-1", "w-2", "w-3"]
    hasher = MaglevHasher(initial_workers, table_size=10007)

    test_tuples = [
        (f"172.16.{i % 250}.1", f"10.0.{i % 50}.2", 2000 + i, 80, "TCP")
        for i in range(1000)
    ]

    initial_mapping = [hasher.get_worker(t) for t in test_tuples]

    # Add a 5th worker
    hasher.add_backend("w-4")
    new_mapping = [hasher.get_worker(t) for t in test_tuples]

    # Fraction of changed assignments should be roughly ~1/5 (20%) +/- tolerance
    changed = sum(1 for old, new in zip(initial_mapping, new_mapping) if old != new)
    churn_ratio = changed / len(test_tuples)

    assert 0.10 <= churn_ratio <= 0.35, f"Churn ratio {churn_ratio:.2f} outside expected ~0.20"


def test_seda_pipeline_end_to_end():
    """Verify multi-stage SEDA pipeline: Ingress -> Worker Partition -> Egress."""
    processed_flows = []
    flushed_batches = []

    def custom_flow_handler(flow):
        flow["processed_by_worker"] = True
        processed_flows.append(flow)
        return flow

    def custom_egress_handler(batch):
        flushed_batches.append(batch)

    pool = SEDAWorkerPool(
        worker_count=3,
        queue_capacity=500,
        flow_handler=custom_flow_handler,
        egress_handler=custom_egress_handler,
    )
    pool.start()

    try:
        raw_flows = [
            {
                "flow_id": f"seda_{i}",
                "src_ip": f"10.0.0.{i + 1}",
                "dst_ip": "8.8.8.8",
                "src_port": 10000 + i,
                "dst_port": 53,
                "protocol": "UDP",
                "dns_query": f"test{i}.internal",
            }
            for i in range(30)
        ]

        # Submit as Protobuf binary batch
        pb_bytes = serialize_flow_batch(raw_flows, batch_id="batch_seda_01")
        accepted = pool.submit_batch(pb_bytes)
        assert accepted is True

        # Wait briefly for stage workers to process
        time.sleep(0.4)

        metrics = pool.get_metrics()
        assert metrics["ingress_enqueued"] >= 1
        assert metrics["flows_routed"] == 30
        assert metrics["flows_processed"] == 30
        assert len(processed_flows) == 30

    finally:
        pool.stop()


def test_seda_backpressure_and_watermark():
    """Verify SEDA backpressure drops batches when queue capacity is reached."""
    pool = SEDAWorkerPool(worker_count=1, queue_capacity=5)
    # Don't start workers so ingress queue fills up
    for i in range(5):
        assert pool.submit_batch({"flows": [{"flow_id": f"q_{i}"}]}) is True

    # 6th should exceed capacity and return False (dropped)
    dropped = pool.submit_batch({"flows": [{"flow_id": "overflow"}]})
    assert dropped is False

    metrics = pool.get_metrics()
    assert metrics["ingress_dropped"] == 1
    assert metrics["ingress_queue_depth"] == 5


def test_grpc_servicer_streaming_and_unary():
    """Verify gRPC FlowIngestionServicer streaming and unary RPC methods."""
    import asyncio

    async def _test():
        mock_pool = MagicMock()
        servicer = FlowIngestionServicer(seda_pool=mock_pool)

        # 1. Unary batch ingestion
        batch = flow_telemetry_pb2.FlowTelemetryBatch()
        batch.batch_id = "u_01"
        flow_rec = batch.flows.add()
        flow_rec.flow_id = "flw_u1"
        flow_rec.src_ip = "192.168.1.10"
        flow_rec.dst_ip = "1.1.1.1"

        ctx = MagicMock()
        resp = await servicer.IngestBatch(batch, ctx)
        assert resp.success is True
        assert resp.accepted_count == 1
        mock_pool.submit_batch.assert_called_once()

        # 2. Streaming batch ingestion
        async def mock_stream():
            for b_id in ["s_1", "s_2"]:
                b = flow_telemetry_pb2.FlowTelemetryBatch()
                b.batch_id = b_id
                f = b.flows.add()
                f.flow_id = f"f_{b_id}"
                yield b

        stream_resp = await servicer.StreamFlows(mock_stream(), ctx)
        assert stream_resp.success is True
        assert stream_resp.accepted_count == 2

    asyncio.run(_test())
