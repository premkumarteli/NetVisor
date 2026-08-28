import time
import threading
from packet_engine.flow_aggregator import FlowManager
from packet_engine.parser import PacketObservation


def test_16_shard_flow_manager_basic():
    expired_flows = []
    fm = FlowManager(
        agent_id="test-agent",
        organization_id="test-org",
        on_flow_expired=lambda summary: expired_flows.append(summary),
        start_worker=False,
    )

    obs = PacketObservation(
        observed_at=time.time(),
        source_type="agent",
        metadata_only=False,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=128,
        domain="example.com",
    )

    fm.update_from_observation(obs)
    snapshot = fm.status_snapshot()

    assert snapshot["active_flow_count"] == 1
    assert snapshot["num_shards"] == 16
    assert snapshot["packet_count"] == 1
    assert snapshot["byte_count"] == 128


def test_16_shard_parallel_updates_benchmark():
    fm = FlowManager(
        agent_id="bench-agent",
        organization_id="bench-org",
        on_flow_expired=lambda summary: None,
        max_flows=50000,
        start_worker=False,
    )

    num_threads = 8
    updates_per_thread = 2000
    threads = []

    def _worker(thread_id: int):
        for i in range(updates_per_thread):
            obs = PacketObservation(
                observed_at=time.time(),
                source_type="agent",
                metadata_only=False,
                src_ip=f"10.0.{thread_id}.{i % 255}",
                dst_ip="1.1.1.1",
                src_port=1000 + (i % 50),
                dst_port=80,
                protocol="TCP",
                packet_size=64,
            )
            fm.update_from_observation(obs)

    start_ts = time.time()
    for t_idx in range(num_threads):
        t = threading.Thread(target=_worker, args=(t_idx,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    duration = time.time() - start_ts
    total_ops = num_threads * updates_per_thread
    ops_per_sec = total_ops / max(duration, 0.0001)

    snapshot = fm.status_snapshot()
    print(f"\n--- SPRINT 2 16-SHARD FLOWMANAGER BENCHMARK ---")
    print(f"Parallel Threads:     {num_threads}")
    print(f"Total Flow Updates:   {total_ops:,}")
    print(f"Active Flow Entries:  {snapshot['active_flow_count']:,}")
    print(f"Execution Duration:   {duration:.4f} seconds")
    print(f"Throughput Rate:      {ops_per_sec:,.2f} updates/sec")

    assert snapshot["active_flow_count"] > 0
    assert snapshot["packet_count"] == total_ops
