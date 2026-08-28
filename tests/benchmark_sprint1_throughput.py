import time
from packet_engine.ring_buffer import DualRingBuffer, wfq_worker_drain_loop
from packet_engine.classifier_fast import classify_packet_tier_fast

# Synthetic sample packets
DUMMY_SYN = (
    b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
    + b"\x00\x50\x1f\x90\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
)

DUMMY_BULK = (
    b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
    + b"\x10\x00\x1f\x90\x00\x00\x00\x01\x00\x00\x00\x00\x50\x10\x20\x00\x00\x00\x00\x00"
)


def benchmark_ingestion_throughput(packet_count: int = 50000):
    rb = DualRingBuffer(control_capacity=10000, data_capacity=20000)
    
    start_time = time.time()
    for i in range(packet_count):
        raw = DUMMY_SYN if (i % 5 == 0) else DUMMY_BULK
        tier = classify_packet_tier_fast(raw)
        rb.push(raw, priority=tier)
    
    enqueue_time = time.time() - start_time
    enqueue_pps = packet_count / max(enqueue_time, 0.0001)

    processed_count = [0]
    class MockStop:
        def is_set(self):
            return rb.control_queue.empty() and rb.data_queue.empty()

    drain_start = time.time()
    wfq_worker_drain_loop(rb, lambda env: processed_count.__setitem__(0, processed_count[0] + 1), MockStop())
    drain_time = time.time() - drain_start
    drain_pps = processed_count[0] / max(drain_time, 0.0001)

    metrics = rb.get_health_metrics()
    print(f"\n--- SPRINT 1 INGESTION BENCHMARK RESULTS ({packet_count:,} packets) ---")
    print(f"Enqueue Throughput: {enqueue_pps:,.2f} pps ({enqueue_time:.4f}s)")
    print(f"Drain Throughput:   {drain_pps:,.2f} pps ({drain_time:.4f}s)")
    print(f"Packets Processed:  {metrics['packets_processed_total']:,}")
    print(f"Packets Dropped:    {metrics['packets_dropped_total']:,} (Data drops: {metrics['data_queue_drops_total']:,})")
    print(f"Control Drops:      {metrics['control_queue_drops_total']:,}")
    print(f"Control Lag Age:    {metrics['control_queue_oldest_age_ms']} ms")
    print(f"Data Lag Age:       {metrics['data_queue_oldest_age_ms']} ms")

    assert metrics['packets_processed_total'] > 0


if __name__ == "__main__":
    benchmark_ingestion_throughput(50000)
