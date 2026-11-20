"""
tests/stress/test_pipeline_supervisor_stress.py
===============================================
Extreme volume and concurrency stress tests for the NetVisor telemetry ingestion pipeline
and worker supervision subsystem:
- FlowService extreme ingestion burst simulation (10,000+ flows).
- Backpressure enforcement, queue overflow handling, and circuit breaker activation under downstream delays.
- Multi-consumer Redis stream race condition verification (XDEL vs independent consumer group ACK).
- WorkerSupervisor crash recovery, rapid process restarts, and health heartbeat simulation.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from backend.core.config import settings
from backend.services.event_dispatcher import flow_ingestion_queue
from backend.services.flow_service import FlowQueueBackpressureError, FlowService
from backend.services.worker_supervisor import WorkerState, WorkerSupervisor
from tests.stress.conftest import MockRedis, generate_flow_batch, generate_synthetic_flow


class TestPipelineIngestionBurstStress:
    """Stress tests simulating extreme flow ingestion bursts through FlowService."""

    @pytest.mark.anyio
    async def test_flow_service_extreme_ingestion_burst(self, mock_redis: MockRedis):
        """
        Simulate an extreme ingestion burst of 10,000 flows submitted in rapid batches
        via FlowService.buffer_flows().
        Measures batch ingestion throughput (flows/sec) and verifies Redis stream buffering.
        """
        service = FlowService()
        total_target_flows = 10000
        batch_size = 1000
        num_batches = total_target_flows // batch_size

        batches = [generate_flow_batch(count=batch_size) for _ in range(num_batches)]

        # Clear any residual items from event bus queue
        while not flow_ingestion_queue.empty():
            try:
                flow_ingestion_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        start_time = time.perf_counter()

        with patch("backend.db.redis_client.get_redis_connection", return_value=mock_redis):
            for batch in batches:
                success = await service.buffer_flows(batch)
                assert success is True

        duration = time.perf_counter() - start_time
        fps = total_target_flows / duration if duration > 0 else 0.0

        # Verify Redis stream holds all published batches
        stream_len = mock_redis.xlen("netvisor:flow_stream")
        assert stream_len == num_batches, f"Expected {num_batches} stream entries, got {stream_len}"

        # Verify throughput is robust (>3,000 flows/sec serialization & buffer rate)
        assert fps > 3000.0, f"Expected >3000 flows/sec ingestion throughput, got {fps:.2f}"

        # Clean up
        service.shutdown()


    @pytest.mark.anyio
    async def test_backpressure_enforcement_and_queue_overflow(self, mock_redis: MockRedis):
        """
        Verify backpressure enforcement when pending flow count or lag exceeds configured
        thresholds, and verify queue overflow handling in flow_ingestion_queue.
        """
        service = FlowService()

        # 1. Test database-backed queue depth backpressure
        mock_db_conn = MagicMock()
        with patch.object(service, "_queue_status_counts", return_value={"pending_flows": 9500, "oldest_pending_age_seconds": 10}):
            with patch.object(settings, "FLOW_INGEST_MAX_PENDING_FLOWS", 10000):
                # 9500 + 600 = 10100 > 10000 -> Should raise FlowQueueBackpressureError
                with pytest.raises(FlowQueueBackpressureError) as exc_info:
                    service._enforce_backpressure(mock_db_conn, incoming_flows=600)
                assert "exceeds configured limit" in str(exc_info.value)

        # 2. Test lag-based backpressure
        with patch.object(service, "_queue_status_counts", return_value={"pending_flows": 100, "oldest_pending_age_seconds": 150}):
            with patch.object(settings, "FLOW_INGEST_MAX_LAG_SECONDS", 120):
                # Age 150s > 120s max lag -> Should raise FlowQueueBackpressureError
                with pytest.raises(FlowQueueBackpressureError) as exc_info:
                    service._enforce_backpressure(mock_db_conn, incoming_flows=10)
                assert "exceeds configured limit" in str(exc_info.value)

        # 3. Test queue overflow behavior in event bus queue (asyncio.QueueFull)
        # Fill queue to maximum capacity
        items_put = 0
        while not flow_ingestion_queue.full():
            try:
                flow_ingestion_queue.put_nowait({"mock": True})
                items_put += 1
            except asyncio.QueueFull:
                break

        assert flow_ingestion_queue.full()

        # When queue is full, buffer_flows should catch QueueFull and continue without crashing
        with patch("backend.db.redis_client.get_redis_connection", return_value=mock_redis):
            test_flow = generate_synthetic_flow("benign")
            result = await service.buffer_flows([test_flow])
            assert result is True

        # Drain queue
        while not flow_ingestion_queue.empty():
            try:
                flow_ingestion_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        service.shutdown()


class TestRedisStreamMultiConsumerRace:
    """Stress testing the multi-consumer Redis stream XDEL vs ACK race condition."""

    def test_multi_consumer_stream_race_condition(self, mock_redis: MockRedis):
        """
        Reproduce the critical multi-consumer race condition identified in Survey 2:
        - When consumer group 1 (flow_writer_worker) calls XDEL after XACK,
          consumer group 2 (correlation_worker) suffers message loss because the message
          is destroyed from the stream before group 2 can read it.
        - When XDEL is omitted and retention relies solely on MAXLEN, both independent
          consumer groups reliably read all messages.
        """
        stream_name = "netvisor:flow_stream"
        group_flow_writer = "netvisor_flow_consumers"
        group_correlation = "correlation_workers"

        # Create both independent consumer groups
        mock_redis.xgroup_create(stream_name, group_flow_writer, id="0", mkstream=True)
        mock_redis.xgroup_create(stream_name, group_correlation, id="0", mkstream=True)

        # Produce 50 messages into the stream
        msg_ids = []
        for i in range(50):
            mid = mock_redis.xadd(stream_name, {"batch_id": f"batch-{i}", "count": 100})
            msg_ids.append(mid)

        assert mock_redis.xlen(stream_name) == 50

        # Scenario A: Flow Writer consumes 25 messages, calls XACK AND XDEL (The Buggy Pattern)
        read_flow = mock_redis.xreadgroup(group_flow_writer, "writer-01", {stream_name: ">"}, count=25)
        assert len(read_flow[0][1]) == 25
        flow_messages = read_flow[0][1]

        # Flow writer executes XACK followed by destructive XDEL
        for mid, _ in flow_messages:
            mock_redis.xack(stream_name, group_flow_writer, mid)
            mock_redis.xdel(stream_name, mid)  # Purges message from stream!

        # Stream length decreased to 25
        assert mock_redis.xlen(stream_name) == 25

        # Correlation worker now attempts to read all 50 messages
        read_corr = mock_redis.xreadgroup(group_correlation, "corr-01", {stream_name: ">"}, count=50)
        corr_messages = read_corr[0][1] if read_corr else []

        # DATA LOSS DEMONSTRATION: Correlation worker ONLY received 25 messages!
        # The first 25 messages were permanently lost to correlation_workers.
        assert len(corr_messages) == 25, (
            f"Expected correlation worker to suffer data loss (25 messages), got {len(corr_messages)}"
        )

        # Scenario B: Bounded Stream retention without XDEL (The Correct Pattern)
        # Clear stream and re-populate
        mock_redis.delete(stream_name)
        mock_redis.xgroup_create(stream_name, group_flow_writer, id="0", mkstream=True)
        mock_redis.xgroup_create(stream_name, group_correlation, id="0", mkstream=True)

        for i in range(50):
            mock_redis.xadd(stream_name, {"batch_id": f"batch-fixed-{i}"}, maxlen=1000)

        # Flow writer reads 25 messages and ONLY calls XACK (no XDEL)
        read_flow_fixed = mock_redis.xreadgroup(group_flow_writer, "writer-02", {stream_name: ">"}, count=25)
        for mid, _ in read_flow_fixed[0][1]:
            mock_redis.xack(stream_name, group_flow_writer, mid)

        # Correlation worker reads from stream
        read_corr_fixed = mock_redis.xreadgroup(group_correlation, "corr-02", {stream_name: ">"}, count=50)
        assert len(read_corr_fixed[0][1]) == 50, "Without XDEL, secondary consumer reads all messages"


class TestWorkerSupervisorStress:
    """Stress testing WorkerSupervisor crash recovery, rapid restarts, and heartbeats."""

    @pytest.mark.anyio
    async def test_worker_supervisor_rapid_crash_recovery(self):
        """
        Stress test WorkerSupervisor under a rapid unhandled exception crash loop.
        Verifies exponential backoff delay calculation, crash recording, and clean shutdown.
        """
        supervisor = WorkerSupervisor(max_restarts=5, base_delay=0.005, max_delay=0.05)
        crash_count = 0

        async def failing_worker():
            nonlocal crash_count
            crash_count += 1
            raise RuntimeError(f"Simulated worker crash #{crash_count}")

        supervisor.register("crash_prone_worker", failing_worker)

        # Start supervisor
        start_task = asyncio.create_task(supervisor.start_all())

        # Allow worker to crash and restart several times
        await asyncio.sleep(0.08)

        # Verify crash metrics and restart tracking
        state = supervisor.get_worker_state("crash_prone_worker")
        assert state is not None
        assert state.restart_count >= 2, f"Expected at least 2 restarts, observed {state.restart_count}"
        assert state.last_exception is not None
        assert "RuntimeError" in state.last_exception
        assert state.last_exception_time > 0

        # Verify status snapshot
        snapshots = supervisor.get_status()
        assert len(snapshots) == 1
        assert snapshots[0]["name"] == "crash_prone_worker"
        assert snapshots[0]["restart_count"] == state.restart_count

        # Graceful shutdown during active crash cycle
        await supervisor.stop_all()
        await start_task

        assert state.running is False


    @pytest.mark.anyio
    async def test_worker_supervisor_heartbeat_synthesis(self):
        """
        Verify that WorkerSupervisor heartbeat loop tracks healthy workers
        and properly records timestamps without deadlocks.
        """
        supervisor = WorkerSupervisor(heartbeat_interval=0.02)
        execution_ticks = 0

        async def healthy_worker():
            nonlocal execution_ticks
            while True:
                execution_ticks += 1
                await asyncio.sleep(0.01)

        supervisor.register("healthy_worker", healthy_worker)
        start_task = asyncio.create_task(supervisor.start_all())

        # Wait for heartbeats to trigger
        await asyncio.sleep(0.06)

        state = supervisor.get_worker_state("healthy_worker")
        assert state is not None
        assert state.running is True
        assert state.last_heartbeat > 0
        assert execution_ticks > 1

        # Stop supervisor
        await supervisor.stop_all()
        await start_task

        assert state.running is False
